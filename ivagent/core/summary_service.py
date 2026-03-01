#!/usr/bin/env python3
"""
SummaryService - 统一摘要生成服务

集中管理所有摘要类 LLM 调用的提示词与工具逻辑，避免分散实现。
"""

from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple, List
import json

from langchain_core.messages import HumanMessage

from .tool_llm_client import ToolBasedLLMClient


@dataclass
class SummaryCompressionPayload:
    """上下文压缩结果载体"""
    summary: str
    store_artifact: bool = False
    reason: str = ""
    raw_tool_args: Optional[Dict[str, Any]] = None


@dataclass(frozen=True)
class ContextCompressionProfile:
    """上下文压缩配置模板。"""
    profile_id: str
    profile_name: str
    primary_goal: str
    required_sections: List[str]
    keep_facts: List[str]
    forbidden_output: List[str]
    extra_requirements: List[str]
    storage_decision_rule: str


class SummaryService:
    """
    统一摘要生成服务

    负责以下类型的摘要生成：
    - 大文本消息摘要（message_large）
    - 历史上下文压缩摘要（context_compress）
    """

    def __init__(
        self,
        llm_client: Any,
        max_retries: int = 2,
        retry_delay: float = 1.0,
        enable_logging: bool = True,
        verbose: bool = False,
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        agent_type: Optional[str] = None,
        target_function: Optional[str] = None,
    ):
        self.llm_client = llm_client
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.enable_logging = enable_logging
        self.verbose = verbose
        self.session_id = session_id
        self.agent_id = agent_id
        self.agent_type = agent_type
        self.target_function = target_function

    def _build_tool_client(
        self,
        summary_kind: str,
        agent_id: Optional[str] = None,
        agent_type: Optional[str] = None,
        target_function: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> ToolBasedLLMClient:
        meta_agent_type = agent_type or self.agent_type
        meta_target = target_function or self.target_function
        return ToolBasedLLMClient(
            llm=self.llm_client,
            max_retries=self.max_retries,
            retry_delay=self.retry_delay,
            verbose=self.verbose,
            enable_logging=self.enable_logging,
            session_id=session_id or self.session_id,
            agent_id=agent_id or self.agent_id,
            log_metadata={
                "agent_type": meta_agent_type or "summary_service",
                "target_function": meta_target or "",
                "summary_kind": summary_kind,
            },
        )

    async def _call_summary_tool(
        self,
        summary_kind: str,
        system_prompt: str,
        user_prompt: str,
        tool_func: Any,
        strict: bool = False,
        agent_id: Optional[str] = None,
        agent_type: Optional[str] = None,
        target_function: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> Tuple[str, Optional[Dict[str, Any]]]:
        tool_client = self._build_tool_client(
            summary_kind=summary_kind,
            agent_id=agent_id,
            agent_type=agent_type,
            target_function=target_function,
            session_id=session_id,
        )
        try:
            result = await tool_client.atool_call(
                messages=[HumanMessage(content=user_prompt)],
                tools=[tool_func],
                system_prompt=system_prompt,
            )
        except Exception as e:
            if strict:
                raise RuntimeError(f"{summary_kind} 摘要生成失败: {e}") from e
            return "", None

        summary = ""
        raw_tool_args = None
        if result and result.tool_calls:
            args = result.tool_calls[0].get("args", {}) or {}
            raw_tool_args = args
            summary = (args.get("summary") or "").strip()
        elif result and result.content:
            summary = (result.content or "").strip()

        if not summary and strict:
            raise RuntimeError(f"{summary_kind} 摘要为空，无法继续执行")
        return summary, raw_tool_args

    def _render_anchor_block(self, anchors: Optional[Dict[str, str]]) -> str:
        """
        将压缩目标锚点渲染为 Markdown 纯文本。
        """
        if not anchors:
            return "## 目标锚点\n- 无"

        system_prompt = str(anchors.get("system_prompt") or "").strip()
        first_user_goal = str(anchors.get("first_user_goal") or "").strip()
        task_summary = str(anchors.get("task_summary") or "").strip()

        lines = [
            "## 目标锚点",
            "",
            "### 系统提示词",
            system_prompt or "无",
            "",
            "### 首条用户目标",
            first_user_goal or "无",
            "",
            "### 任务摘要",
            task_summary or "无",
        ]
        return "\n".join(lines)

    async def summarize_message_large(
        self,
        content: str,
        metadata: Optional[Dict[str, Any]] = None,
        agent_id: Optional[str] = None,
        agent_type: Optional[str] = None,
        target_function: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> str:
        """
        为大文本消息生成摘要（用于 MessageManager）。
        """
        if not content.strip():
            return ""
        meta = metadata or {}
        tool_name = meta.get("tool_name", "")
        tool_hint = f"工具: {tool_name}\n" if tool_name else ""
        function_id_rules = (
            "你正在压缩漏洞挖掘/程序分析工具输出，必须优先保留可复用的代码事实：\n"
            "- 函数标识符：优先保留 `search_symbol` 返回的标准 `function_identifier`（原样拷贝）；禁止仅保留 `typeN @0x...`、`sub_xxx @addr` 等弱标识。\n"
            "- 约束信息：保留入参约束、长度/计数/索引边界、类型转换约束、有符号/无符号影响。\n"
            "- 入参约束范围：仅允许目标函数签名参数；局部变量/临时变量仅可作为证据锚点。\n"
            "- 全局与状态：保留全局变量、对象状态、状态机、认证/权限前置约束。\n"
            "- 风险与证据：保留风险操作（拷贝/索引/分配/格式化/释放等）及证据锚点（函数、调用点、地址/偏移、工具输出片段编号）。\n"
            "- 调用关系：保留与漏洞相关的关键调用链（caller -> callee）。\n"
            "- 若内容是源码/反编译正文等中间产物，不要逐行复述代码，只保留支撑结论所需事实。\n"
            "- 不确定信息必须标注为“未知/待验证”，禁止编造。\n"
        )

        def finish_message_summary(summary: str):
            """
            Return a Markdown plain text summary for a large message.

            Args:
                summary: Markdown 纯文本摘要
            """
            pass

        system_prompt = (
            "你是面向漏洞挖掘与程序分析的证据压缩器。"
            "只能输出 Markdown 纯文本摘要。"
            "目标是在尽量短的篇幅中保留后续漏洞分析必须依赖的事实与证据锚点。"
            "禁止编造事实，禁止把推测写成结论。"
            "若出现标准 function_identifier，必须原样保留。"
            "必须调用 finish_message_summary 工具返回结果。"
        )
        user_prompt = (
            f"{tool_hint}"
            f"{function_id_rules}"
            "请对以下内容生成高保真精简摘要。\n"
            "摘要必须包含以下章节（无内容时填写“无”）：\n"
            "- ## 核心结论\n"
            "- ## 函数标识符\n"
            "- ## 关键约束与前置条件\n"
            "- ## 风险操作与证据锚点\n"
            "- ## 关键调用链\n"
            "- ## 未知项与待验证\n"
            "- ## 工具输出索引\n"
            "删除重复叙述、闲聊与流程性噪声，但不得删除关键代码事实。"
            "不要输出任何引用标记（如 [ARTIFACT_REF:...]）或多余标签。\n\n"
            f"{content}\n"
        )
        summary, _ = await self._call_summary_tool(
            summary_kind="message_large",
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            tool_func=finish_message_summary,
            strict=False,
            agent_id=agent_id,
            agent_type=agent_type,
            target_function=target_function,
            session_id=session_id,
        )
        return summary

    async def summarize_context_compression(
        self,
        raw_context: str,
        anchors: Optional[Dict[str, str]] = None,
        compression_profile: str = "general",
        consumer_agent: str = "",
        purpose: str = "",
        agent_id: Optional[str] = None,
        agent_type: Optional[str] = None,
        target_function: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> SummaryCompressionPayload:
        """
        历史上下文压缩摘要（用于 ContextCompressor）。
        """

        def finish_context_compression(
            summary: str,
            store_artifact: bool = False,
            reason: str = "",
        ):
            """
            Return compressed context summary and storage decision.

            Args:
                summary: Markdown 纯文本摘要
                store_artifact: 是否需要将摘要落盘保存
                reason: 落盘或不落盘的原因（可选）
            """
            pass

        profile = self._resolve_context_compression_profile(compression_profile)
        system_prompt = self._build_context_compression_system_prompt(
            profile=profile,
            consumer_agent=consumer_agent,
            purpose=purpose,
        )
        anchor_block = self._render_anchor_block(anchors)
        sections_text = "\n".join(f"- {item}" for item in profile.required_sections)
        keep_facts_text = "\n".join(f"- {item}" for item in profile.keep_facts)
        forbidden_text = "\n".join(f"- {item}" for item in profile.forbidden_output)
        requirements_text = "\n".join(f"- {item}" for item in profile.extra_requirements)
        user_prompt = (
            "请对以下历史对话进行高保真压缩，输出 Markdown 纯文本摘要。\n\n"
            f"## 压缩场景\n"
            f"- profile: `{profile.profile_id}` ({profile.profile_name})\n"
            f"- consumer_agent: `{consumer_agent or 'unknown'}`\n"
            f"- purpose: {purpose or '无'}\n\n"
            f"{anchor_block}\n\n"
            "## 场景目标\n"
            f"- {profile.primary_goal}\n\n"
            "## 必须保留事实\n"
            f"{keep_facts_text}\n\n"
            "## 禁止输出内容\n"
            f"{forbidden_text}\n\n"
            "锚点约束：\n"
            "- 任务目标必须与“首条用户目标”对齐，不得偏题；\n"
            "- 若锚点与历史内容冲突，必须在“未知项与待验证”中标注冲突来源，不得私自改写目标。\n\n"
            "压缩输出必须包含以下小节（无内容写“无”，不得省略标题）：\n"
            f"{sections_text}\n\n"
            "额外要求：\n"
            f"{requirements_text}\n\n"
            "请同时决策 `store_artifact`：\n"
            f"{profile.storage_decision_rule}\n\n"
            "## 原始上下文\n"
            f"{raw_context}\n"
        )
        effective_session_id = session_id or self.session_id
        summary_agent_id = f"context_compressor_{effective_session_id}" if effective_session_id else "context_compressor_default"
        summary, raw_tool_args = await self._call_summary_tool(
            summary_kind="context_compress",
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            tool_func=finish_context_compression,
            strict=False,
            agent_id=summary_agent_id,
            agent_type="context_compressor",
            target_function="context_compression",
            session_id=effective_session_id,
        )
        store_artifact = False
        reason = ""
        if raw_tool_args:
            store_artifact = bool(raw_tool_args.get("store_artifact"))
            reason = (raw_tool_args.get("reason") or "").strip()

        return SummaryCompressionPayload(
            summary=summary,
            store_artifact=store_artifact,
            reason=reason,
            raw_tool_args=raw_tool_args,
        )

    def _build_context_compression_system_prompt(
        self,
        profile: ContextCompressionProfile,
        consumer_agent: str,
        purpose: str,
    ) -> str:
        """
        构建上下文压缩 System Prompt（按 profile 动态生成）。
        """
        return (
            "你是程序分析任务的上下文压缩器，只能输出 Markdown 纯文本摘要。"
            "你必须根据当前 profile 产出“最小但充分”的任务记忆，并服务指定 consumer。"
            "禁止编造事实或推断未出现的信息；未知信息必须显式标注。"
            "必须先对齐锚点（系统提示词、首条用户目标）再压缩。"
            "对源码型 tool 输出（如 get_function_def/read_file/search_code/read_artifact）仅保留结论与证据，不复述源码正文。"
            "若出现标准 function_identifier，必须原样保留。"
            "入参约束仅允许函数签名参数；局部变量仅可作为证据锚点。"
            "必须保留已执行 Tool Call 去重记忆（tool_name + args）。"
            "必须调用 finish_context_compression 工具返回结果。"
            f"\n当前 profile: {profile.profile_id} ({profile.profile_name})。"
            f"\nconsumer_agent: {consumer_agent or 'unknown'}。"
            f"\npurpose: {purpose or '无'}。"
        )

    def _resolve_context_compression_profile(self, profile_id: str) -> ContextCompressionProfile:
        """
        根据 profile_id 返回上下文压缩模板。
        """
        pid = (profile_id or "general").strip().lower()

        common_keep_facts = [
            "目标锚点与任务目标",
            "标准 function_identifier（原样）",
            "已执行 Tool Call + args + 返回摘要（用于防重复）",
            "已完成与未完成子任务边界",
            "仍需最小取证集（避免全量重查）",
            "证据冲突及其来源消息索引（若存在）",
        ]
        common_requirements = [
            "对多任务场景，必须区分“可直接输出”与“待补证据”",
            "只保留事实与证据，不输出修复建议或规范性建议",
            "入参约束仅允许函数签名参数；局部变量只作为证据锚点",
            "同 tool_name + args 默认禁止重复调用，除非目标变化或证据不足",
        ]

        if pid == "code_explorer":
            return ContextCompressionProfile(
                profile_id="code_explorer",
                profile_name="代码探索压缩",
                primary_goal="最大化保留下一轮代码探索可直接复用的信息，减少漏洞分析噪声。",
                required_sections=[
                    "## 任务目标",
                    "## 目标函数与标识符",
                    "## 已完成探索",
                    "## 当前探索进度（可直接输出/待补证据）",
                    "## 仍需 Tool Call 的最小取证集",
                    "## 已执行 Tool Call 与返回摘要（防重复）",
                    "## 未知项与待验证",
                    "## 关键工具输出索引",
                ],
                keep_facts=common_keep_facts + [
                    "函数枚举结果、签名、分发关系等探索主线事实",
                    "本轮已确认/未确认的映射关系与缺口",
                ],
                forbidden_output=[
                    "漏洞评级、可利用性判定、风险优先级列表",
                    "“高风险调用链摘要”这类偏漏洞研判章节",
                    "与当前探索目标无关的修复建议/审计建议",
                ],
                extra_requirements=common_requirements + [
                    "压缩结果优先支持“继续探索下一步”而非“直接漏洞报告”",
                    "若分发映射未补齐，明确列出最小缺口（函数定义或调用点）",
                ],
                storage_decision_rule=(
                    "- 当摘要包含多函数标识符、分发关系、探索进度与最小取证集且预期复用时，设为 true；\n"
                    "- 当内容是一次性临时探索记录、复用价值低时，设为 false；\n"
                    "- `reason` 用一句话说明依据。"
                ),
            )

        if pid == "vuln_analysis":
            return ContextCompressionProfile(
                profile_id="vuln_analysis",
                profile_name="漏洞分析压缩",
                primary_goal="保留漏洞研判所需约束、证据与调用链，支撑下一轮漏洞分析。",
                required_sections=[
                    "## 任务目标",
                    "## 目标函数与标识符",
                    "## 已完成工作",
                    "## 关键约束（入参/边界/全局/状态）",
                    "## 漏洞相关证据与调用链",
                    "## 已执行 Tool Call 与返回摘要（防重复）",
                    "## 任务级判定进度（可直接输出/待补证据）",
                    "## 仍需 Tool Call 的最小取证集",
                    "## 未完成事项",
                    "## 未知项与待验证",
                    "## 关键工具输出索引",
                ],
                keep_facts=common_keep_facts + [
                    "可控输入、路径条件、校验逻辑、长度上限、状态前置",
                    "风险操作证据与关键调用链",
                ],
                forbidden_output=[
                    "与漏洞分析无关的流程噪声与闲聊内容",
                ],
                extra_requirements=common_requirements,
                storage_decision_rule=(
                    "- 当摘要包含关键函数标识符、参数约束、漏洞证据与调用链且预期复用时，设为 true；\n"
                    "- 当内容一次性且复用价值低时，设为 false；\n"
                    "- `reason` 用一句话说明依据。"
                ),
            )

        if pid in {"orchestrator", "task_executor", "execution"}:
            return ContextCompressionProfile(
                profile_id="orchestrator",
                profile_name="编排执行压缩",
                primary_goal="保留编排推进与取证闭环所需事实，避免执行空转。",
                required_sections=[
                    "## 任务目标",
                    "## 已完成工作",
                    "## 当前可直接决策事项",
                    "## 待补证据事项",
                    "## 仍需 Tool Call 的最小动作集",
                    "## 已执行 Tool Call 与返回摘要（防重复）",
                    "## 任务状态与阻塞点",
                    "## 未知项与待验证",
                ],
                keep_facts=common_keep_facts + [
                    "任务状态变化、错误码、阻塞原因与恢复动作",
                    "可直接继续执行的 task_id / tool 调用线索",
                ],
                forbidden_output=[
                    "详细漏洞利用推导",
                    "与任务推进无关的长篇源码细节",
                ],
                extra_requirements=common_requirements + [
                    "优先输出可执行的下一步，不输出空泛描述",
                ],
                storage_decision_rule=(
                    "- 当摘要包含任务状态、阻塞点与可执行下一步且会在后续轮次复用时，设为 true；\n"
                    "- 当内容仅用于一次性过渡且复用价值低时，设为 false；\n"
                    "- `reason` 用一句话说明依据。"
                ),
            )

        return ContextCompressionProfile(
            profile_id="general",
            profile_name="通用压缩",
            primary_goal="保留后续继续分析所需最小事实闭环。",
            required_sections=[
                "## 任务目标",
                "## 关键事实",
                "## 已完成工作",
                "## 待补证据",
                "## 已执行 Tool Call 与返回摘要（防重复）",
                "## 仍需 Tool Call 的最小取证集",
                "## 未知项与待验证",
            ],
            keep_facts=common_keep_facts,
            forbidden_output=[
                "与当前任务目标无关的扩展分析",
            ],
            extra_requirements=common_requirements,
            storage_decision_rule=(
                "- 当摘要在后续任务中可复用时，设为 true；否则设为 false；\n"
                "- `reason` 用一句话说明依据。"
            ),
        )

__all__ = [
    "SummaryService",
    "SummaryCompressionPayload",
    "ContextCompressionProfile",
]
