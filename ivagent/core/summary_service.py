#!/usr/bin/env python3
"""
SummaryService - 统一摘要生成服务

集中管理所有摘要类 LLM 调用的提示词与工具逻辑，避免分散实现。
"""

from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from langchain_core.messages import HumanMessage

from .tool_llm_client import ToolBasedLLMClient


@dataclass
class SummaryCompressionPayload:
    """上下文压缩结果载体"""
    summary: str
    store_artifact: bool = False
    reason: str = ""
    raw_tool_args: Optional[Dict[str, Any]] = None


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
            "- 全局与状态：保留全局变量、对象状态、状态机、认证/权限前置约束。\n"
            "- 风险与证据：保留风险操作（拷贝/索引/分配/格式化/释放等）及证据锚点（函数、调用点、地址/偏移、工具输出片段编号）。\n"
            "- 调用关系：保留与漏洞相关的关键调用链（caller -> callee）。\n"
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

        system_prompt = (
            "你是漏洞挖掘与程序分析任务的上下文压缩器，只能输出 Markdown 纯文本摘要。"
            "你的目标是把长历史对话压缩成“最小但充分”的分析记忆，保证后续可直接继续漏洞挖掘。"
            "禁止编造事实或推断未出现的信息；未知信息必须显式标注为未知。"
            "必须优先保留标准 function_identifier（原样）、关键调用链、入参与边界约束、全局/状态约束、风险操作证据。"
            "如证据存在冲突，保留冲突双方并注明来源消息索引。"
            "必须调用 finish_context_compression 工具返回结果。"
        )
        user_prompt = (
            "请对以下历史对话进行高保真压缩，输出 Markdown 纯文本摘要。\n\n"
            "压缩输出必须包含以下小节（无内容写“无”，不得省略标题）：\n"
            "- ## 任务目标\n"
            "- ## 目标函数与标识符\n"
            "- ## 已完成工作\n"
            "- ## 关键约束（入参/边界/全局/状态）\n"
            "- ## 漏洞相关证据与调用链\n"
            "- ## 未完成事项\n"
            "- ## 未知项与待验证\n"
            "- ## 关键工具输出索引\n\n"
            "额外要求：\n"
            "- 若出现函数标识符，必须原样保留标准 function_identifier；\n"
            "- 保留可利用性相关事实：可控输入、路径条件、过滤/校验、长度上限、状态前置；\n"
            "- 不要输出规范性建议（如“应当/需要修复”），只保留事实与证据。\n\n"
            "请同时决策 `store_artifact`：\n"
            "- 当摘要包含多个关键函数标识符、关键约束、调用链证据，且预期会被后续任务复用时，设为 true；\n"
            "- 当内容一次性、重复性高、复用价值低时，设为 false；\n"
            "- `reason` 用一句话说明决策依据。\n\n"
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

__all__ = [
    "SummaryService",
    "SummaryCompressionPayload",
]
