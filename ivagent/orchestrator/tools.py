#!/usr/bin/env python3
"""
Orchestrator Tools - 简化的 Tool 管理

所有 Tools 整合到一个类中，通过类变量共享状态：
- engine: 当前分析引擎
- workflow_context: Workflow 上下文
- llm_client: LLM 客户端
- agents: 创建的 Agent 缓存
- vulnerabilities: 发现的漏洞列表
"""


from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from pathlib import Path
import uuid
import json
import asyncio
import re

from .agent_delegate import AgentDelegate
from ..models.workflow import WorkflowContext

from ..engines import create_engine, BaseStaticAnalysisEngine
from ..engines.base_static_analysis_engine import SearchOptions
from ..agents.deep_vuln_agent import DeepVulnAgent
from ..agents.prompts import get_vuln_agent_system_prompt
from ..core.context import ArtifactStore
from ..core import SummaryService
from ..core.tool_llm_client import ToolBasedLLMClient
from ..core.cli_logger import CLILogger
from langchain_core.messages import HumanMessage



@dataclass
class AgentInstance:
    """Agent 实例记录"""
    agent_id: str
    agent_type: str
    engine_name: str
    analysis_focus: str
    instance: Any = None


@dataclass
class VulnerabilityInfo:
    """漏洞信息"""
    name: str
    vuln_type: str
    description: str
    location: str
    severity: float
    confidence: float
    evidence: List[str] = field(default_factory=list)
    remediation: str = ""


class OrchestratorTools:
    """
    Orchestrator 工具集合
    
    所有工具方法共享类变量状态，无需通过参数传递上下文。
    """

    def __init__(
            self,
            llm_client: Any = None,
            workflow_context: Optional[WorkflowContext] = None,
            engine_type: Optional[str] = None,
            target_path: Optional[str] = None,
            source_root: Optional[str] = None,
            artifact_store: Optional[ArtifactStore] = None,
            session_id: Optional[str] = None,
            max_vuln_concurrency: int = 3,
            summary_service: Optional[SummaryService] = None,
            tool_output_summary_threshold: int = 4000,
            verbose: bool = True,
            logger: Optional[CLILogger] = None,
    ):

        self.llm_client = llm_client
        self.workflow_context = workflow_context

        # 共享状态
        self.engine: Optional[BaseStaticAnalysisEngine] = None
        self.engine_name: Optional[str] = None
        self.agents: Dict[str, AgentInstance] = {}
        self.vulnerabilities: List[VulnerabilityInfo] = []
        self._last_agent_id: Optional[str] = None
        self.artifact_store: Optional[ArtifactStore] = artifact_store
        self.summary_service: Optional[SummaryService] = summary_service
        self._tool_summary_service: Optional[SummaryService] = None
        self.tool_output_summary_threshold = max(0, int(tool_output_summary_threshold))


        # 延迟初始化参数（用于异步初始化）

        self._pending_engine_type = engine_type
        self._pending_target_path = target_path
        self._pending_source_root = source_root
        self._initialized = False
        
        # 工作流规划状态
        self._planned_workflows: Optional[List[Dict[str, Any]]] = None
        self._is_multi_workflow: bool = False
        
        # 新设计的组件（简化的任务编排）
        self._session_id = session_id
        self._task_list_manager: Optional[Any] = None
        self._agent_delegate: Optional[AgentDelegate] = None
        self._message_manager: Optional[Any] = None
        self._verified_function_identifiers: Dict[str, set[str]] = {}
        self.max_vuln_concurrency = max(1, int(max_vuln_concurrency))
        self._recovery_lock_task_id: Optional[str] = None
        self._claimant_id = f"claimant_{uuid.uuid4().hex[:8]}"
        self.verbose = verbose
        self._logger = logger or CLILogger(component="OrchestratorTools", verbose=verbose)

    def _set_recovery_lock(self, task_id: str) -> None:
        """锁定需要恢复的任务，避免执行阶段跳到其他任务。"""
        self._recovery_lock_task_id = task_id

    def _clear_recovery_lock(self, task_id: Optional[str] = None) -> None:
        """清除恢复锁。若指定 task_id，则仅在匹配时清除。"""
        if not self._recovery_lock_task_id:
            return
        if task_id and self._recovery_lock_task_id != task_id:
            return
        self._recovery_lock_task_id = None

    def _format_recovery_lock_error(
        self,
        task_id: str,
        description: str = "",
        task_group: Optional[str] = None,
    ) -> str:
        """生成恢复锁定态的错误提示。"""
        return self._format_recoverable_error(
            error_code="RECOVERY_LOCK_ACTIVE",
            message=f"存在未恢复的任务锁定：{task_id}，请先完成该任务的 function_identifier 绑定。",
            payload={
                "task_id": task_id,
                "task_description": description,
                "task_group": task_group or "",
                "required_next_actions": [
                    "先为锁定任务补齐并验证 function_identifier",
                    "恢复后重试执行工具",
                ],
            },
        )

    # ==================== 内部方法 ====================

    def _get_next_task_index(self) -> int:
        """获取下一个任务序号（用于 append_tasks 的 task_id 预分配）。"""
        if not self._task_list_manager:
            return 1
        max_num = 0
        for task in self._task_list_manager.get_all_tasks():
            try:
                num = int(str(task.id).split("_", 1)[1])
                max_num = max(max_num, num)
            except Exception:
                continue
        return max_num + 1

    def _build_artifact_summary(self, text: str, max_chars: int = 220) -> str:
        """生成简短摘要，供 Artifact 元数据使用。"""
        compact = " ".join(str(text or "").split())
        if len(compact) <= max_chars:
            return compact
        return compact[: max_chars - 3] + "..."

    def _externalize_analysis_context(
        self,
        flat_tasks: List[Dict[str, Any]],
        start_index: int = 1,
    ) -> None:
        """
        将任务的 analysis_context 写入 artifacts 文件，并在任务中保存引用文件名。

        说明：
            - 仅当 analysis_context 非空时生效
            - 使用 ArtifactStore 统一落盘
        """
        if not self.artifact_store:
            return
        for offset, task in enumerate(flat_tasks):
            raw_context = task.get("analysis_context")
            if raw_context is None:
                continue
            context_text = str(raw_context).strip()
            if not context_text:
                continue
            task_id = f"task_{start_index + offset}"
            artifact = self.artifact_store.put_text(
                content=context_text,
                kind="analysis_context",
                summary=self._build_artifact_summary(context_text),
                task_id=task_id,
                workflow_id=str(task.get("task_group") or ""),
                producer="plan_tasks",
                metadata={
                    "kind": "analysis_context",
                    "task_id": task_id,
                    "task_group": str(task.get("task_group") or ""),
                },
            )
            task["analysis_context"] = artifact.artifact_id

    def _resolve_task_analysis_context(self, task: Any) -> str:
        """
        解析任务的 analysis_context 引用为具体内容。

        返回：
            解析后的前置信息文本（可能为空）
        """
        value = getattr(task, "analysis_context", None)
        if not value:
            return ""
        if self.artifact_store and self.artifact_store.exists(str(value)):
            return self.artifact_store.read(str(value))
        return str(value)

    def _build_task_context(self, task: Any, additional_context: str) -> str:
        """
        构建任务执行上下文，优先注入 analysis_context。
        """
        analysis_context = self._resolve_task_analysis_context(task).strip()
        extra = (additional_context or "").strip()
        if analysis_context and extra:
            return f"{analysis_context}\n\n{extra}"
        return analysis_context or extra

    def _extract_artifact_id(self, ref: str) -> str:
        """
        解析 artifact 引用字符串，兼容 `[ARTIFACT_REF:xxx]` 与 `xxx`。
        """
        value = str(ref or "").strip()
        if not value:
            return ""
        match = re.match(r"^\[ARTIFACT_REF:([A-Za-z0-9_\-]+)\]$", value)
        if match:
            return match.group(1)
        return value

    def _read_context_ref_text(self, context_ref: str) -> str:
        """
        读取上下文引用内容。

        支持：
        - ArtifactStore 的 artifact_id 或 `[ARTIFACT_REF:artifact_id]`
        """
        ref = self._extract_artifact_id(context_ref)
        if not ref:
            return ""

        if self.artifact_store and self.artifact_store.exists(ref):
            return self.artifact_store.read(ref)

        return ""

    def _merge_task_context(
        self,
        task: Any,
        additional_context: str,
        context_ref: str = "",
    ) -> str:
        """
        合并任务上下文（analysis_context + context_ref + additional_context）。
        """
        base = self._build_task_context(task, additional_context)
        from_ref = self._read_context_ref_text(context_ref).strip()
        if from_ref and base:
            return f"{from_ref}\n\n{base}"
        return from_ref or base

    def _resolve_selected_input_files(
        self,
        current_task_id: str,
        task_group: Optional[str],
        selected_file_ids: Optional[List[str]],
    ) -> Tuple[List[str], List[str]]:
        """
        将 selected_file_ids 解析为实际输入 artifact_ref。
        """
        selected = []
        seen: Set[str] = set()
        for file_id in selected_file_ids or []:
            normalized = str(file_id or "").strip()
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            selected.append(normalized)

        if not selected:
            return [], []

        if not self.artifact_store:
            return [], selected

        resolved: List[str] = []
        unresolved: List[str] = []

        candidates = self._get_previous_task_outputs(current_task_id, task_group=task_group)
        candidate_set = set(candidates)

        for file_id in selected:
            if file_id in candidate_set and self.artifact_store.exists(file_id):
                resolved.append(file_id)
                continue
            if self.artifact_store.exists(file_id):
                resolved.append(file_id)
                continue
            unresolved.append(file_id)

        return resolved, unresolved

    def _resolve_artifact_refs(
        self,
        artifact_refs: List[str],
    ) -> Tuple[List[Dict[str, str]], List[str]]:
        """
        解析 artifact_refs，返回可读取条目与失败条目。
        """
        resolved: List[Dict[str, str]] = []
        unresolved: List[str] = []

        for raw_ref in artifact_refs or []:
            ref = str(raw_ref or "").strip()
            if not ref:
                continue
            artifact_id = self._extract_artifact_id(ref)
            if not artifact_id:
                unresolved.append(ref)
                continue

            if self.artifact_store and self.artifact_store.exists(artifact_id):
                content = self.artifact_store.read(artifact_id)
                resolved.append(
                    {
                        "ref": ref,
                        "source": "artifact_store",
                        "id": artifact_id,
                        "content": content,
                    }
                )
                continue

            unresolved.append(ref)

        return resolved, unresolved

    def _ensure_agent_delegate(self) -> Optional[str]:
        """
        确保 AgentDelegate 可用，失败时返回错误文本。
        """
        if self._agent_delegate:
            return None
        if not self.engine:
            return "[错误] 引擎未初始化，无法创建 AgentDelegate。请先初始化引擎并重新初始化 Orchestrator。"
        if not self.llm_client:
            return "[错误] LLM 客户端未初始化，无法创建 AgentDelegate。"
        if not self.artifact_store:
            return "[错误] ArtifactStore 未初始化，无法创建 AgentDelegate。"
        from .agent_delegate import AgentDelegate
        self._agent_delegate = AgentDelegate(
            engine=self.engine,
            llm_client=self.llm_client,
            artifact_store=self.artifact_store,
            verbose=self.verbose,
        )
        return None

    def _format_recoverable_error(
        self,
        error_code: str,
        message: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> str:
        """统一生成可恢复错误响应（纯文本 Markdown）。"""
        lines = [f"[错误] {error_code}: {message}"]
        if payload:
            task_id = str(payload.get("task_id", "") or "").strip()
            if task_id:
                lines.append(f"- task_id: `{task_id}`")
            task_group = str(payload.get("task_group", "") or "").strip()
            if task_group:
                lines.append(f"- task_group: `{task_group}`")
            task_description = str(payload.get("task_description", "") or "").strip()
            if task_description:
                lines.append(f"- task_description: {task_description}")
            task_status = str(payload.get("task_status", "") or "").strip()
            if task_status:
                lines.append(f"- task_status: `{task_status}`")
            artifact_ref = str(payload.get("artifact_ref", "") or "").strip()
            if artifact_ref:
                lines.append(f"- artifact_ref: `{artifact_ref}`")
            task_groups = payload.get("task_groups")
            if isinstance(task_groups, list) and task_groups:
                lines.append(f"- task_groups: {', '.join(str(x) for x in task_groups)}")
            missing_sections = payload.get("missing_sections")
            if isinstance(missing_sections, list) and missing_sections:
                lines.append(f"- missing_sections: {', '.join(str(x) for x in missing_sections)}")

            actions = payload.get("required_next_actions")
            if isinstance(actions, list) and actions:
                lines.extend(["", "建议操作："])
                lines.extend([f"- {str(action)}" for action in actions[:5]])
        return "\n".join(lines)

    def _get_summary_service(self) -> Optional[SummaryService]:
        """获取用于工具输出摘要的 SummaryService（必要时惰性创建）。"""
        if self.summary_service:
            return self.summary_service
        if not self.llm_client:
            return None
        if not self._tool_summary_service:
            self._tool_summary_service = SummaryService(
                llm_client=self.llm_client,
                max_retries=2,
                retry_delay=1.0,
                enable_logging=True,
                verbose=False,
                session_id=self._session_id,
                agent_id=f"tool_summary_{self._session_id or id(self)}",
                agent_type="tool_summary",
                target_function="orchestrator_tools",
            )
        return self._tool_summary_service

    def _should_summarize_tool_output(self, content: str) -> bool:
        """
        判断是否需要对工具输出生成摘要。

        说明:
            - 仅在输出超长时摘要
            - 对错误输出保持原文，避免丢失关键信息
        """
        if not content:
            return False
        if self.tool_output_summary_threshold <= 0:
            return False
        if content.lstrip().startswith("[错误]"):
            return False
        return len(content) > self.tool_output_summary_threshold

    async def _summarize_tool_output(self, tool_name: str, content: str) -> str:
        """调用 LLM 生成工具输出摘要（Markdown 纯文本）。"""
        service = self._get_summary_service()
        if not service:
            return ""
        return await service.summarize_message_large(
            content=content,
            metadata={"tool_name": tool_name},
        )

    async def _maybe_pack_tool_output(self, tool_name: str, content: str) -> Any:
        """
        仅在输出超长时返回 content/summary 双轨结构，否则返回原文。
        """
        if not self._should_summarize_tool_output(content):
            return content
        summary = await self._summarize_tool_output(tool_name, content)
        if not summary:
            return content
        return {"content": content, "summary": summary}

    @staticmethod
    def _build_neutral_vuln_task_description(function_identifier: str, fallback: str = "") -> str:
        """构造中性的 vuln_analysis 任务描述，避免预设具体漏洞类型。"""
        fid = str(function_identifier or "").strip()
        if fid:
            return f"挖掘 {fid} 中的漏洞"
        normalized_fallback = str(fallback or "").strip()
        return normalized_fallback or "执行漏洞挖掘任务"

    async def _validate_and_normalize_workflows(
        self,
        workflows: List[Dict[str, Any]],
        verify_function_identifier: bool = True,
        verified_identifiers: Optional[Set[str]] = None,
    ) -> Tuple[Optional[List[Dict[str, Any]]], Optional[str], Set[str]]:
        """
        校验并标准化 workflows 结构，返回标准化结果与已验证的函数标识符集合。

        Args:
            workflows: 原始 workflow 列表
            verify_function_identifier: 是否调用 search_symbol 进行校验
            verified_identifiers: 已验证的 function_identifier 集合（可选）

        Returns:
            (标准化后的 workflows, 错误信息, 已验证标识符集合)
        """
        if not workflows:
            return None, "[错误] workflows 参数为空", set()
        if not isinstance(workflows, list):
            return None, "[错误] workflows 必须是列表类型", set()

        verified = set(verified_identifiers or [])

        for i, wf in enumerate(workflows):
            if not isinstance(wf, dict):
                return None, f"[错误] workflow[{i}] 不是字典类型", verified
            if "tasks" not in wf:
                return None, f"[错误] workflow[{i}] 缺少必需字段 'tasks'", verified

            tasks = wf["tasks"]
            if isinstance(tasks, dict):
                if "tasks" in tasks:
                    wf["tasks"] = tasks["tasks"]
                elif "task_list" in tasks:
                    wf["tasks"] = tasks["task_list"]
                else:
                    wf["tasks"] = list(tasks.values()) if tasks else []
                tasks = wf["tasks"]

            if not isinstance(tasks, list) or not tasks:
                return None, f"[错误] workflow[{i}] 的 'tasks' 必须是非空列表", verified

            for j, task in enumerate(tasks):
                if isinstance(task, str):
                    description = task.strip()
                    return None, self._format_recoverable_error(
                        error_code="MISSING_AGENT_TYPE_IN_PLAN",
                        message=f"workflow[{i}] 的 tasks[{j}] 缺少 agent_type（任务必须显式指定）。",
                        payload={
                            "workflow_index": i,
                            "task_index": j,
                            "task_description": description,
                            "required_next_actions": [
                                "将该任务改为对象形式，并补充 agent_type",
                                "若为 vuln_analysis 任务，补充 function_identifier",
                                "重新调用 plan_tasks(workflows)",
                            ],
                        },
                    ), verified
                if isinstance(task, dict):
                    if "description" not in task:
                        return None, f"[错误] workflow[{i}] 的 tasks[{j}] 缺少 description 字段", verified
                    description = str(task["description"]).strip()
                    agent_type = task.get("agent_type")
                    function_identifier = (task.get("function_identifier") or "").strip()

                    if not agent_type:
                        return None, self._format_recoverable_error(
                            error_code="MISSING_AGENT_TYPE_IN_PLAN",
                            message=f"workflow[{i}] 的 tasks[{j}] 缺少 agent_type（任务必须显式指定）。",
                            payload={
                                "workflow_index": i,
                                "task_index": j,
                                "task_description": description,
                                "required_next_actions": [
                                    "为该任务补充 agent_type（code_explorer / vuln_analysis）",
                                    "若为 vuln_analysis 任务，补充 function_identifier",
                                    "重新调用 plan_tasks(workflows)",
                                ],
                            },
                        ), verified

                    if agent_type == "vuln_analysis" and not function_identifier:
                        return None, self._format_recoverable_error(
                            error_code="MISSING_FUNCTION_IDENTIFIER_IN_PLAN",
                            message=f"workflow[{i}] 的 tasks[{j}] 缺少 function_identifier（vuln_analysis 必需）。",
                            payload={
                                "workflow_index": i,
                                "task_index": j,
                                "task_description": description,
                                "required_next_actions": [
                                    "先调用 delegate_task(agent_type='code_explorer')，并要求使用 search_symbol 返回标准函数标识符",
                                    "将返回的 function_identifier 原样填写到该 vuln_analysis 任务",
                                    "重新调用 plan_tasks(workflows)",
                                ],
                            },
                        ), verified

                    analysis_context = task.get("analysis_context")
                    if analysis_context is None:
                        analysis_context = ""
                    if not isinstance(analysis_context, str):
                        analysis_context = str(analysis_context)

                    if agent_type == "vuln_analysis":
                        description = self._build_neutral_vuln_task_description(
                            function_identifier=function_identifier,
                            fallback=description,
                        )
                        if verify_function_identifier:
                            if not self.engine:
                                return None, self._format_recoverable_error(
                                    error_code="ENGINE_NOT_READY_FOR_FUNCTION_IDENTIFIER_VALIDATION",
                                    message="引擎未初始化，无法使用 search_symbol 校验 function_identifier。",
                                    payload={
                                        "workflow_index": i,
                                        "task_index": j,
                                        "function_identifier": function_identifier,
                                        "required_next_actions": [
                                            "先初始化分析引擎",
                                            "调用 delegate_task(agent_type='code_explorer') 或 search_symbol 进行校验",
                                            "确认后重新调用 plan_tasks(workflows)",
                                        ],
                                    },
                                ), verified

                            is_verified = await self._is_function_identifier_verified_by_search_symbol(
                                function_identifier
                            )
                            if not is_verified:
                                return None, self._format_recoverable_error(
                                    error_code="UNVERIFIED_FUNCTION_IDENTIFIER_IN_PLAN",
                                    message=(
                                        f"workflow[{i}] 的 tasks[{j}] function_identifier 未通过 "
                                        "search_symbol 验证。function_identifier 必须是单个字符串，"
                                        "不可使用列表/拼接字符串；多函数分析需拆分为多个任务。"
                                    ),
                                    payload={
                                        "workflow_index": i,
                                        "task_index": j,
                                        "task_description": description,
                                        "function_identifier": function_identifier,
                                        "required_next_actions": [
                                            "调用 delegate_task(agent_type='code_explorer') 使用 search_symbol 获取标准标识符",
                                            "将 function_identifier 替换为 search_symbol 的单个返回值（保持原样）",
                                            "若需多函数分析，请拆分为多个 vuln_analysis 任务",
                                            "重新调用 plan_tasks(workflows)",
                                        ],
                                    },
                                ), verified
                            verified.add(function_identifier)
                        else:
                            if verified and function_identifier not in verified:
                                return None, (
                                    f"[错误] workflow[{i}] 的 tasks[{j}] function_identifier "
                                    f"未在已验证集合中: {function_identifier}"
                                ), verified
                        if not analysis_context.strip():
                            return None, self._format_recoverable_error(
                                error_code="MISSING_ANALYSIS_CONTEXT_IN_PLAN",
                                message=f"workflow[{i}] 的 tasks[{j}] 缺少 analysis_context（漏洞挖掘上下文摘要）。",
                                payload={
                                    "workflow_index": i,
                                    "task_index": j,
                                    "task_description": description,
                                    "required_next_actions": [
                                        "调用 delegate_task(agent_type='code_explorer') 获取参数级入参约束（来源/可控性/污点/边界/校验）与全局变量约束/证据锚点",
                                        "将上述信息写入该 vuln_analysis 任务的 analysis_context（纯文本）",
                                        "重新调用 plan_tasks(workflows)",
                                    ],
                                },
                            ), verified
                        required_sections = [
                            "## 目标函数",
                            "## 入参约束",
                            "## 全局变量约束",
                            "## 证据锚点",
                        ]
                        missing_sections = [
                            section for section in required_sections
                            if section not in analysis_context
                        ]
                        if missing_sections:
                            missing_text = "、".join(missing_sections)
                            return None, self._format_recoverable_error(
                                error_code="MISSING_ANALYSIS_CONTEXT_SECTIONS_IN_PLAN",
                                message=(
                                    f"workflow[{i}] 的 tasks[{j}] analysis_context 缺少必需章节："
                                    f"{missing_text}"
                                ),
                                payload={
                                    "workflow_index": i,
                                    "task_index": j,
                                    "task_description": description,
                                    "missing_sections": missing_sections,
                                    "required_next_actions": [
                                        "调用 delegate_task(agent_type='code_explorer') 重新抽取目标函数参数级约束",
                                        "按固定章节写入 analysis_context：目标函数/入参约束（逐参数：来源/可控性/污点/边界/校验/证据）/全局变量约束/证据锚点",
                                        "重新调用 plan_tasks(workflows)",
                                    ],
                                },
                            ), verified

                    tasks[j] = {
                        "description": description,
                        "agent_type": agent_type,
                        "function_identifier": function_identifier or None,
                        "analysis_context": analysis_context.strip(),
                    }
                    continue
                return None, f"[错误] workflow[{i}] 的 tasks[{j}] 类型不支持（仅支持字典对象）", verified

        return workflows, None, verified

    async def _is_function_identifier_verified_by_search_symbol(self, identifier: str) -> bool:
        """通过 search_symbol 校验 function_identifier 是否可解析。"""
        normalized = (identifier or "").strip()
        if not normalized or not self.engine:
            return False

        try:
            results = await self.engine.search_symbol(
                query=normalized,
                options=SearchOptions(limit=20),
            )
        except Exception:
            return False

        for item in results or []:
            function_identifier = (getattr(item, "identifier", "") or "").strip()
            name = (getattr(item, "name", "") or "").strip()
            if function_identifier == normalized or name == normalized:
                return True
        return False

    async def initialize(
            self,
            engine_type: Optional[str] = None,
            target_path: Optional[str] = None,
            source_root: Optional[str] = None,
    ) -> bool:
        """异步初始化分析引擎。"""
        # 使用延迟初始化参数（如果没有提供新参数）
        engine_name = (engine_type or self._pending_engine_type)
        target = (target_path or self._pending_target_path)
        src_root = (source_root or self._pending_source_root)

        if not engine_name or not target:
            return False

        engine_name = engine_name.lower()
        path = Path(target)

        if not path.exists():
            raise ValueError(f"Target path does not exist: {target}")

        try:
            self.engine = create_engine(
                engine_type=engine_name,
                target_path=target,
                source_root=src_root,
                max_concurrency=10,
                llm_client=self.llm_client,
                logger=self._logger,
            )

            # 异步初始化
            initialized = await self.engine.initialize()
            if not initialized:
                raise ValueError(f"Failed to initialize {engine_name} engine")

            self.engine_name = engine_name
            self._initialized = True
            return True

        except Exception as e:
            raise ValueError(f"Engine initialization failed: {e}")

    def _ensure_initialized(self) -> None:
        """确保引擎已初始化"""
        if not self._initialized or not self.engine:
            raise ValueError("Engine not initialized. Call initialize() first.")

    def set_artifact_store(self, artifact_store: ArtifactStore) -> None:
        """设置 ArtifactStore（用于 read_artifact 工具）"""
        self.artifact_store = artifact_store

    def set_message_manager(self, message_manager: Any) -> None:
        """设置 MessageManager（用于上下文压缩投影裁切）。"""
        self._message_manager = message_manager

    def initialize_orchestrator_components(self, session_dir: Path) -> None:
        """初始化简化的任务编排组件（幂等）
        
        Args:
            session_dir: Session 目录路径（如 .ivagent/sessions/{session_id}）
        """
        from .task_list_manager import TaskListManager
        from .agent_delegate import AgentDelegate

        # 初始化 TaskListManager（幂等）
        if not self._task_list_manager:
            tasks_file = session_dir / "tasks.md"
            self._task_list_manager = TaskListManager(tasks_file=tasks_file)
        
        # 初始化 AgentDelegate（幂等）
        if self.engine and self.llm_client and not self._agent_delegate:
            self._agent_delegate = AgentDelegate(
                engine=self.engine,
                llm_client=self.llm_client,
                artifact_store=self.artifact_store,
                verbose=self.verbose,
            )

    # ==================== Tool 定义 ====================

    async def read_artifact(
            self,
            artifact_id: str,
            offset: int = 0,
            limit: int = 200,
    ) -> Any:
        """读取已归档的 Artifact 原文内容。

        参数:
            artifact_id: Artifact ID
            offset: 起始行号（从0开始）
            limit: 返回行数上限

        返回:
            正文内容；若输出超长，返回 {"content": "...", "summary": "..."}。
        """
        if not self.artifact_store:
            return "[错误] ArtifactStore 未初始化"

        content = self.artifact_store.read(artifact_id, offset=offset, limit=limit)
        return await self._maybe_pack_tool_output("read_artifact", content)

    async def mark_compression_projection(
            self,
            remove_message_ids: Optional[List[str]] = None,
            fold_message_ids: Optional[List[str]] = None,
            reason: str = "",
    ) -> str:
        """
        提交上下文压缩前裁切清单（按 message_id，支持删除与折叠）。

        参数:
            remove_message_ids: 待删除消息 ID 列表（Message_xxx 或内部 message_id）
            fold_message_ids: 待折叠消息 ID 列表（保留消息与 tool_call 链，仅替换正文为折叠占位）
            reason: 裁切依据说明（Markdown 纯文本）

        返回:
            Markdown 纯文本确认信息。
        """
        if not self._message_manager:
            return "[错误] MessageManager 未初始化，无法提交压缩裁切清单。"

        payload = self._message_manager.mark_compression_projection(
            remove_message_ids=remove_message_ids,
            fold_message_ids=fold_message_ids,
            reason=reason,
        )
        accepted_remove = payload.get("accepted_remove_message_ids") or []
        accepted_remove = [str(mid) for mid in accepted_remove if str(mid or "").strip()]
        accepted_fold = payload.get("accepted_fold_message_ids") or []
        accepted_fold = [str(mid) for mid in accepted_fold if str(mid or "").strip()]
        reason_text = str(payload.get("reason") or "").strip()

        lines = [
            "## Compression Projection Marked",
            f"- remove_message_ids_count: {len(accepted_remove)}",
            f"- fold_message_ids_count: {len(accepted_fold)}",
            f"- reason: {reason_text or '无'}",
        ]
        if accepted_remove:
            lines.append("- remove_message_ids:")
            lines.extend([f"  - `{mid}`" for mid in accepted_remove])
        else:
            lines.append("- remove_message_ids: 无")
        if accepted_fold:
            lines.append("- fold_message_ids:")
            lines.extend([f"  - `{mid}`" for mid in accepted_fold])
        else:
            lines.append("- fold_message_ids: 无")
        lines.append("- 说明: 将在下一轮上下文压缩前应用该裁切清单（删除为精确删除；折叠会保留消息链路并替换为占位文本）。")
        return "\n".join(lines)

    async def delegate_task(
            self,
            agent_type: str,
            query: str,
            context: Optional[str] = None,
            function_identifier: Optional[str] = None,
            max_depth: int = 10,
            max_iterations: int = 15,
    ) -> Any:
        """委托任务给专门的 Agent 执行。
        
        这是一个统一的 Agent 调度接口，类似 Claude 的 task 工具。
        根据 agent_type 自动创建并调用相应的 Agent，返回markdown格式的文本结果。
        
        参数:
            agent_type: Agent 类型，可选值：
                - "code_explorer": 代码探索 Agent（搜索、读取、语义分析）
                - "vuln_analysis": 漏洞挖掘 Agent（深度漏洞分析）
            
            query: 任务描述（自然语言）
                - 对于 code_explorer: "找到所有处理用户输入的函数"
                - 对于 vuln_analysis: "挖掘 parse_request 函数中的漏洞"
            
            context: 可选的上下文信息
                - 约束、背景知识等
                - 建议包含“上下文摘要”三部分：参数级入参约束 / 全局变量约束 / 证据锚点
                - 规划阶段仅提供函数事实与约束，不做漏洞判定
            
            function_identifier: 函数唯一标识符（仅 vuln_analysis 使用）
                - 如果提供，直接使用此标识符，不从 query 中提取
                - 格式示例: "PasswordProvider.query", "parse_request", "com.example.MyClass.method"
                - 推荐：先使用 search_symbol 或 query_code 获取准确的函数标识符，再传入此参数
            
            max_depth: 最大分析深度（仅 vuln_analysis 使用）
            max_iterations: 最大迭代次数
        
        返回: markdown 格式文本；若输出超长，返回 {"content": "...", "summary": "..."}。
        """
        if not self.engine:
            # Best-effort lazy initialization when pending engine config is available.
            if not self._initialized:
                try:
                    initialized = await self.initialize()
                except Exception as e:
                    return f"[错误] 引擎初始化失败: {str(e)}"
                if initialized and self.engine:
                    pass
                else:
                    return "[错误] 引擎未初始化，请先调用 initialize()（并提供 engine_type/target_path）"
            else:
                return "[错误] 引擎未初始化，请先调用 initialize()"

        if not self.llm_client:
            return "[错误] LLM 客户端不可用"

        try:
            if agent_type == "code_explorer":
                # 创建 CodeExplorerAgent
                from ..agents.code_explorer_agent import CodeExplorerAgent

                agent = CodeExplorerAgent(
                    engine=self.engine,
                    llm_client=self.llm_client,
                    max_iterations=max_iterations,
                    enable_logging=True,
                    session_id=getattr(self, 'session_id', None),
                )

                result = await agent.explore(
                    query=query,
                    context=context
                )

                if isinstance(result, dict):
                    error = (result.get("error") or "").strip()
                    if error:
                        return error
                    output = result.get("output", "") or ""
                    summary = (result.get("summary") or "").strip()
                    if summary:
                        return {"content": output, "summary": summary}
                    return await self._maybe_pack_tool_output("delegate_task", output)

                return await self._maybe_pack_tool_output("delegate_task", result or "")

            elif agent_type == "vuln_analysis":
                # function_identifier 是必需的
                target_function_id = function_identifier
                if not target_function_id:
                    return """[错误] 必须提供 function_identifier 参数

请按以下步骤操作：
1. 使用 search_symbol 或其他工具查找目标函数
2. 从结果中提取标准格式的函数标识符
3. 再次调用 delegate_task 并传递 function_identifier

示例：
  search_symbol(pattern="PasswordProvider")
  # 从结果中获取: com.example.auth.PasswordProvider.query
  delegate_task(
      agent_type="vuln_analysis",
      query="挖掘该函数中的漏洞",
      function_identifier="com.example.auth.PasswordProvider.query",
      context="参数与边界约束来自上游探索结果"
  )
"""

                # 构建上下文摘要
                analysis_context = context if context else query

                # 创建 DeepVulnAgent
                from ..agents.deep_vuln_agent import DeepVulnAgent
                from ..agents.prompts import get_vuln_agent_system_prompt
                from ..models.constraints import FunctionContext, Precondition

                base_prompt = get_vuln_agent_system_prompt(self.engine_name or "ida")

                agent = DeepVulnAgent(
                    engine=self.engine,
                    llm_client=self.llm_client,
                    max_iterations=max_iterations,
                    max_depth=max_depth,
                    verbose=self.verbose,
                    system_prompt=base_prompt,
                    progress_logger=self._build_progress_logger(target_function_id),
                )

                agent_id = str(uuid.uuid4())[:8]
                self.agents[agent_id] = AgentInstance(
                    agent_id=agent_id,
                    agent_type="DeepVulnAgent",
                    engine_name=self.engine_name or "unknown",
                    analysis_focus=target_function_id,
                    instance=agent,
                )
                self._last_agent_id = agent_id

                # 执行分析
                precondition_text = (analysis_context or "").strip()
                if self.workflow_context and self.workflow_context.background_knowledge:
                    if precondition_text:
                        precondition_text = f"{precondition_text}\n\n### 背景知识\n{self.workflow_context.background_knowledge}"
                    else:
                        precondition_text = f"### 背景知识\n{self.workflow_context.background_knowledge}"
                precondition = None
                if precondition_text:
                    precondition = Precondition.from_text(
                        name="analysis_context",
                        text_content=precondition_text,
                        description="analysis context",
                        target="vuln_analysis",
                    )
                function_context = FunctionContext(
                    function_identifier=target_function_id,
                    precondition=precondition,
                )

                result = await agent.run(function_identifier=target_function_id, context=function_context)
                
                # 格式化结果为markdown文本
                formatted = self._format_vuln_result(result, target_function_id, agent_id)
                return await self._maybe_pack_tool_output("delegate_task", formatted)

            else:
                return f"[错误] 不支持的 Agent 类型: {agent_type}，支持的类型: code_explorer, vuln_analysis"

        except Exception as e:
            return f"[错误] Agent 执行失败: {str(e)}"

    async def delegate_code_explorer(
            self,
            query: str,
            context: Optional[str] = None,
            max_iterations: int = 15,
    ) -> Any:
        """受限委托：仅允许调用 code_explorer 执行探索与取证。

        说明：
            - 该工具固定委托给 `code_explorer`，不允许指定其他 agent_type；
            - 适用于执行阶段遇阻时补充事实证据；
            - 返回保持为 Markdown 纯文本（必要时由摘要包装器返回 content/summary）。

        参数:
            query: 探索任务描述（自然语言）
            context: 可选补充上下文（建议基于已获得证据）
            max_iterations: 最大迭代次数

        返回:
            code_explorer 的执行结果
        """
        return await self.delegate_task(
            agent_type="code_explorer",
            query=query,
            context=context,
            max_iterations=max_iterations,
        )
    
    def _log(self, message: str, level: str = "info"):
        """打印日志"""
        if not self.verbose:
            return
        self._logger.log(level=level, event="tools.event", message=message)

    def _build_progress_logger(self, function_identifier: str):
        """构建 DeepVulnAgent 进度日志回调。"""
        def _progress_logger(message: str, level: str = "info", kind: str = "trace", **extra_fields: Any):
            if not self.verbose:
                return
            self._logger.log(
                level=level,
                event="tools.agent_progress",
                message=message,
                kind=kind,
                function=function_identifier,
                **extra_fields,
            )

        return _progress_logger

    def _format_vuln_result(
            self,
            result: Dict[str, Any],
            function_identifier: str,
            agent_id: str
    ) -> str:
        """格式化漏洞分析结果为markdown文本"""
        vulns = result.get("vulnerabilities", [])

        all_vulns = []
        for v in vulns:
            vuln_info = VulnerabilityInfo(
                name=getattr(v, 'name', 'Unknown'),
                vuln_type=getattr(v, 'type', 'UNKNOWN'),
                description=getattr(v, 'description', ''),
                location=getattr(v, 'location', ''),
                severity=getattr(v, 'severity', 0.5),
                confidence=getattr(v, 'confidence', 0.5),
            )
            self.vulnerabilities.append(vuln_info)
            all_vulns.append(vuln_info)

        # 格式化为markdown文本
        lines = [
            "# 漏洞分析结果",
            "",
            f"**目标函数**: {function_identifier}",
            f"**Agent ID**: {agent_id}",
            "",
            f"## 分析摘要",
            "",
            f"- 本次发现漏洞: {len(all_vulns)} 个",
            f"- 累计漏洞总数: {len(self.vulnerabilities)} 个",
            "",
        ]

        if all_vulns:
            lines.append("## 漏洞详情")
            lines.append("")
            for i, v in enumerate(all_vulns, 1):
                lines.append(f"### 漏洞 #{i}: {v.name}")
                lines.append("")
                lines.append(f"- **类型**: {v.vuln_type}")
                lines.append(f"- **位置**: {v.location}")
                lines.append(f"- **严重度**: {v.severity:.2f}")
                lines.append(f"- **置信度**: {v.confidence:.2f}")
                lines.append(f"- **描述**: {v.description}")
                lines.append("")
        else:
            lines.append("## 分析结果")
            lines.append("")
            lines.append("本次分析未发现漏洞。")
            lines.append("")

        return "\n".join(lines)

    async def run_vuln_analysis(

            self,
            function_identifier: str,
            analysis_context: str,
            max_depth: int = 10,
    ) -> str:
        """创建漏洞分析 Agent 并执行单一函数的深度漏洞挖掘。

        根据上下文约束，创建 Specialized 漏洞分析 Agent，
        对指定的函数开展深度漏洞挖掘。

        参数:
            function_identifier: 待分析的函数标识符（如 "int parse_request(char* buf, size_t len)"）
            analysis_context: 上下文约束描述，应包含：
                - 函数标识符和参数信息
                - 污点参数说明（哪些参数是受外部输入影响的）
                - 外部输入到关键操作的约束与证据锚点
                - 相关组件/模块背景
                - 历史分析经验或前期发现的关键信息
            max_depth: 最大调用深度，默认 10
        """
        # 返回: 格式化的漏洞分析结果文本
        if not function_identifier:
            return "[错误] 必须指定 function_identifier（函数标识符）"

        if not self.engine:
            return "[错误] 引擎未初始化"

        if not self.llm_client:
            return "[错误] LLM 客户端不可用"

        try:
            # 创建 Agent
            base_prompt = get_vuln_agent_system_prompt(self.engine_name or "ida")

            agent = DeepVulnAgent(
                engine=self.engine,
                llm_client=self.llm_client,
                max_iterations=10,
                max_depth=max_depth,
                verbose=self.verbose,
                system_prompt=base_prompt,
                progress_logger=self._build_progress_logger(function_identifier),
            )

            agent_id = str(uuid.uuid4())[:8]
            self.agents[agent_id] = AgentInstance(
                agent_id=agent_id,
                agent_type="DeepVulnAgent",
                engine_name=self.engine_name or "unknown",
                analysis_focus=function_identifier,
                instance=agent,
            )
            self._last_agent_id = agent_id

            # 执行分析
            from ..models.constraints import FunctionContext, Precondition
            precondition_text = (analysis_context or "").strip()
            if self.workflow_context and self.workflow_context.background_knowledge:
                if precondition_text:
                    precondition_text = f"{precondition_text}\n\n### 背景知识\n{self.workflow_context.background_knowledge}"
                else:
                    precondition_text = f"### 背景知识\n{self.workflow_context.background_knowledge}"
            precondition = None
            if precondition_text:
                precondition = Precondition.from_text(
                    name="analysis_context",
                    text_content=precondition_text,
                    description="analysis context",
                    target="vuln_analysis",
                )
            function_context = FunctionContext(
                function_identifier=function_identifier,
                precondition=precondition,
            )
            result = await agent.run(function_identifier=function_identifier, context=function_context)
            vulns = result.get("vulnerabilities", [])

            all_vulns = []
            for v in vulns:
                vuln_info = VulnerabilityInfo(
                    name=getattr(v, 'name', 'Unknown'),
                    vuln_type=getattr(v, 'type', 'UNKNOWN'),
                    description=getattr(v, 'description', ''),
                    location=getattr(v, 'location', ''),
                    severity=getattr(v, 'severity', 0.5),
                    confidence=getattr(v, 'confidence', 0.5),
                )
                self.vulnerabilities.append(vuln_info)
                all_vulns.append(vuln_info)

            # 格式化为易读的文本
            lines = [
                f"=== 漏洞分析结果 ===",
                f"",
                f"目标函数: {function_identifier}",
                f"Agent ID: {agent_id}",
                f"",
                f"【本次发现漏洞】: {len(all_vulns)} 个",
                f"【累计漏洞总数】: {len(self.vulnerabilities)} 个",
                f"",
            ]

            if all_vulns:
                lines.append("【漏洞详情】")
                for i, v in enumerate(all_vulns, 1):
                    lines.append(f"\n--- 漏洞 #{i} ---")
                    lines.append(f"  名称: {v.name}")
                    lines.append(f"  类型: {v.vuln_type}")
                    lines.append(f"  位置: {v.location}")
                    lines.append(f"  严重度: {v.severity:.2f}")
                    lines.append(f"  置信度: {v.confidence:.2f}")
                    lines.append(f"  描述: {v.description}")
            else:
                lines.append("【结果】本次分析未发现漏洞。")

            return "\n".join(lines)

        except Exception as e:
            return f"[错误] 漏洞分析执行失败: {str(e)}"

    # ==================== 简化的 Tool 接口（新设计）====================


    async def plan_tasks(self, workflows: Optional[List[Dict[str, Any]]] = None) -> str:
        """规划任务列表，支持单/多 workflow 模式。

        每个 workflow 字典应包含: tasks (必需的任务列表), workflow_id (可选标识符),
        workflow_name (可选名称), workflow_description (可选描述),
        execution_mode (可选，sequential 或 parallel)。
        
        tasks 必须为字典对象，字段包括 description / agent_type / function_identifier / analysis_context
          - agent_type 必须显式提供（code_explorer / vuln_analysis）
          - agent_type 为 vuln_analysis 时必须提供 function_identifier
          - function_identifier 必须来自 search_symbol 的验证结果，保持原样
          - function_identifier 必须是单个字符串，不允许列表/拼接；多函数分析需拆分任务
          - analysis_context 为漏洞挖掘前置信息（Markdown 纯文本）
          - analysis_context 必须包含固定章节：目标函数 / 入参约束 / 全局变量约束 / 证据锚点
          - `入参约束` 需要按参数逐条给出来源/可控性/污点/边界/校验/证据

        Args:
            workflows: Workflow 配置列表，缺失时返回可恢复错误提示

        Returns:
            规划结果摘要（Markdown 格式）
        """
        try:
            if not workflows:
                return (
                    "[错误] 缺少 workflows 参数，请调用 plan_tasks(workflows) 并提供规划内容。\n"
                    "示例：\n"
                    "```\n"
                    "{\n"
                    "  \"workflows\": [\n"
                    "    {\n"
                    "      \"workflow_id\": \"analysis_1\",\n"
                    "      \"workflow_name\": \"RPC 处理链分析\",\n"
                    "      \"tasks\": [\n"
                    "        {\n"
                    "          \"description\": \"定位用户输入到数据库查询的路径\",\n"
                    "          \"agent_type\": \"code_explorer\"\n"
                    "        }\n"
                    "      ]\n"
                    "    }\n"
                    "  ]\n"
                    "}\n"
                    "```\n"
                )
            # 1. 校验与标准化（含 function_identifier 校验）
            normalized_workflows, error, verified = await self._validate_and_normalize_workflows(
                workflows,
                verify_function_identifier=True,
            )
            if error:
                return error

            # 2. 标准化 workflow 信息
            normalized = self._normalize_workflows(normalized_workflows)

            # 3. 保存规划状态（关键！）
            self._planned_workflows = normalized
            self._is_multi_workflow = True

            # 4. 创建任务列表（多 workflow 展开为统一任务序列）
            if not self._task_list_manager:
                return "[错误] TaskListManager 未初始化。请先初始化 Orchestrator。"
            if not self.artifact_store:
                return "[错误] ArtifactStore 未初始化。请先初始化 Orchestrator。"

            flat_tasks = self._flatten_workflow_tasks(normalized)
            self._externalize_analysis_context(flat_tasks, start_index=1)
            self._clear_recovery_lock()
            self._verified_function_identifiers = {}
            create_stats = self._task_list_manager.create_tasks(flat_tasks)

            # 5. 返回多 workflow 摘要
            summary = self._format_multi_workflow_summary(normalized)
            added = int((create_stats or {}).get("added", len(flat_tasks)))
            skipped = int((create_stats or {}).get("skipped_duplicates", 0))
            return "\n".join([
                summary,
                "",
                "## 入队统计",
                "",
                f"- 新增任务: {added}",
                f"- 跳过重复: {skipped}",
            ])

        except Exception as e:
            return f"[错误] 规划任务失败: {str(e)}"

    async def append_tasks(self, workflows: Optional[List[Dict[str, Any]]] = None) -> str:
        """追加任务列表到现有任务看板。

        Args:
            workflows: Workflow 配置列表（结构与 plan_tasks 一致）

        Returns:
            追加结果摘要（Markdown 格式）
        """
        try:
            if not workflows:
                return (
                    "[错误] 缺少 workflows 参数，请调用 append_tasks(workflows) 并提供追加内容。\n"
                    "提示：workflows 结构与 plan_tasks 保持一致。"
                )
            if not self._planned_workflows:
                return "[错误] 尚未存在基础任务列表，请先调用 plan_tasks(workflows)。"

            normalized_workflows, error, verified = await self._validate_and_normalize_workflows(
                workflows,
                verify_function_identifier=True,
            )
            if error:
                return error

            normalized = self._normalize_workflows(normalized_workflows)

            # 追加到已规划的 workflows
            merged = list(self._planned_workflows)
            for wf in normalized:
                existing = next((x for x in merged if x.get("workflow_id") == wf.get("workflow_id")), None)
                if existing:
                    existing["tasks"].extend(wf.get("tasks", []))
                else:
                    merged.append(wf)

            self._planned_workflows = merged

            if not self._task_list_manager:
                return "[错误] TaskListManager 未初始化。请先初始化 Orchestrator。"
            if not self.artifact_store:
                return "[错误] ArtifactStore 未初始化。请先初始化 Orchestrator。"

            flat_tasks = self._flatten_workflow_tasks(normalized)
            start_index = self._get_next_task_index()
            self._externalize_analysis_context(flat_tasks, start_index=start_index)
            append_stats = self._task_list_manager.append_tasks(flat_tasks)
            total_added = int((append_stats or {}).get("added", 0))
            skipped = int((append_stats or {}).get("skipped_duplicates", 0))
            content = "\n".join([
                "# 任务追加完成",
                "",
                f"**追加任务数**: {total_added}",
                f"**跳过重复**: {skipped}",
                "",
                "✅ 任务已按幂等语义追加到统一任务看板。",
            ])
            return {
                "content": content,
                "summary": f"append_tasks: added={total_added}, skipped_duplicates={skipped}",
                "meta": {
                    "added_tasks": total_added,
                    "skipped_duplicates": skipped,
                    "deduplicated": True,
                },
            }
        except Exception as e:
            return f"[错误] 追加任务失败: {str(e)}"


    async def resolve_function_identifier(self, task_id: str, query_hint: str = "") -> str:
        """
        通过 search_symbol 为指定任务解析可用的 function_identifier。

        Args:
            task_id: 任务 ID（如 task_2）
            query_hint: 可选的查询提示；为空时回退到任务 description

        Returns:
            Markdown 结果，包含候选列表与推荐标识符
        """
        try:
            if not self._task_list_manager:
                return "[错误] TaskListManager 未初始化。"
            if not self.engine:
                return "[错误] 引擎未初始化，无法调用 search_symbol。"

            if self._recovery_lock_task_id and task_id != self._recovery_lock_task_id:
                locked_task = self._task_list_manager.get_task(self._recovery_lock_task_id)
                description = locked_task.description if locked_task else ""
                task_group = locked_task.task_group if locked_task else None
                return self._format_recovery_lock_error(self._recovery_lock_task_id, description, task_group=task_group)

            task = self._task_list_manager.get_task(task_id)
            if not task:
                return f"[错误] 任务不存在: {task_id}"

            query = (query_hint or task.description or "").strip()
            if not query:
                return f"[错误] 缺少查询条件，无法为任务 {task_id} 解析 function_identifier。"

            options = SearchOptions(limit=20)
            results = await self.engine.search_symbol(query=query, options=options)

            candidate_rows = []
            function_identifiers: List[str] = []
            for item in results or []:
                function_identifier = (getattr(item, "identifier", "") or "").strip()
                symbol_type = str(getattr(getattr(item, "symbol_type", None), "value", getattr(item, "symbol_type", "unknown")))
                if symbol_type not in {"function", "method", "unknown"}:
                    continue
                if not function_identifier:
                    continue
                function_identifiers.append(function_identifier)
                candidate_rows.append({
                    "function_identifier": function_identifier,
                    "name": getattr(item, "name", ""),
                    "type": symbol_type,
                    "file_path": getattr(item, "file_path", "") or "",
                    "line": getattr(item, "line", 0),
                    "score": getattr(item, "match_score", 0.0),
                })

            dedup_function_identifiers = list(dict.fromkeys(function_identifiers))
            self._verified_function_identifiers[task_id] = set(dedup_function_identifiers)

            if not dedup_function_identifiers:
                return (
                    f"[错误] 未通过 search_symbol 找到可用函数标识符（task_id={task_id}, query={query}）。\n"
                    "请调整 query_hint 后重试 resolve_function_identifier。"
                )

            recommended = dedup_function_identifiers[0]
            lines = [
                "# function_identifier 解析结果",
                "",
                f"- 任务: `{task_id}`",
                f"- 查询: `{query}`",
                f"- 候选数量: {len(dedup_function_identifiers)}",
                f"- 推荐: `{recommended}`",
                "",
                "## 候选列表（来自 search_symbol）",
                "",
            ]
            for idx, row in enumerate(candidate_rows[:10], 1):
                lines.extend([
                    f"{idx}. `{row['function_identifier']}`",
                    f"   - type: {row['type']}, score: {row['score']}",
                    f"   - location: {row['file_path']}:{row['line']}",
                ])

            lines.extend([
                "",
                "## 下一步",
                "",
                "调用 `set_task_function_identifier` 写回任务参数，然后重试执行工具。",
                f"示例: set_task_function_identifier(task_id=\"{task_id}\", function_identifier=\"{recommended}\", source=\"search_symbol\")",
            ])
            content = "\n".join(lines)
            return await self._maybe_pack_tool_output("read_task_output", content)
        except Exception as e:
            return f"[错误] resolve_function_identifier 失败: {str(e)}"

    async def set_task_function_identifier(
        self,
        task_id: str,
        function_identifier: str,
        source: str = "search_symbol",
    ) -> str:
        """
        为任务写入 function_identifier，并要求来源可追溯到 search_symbol。

        Args:
            task_id: 任务 ID
            function_identifier: 函数标识符
            source: 标识符来源，默认必须为 search_symbol

        Returns:
            写回结果（Markdown 文本）
        """
        try:
            if not self._task_list_manager:
                return "[错误] TaskListManager 未初始化。"
            if source != "search_symbol":
                return "[错误] source 必须是 search_symbol。"

            if self._recovery_lock_task_id and task_id != self._recovery_lock_task_id:
                locked_task = self._task_list_manager.get_task(self._recovery_lock_task_id)
                description = locked_task.description if locked_task else ""
                task_group = locked_task.task_group if locked_task else None
                return self._format_recovery_lock_error(self._recovery_lock_task_id, description, task_group=task_group)

            task = self._task_list_manager.get_task(task_id)
            if not task:
                return f"[错误] 任务不存在: {task_id}"

            normalized = (function_identifier or "").strip()
            if not normalized:
                return "[错误] function_identifier 不能为空。"

            verified = normalized in self._verified_function_identifiers.get(task_id, set())
            if not verified:
                verified = await self._is_function_identifier_verified_by_search_symbol(normalized)

            if not verified:
                return (
                    f"[错误] function_identifier 未通过 search_symbol 验证: `{normalized}`。\n"
                    "请先调用 resolve_function_identifier，或使用其返回的候选标识符。"
                )

            self._task_list_manager.set_task_function_identifier(task_id=task_id, function_identifier=normalized)
            self._clear_recovery_lock(task_id)

            return "\n".join([
                "# 任务参数已更新",
                "",
                f"- task_id: `{task_id}`",
                f"- function_identifier: `{normalized}`",
                "- source: `search_symbol`",
                "",
                "可直接重试 `execute_task`。",
                "若执行提示上下文不足，再按需调用 `compose_task_context`。",
            ])
        except Exception as e:
            return f"[错误] set_task_function_identifier 失败: {str(e)}"

    async def list_runnable_tasks(
        self,
        task_group: Optional[str] = None,
        agent_type: Optional[str] = None,
    ) -> Any:
        """
        列出当前可执行任务及阻塞原因（Markdown 纯文本）。
        """
        try:
            if not self._task_list_manager:
                return "[错误] TaskListManager 未初始化。"

            items = self._task_list_manager.list_tasks_with_runnable(
                task_group=task_group,
                agent_type=agent_type,
            )
            if not items:
                group_info = f"(task_group={task_group})" if task_group else ""
                return f"# Runnable 任务列表\n\n（无任务{group_info}）"

            runnable_count = sum(1 for item in items if item.get("runnable"))
            blocked_count = len(items) - runnable_count

            lines = [
                "# Runnable 任务列表",
                "",
                f"- task_group: `{task_group}`" if task_group else "- task_group: `<default>`",
                f"- agent_type_filter: `{agent_type}`" if agent_type else "- agent_type_filter: `<none>`",
                f"- runnable: {runnable_count}",
                f"- blocked: {blocked_count}",
                "",
                "## 任务明细",
                "",
            ]

            for idx, item in enumerate(items, 1):
                task = item["task"]
                runnable = bool(item.get("runnable"))
                reason = str(item.get("reason") or "")
                state = str(getattr(getattr(task, "status", None), "value", getattr(task, "status", "")))
                prefix = "✅" if runnable else "⛔"
                lines.extend(
                    [
                        f"{idx}. {prefix} `{task.id}` ({task.agent_type or 'unknown'})",
                        f"   - status: {state}",
                        f"   - description: {task.description}",
                        f"   - reason: {reason}",
                        f"   - function_identifier: `{(task.function_identifier or '').strip() or 'N/A'}`",
                    ]
                )
            return await self._maybe_pack_tool_output("list_runnable_tasks", "\n".join(lines))
        except Exception as e:
            return f"[错误] list_runnable_tasks 失败: {str(e)}"

    async def compose_task_context(
        self,
        analysis_target: str = "",
        task_id: str = "",
        artifact_refs: Optional[List[str]] = None,
        conversation_context: str = "",
        extra_context: str = "",
        required_sections: Optional[List[str]] = None,
        mode: str = "minimal",
        task_group: Optional[str] = None,
        store_artifact: bool = True,
    ) -> Any:
        """
        组装任务上下文（通用工具）。

        输入可来自：任务目标、artifact 引用、会话背景文本、补充上下文。
        输出 Markdown 纯文本上下文，并返回推荐 selected_file_ids。
        """
        try:
            if not self._task_list_manager:
                return "[错误] TaskListManager 未初始化。"
            if not self.artifact_store:
                return "[错误] ArtifactStore 未初始化。"

            mode_value = (mode or "minimal").strip().lower()
            if mode_value not in {"minimal", "full"}:
                return "[错误] mode 仅支持 minimal/full。"

            task = None
            task_desc = ""
            task_context = ""
            resolved_group = task_group
            if task_id:
                task = self._task_list_manager.get_task(task_id)
                if not task:
                    return f"[错误] 任务不存在: {task_id}"
                if task_group and (task.task_group or "") != task_group:
                    return (
                        f"[错误] task_group 不匹配: task_id={task_id}, "
                        f"task.task_group={task.task_group or ''}, provided={task_group}"
                    )
                resolved_group = task.task_group or task_group
                task_desc = task.description or ""
                task_context = self._resolve_task_analysis_context(task).strip()

            final_target = (analysis_target or "").strip() or task_desc
            if not final_target:
                return "[错误] analysis_target 不能为空（或提供 task_id 以回退任务描述）。"

            artifact_refs = artifact_refs or []
            resolved_artifacts, unresolved_artifacts = self._resolve_artifact_refs(artifact_refs)

            candidate_files: List[str] = []
            if task_id:
                candidate_files = self._get_previous_task_outputs(task_id, task_group=resolved_group)

            candidate_blocks: List[str] = []
            candidate_ids: List[str] = []
            for idx, file_id in enumerate(candidate_files, 1):
                candidate_ids.append(file_id)
                summary_text = ""
                meta = self.artifact_store.read_metadata(file_id)
                summary_text = str(meta.get("summary") or "").strip()
                if not summary_text:
                    raw_text = self.artifact_store.read(file_id)
                    summary_text = raw_text
                    if len(raw_text) > 3000 and self.summary_service:
                        generated = await self.summary_service.summarize_message_large(
                            content=raw_text,
                            metadata={"tool_name": "compose_task_context"},
                            agent_type="context_composer",
                            target_function=final_target,
                            session_id=self._session_id,
                        )
                        if generated:
                            summary_text = generated
                candidate_blocks.append(
                    "\n".join(
                        [
                            f"### 候选 {idx}: `{file_id}`",
                            f"- artifact_ref: `{file_id}`",
                            f"- kind: {meta.get('kind', 'unknown')}",
                            "- 摘要:",
                            summary_text or "（无）",
                            "",
                        ]
                    )
                )

            artifact_blocks: List[str] = []
            for idx, item in enumerate(resolved_artifacts, 1):
                artifact_blocks.append(
                    "\n".join(
                        [
                            f"### 引用 {idx}: `{item['ref']}`",
                            f"- source: {item['source']}",
                            f"- id: {item['id']}",
                            "- 内容:",
                            item["content"] or "（无）",
                            "",
                        ]
                    )
                )

            required_sections = required_sections or [
                "分析目标",
                "任务相关背景事实",
                "前置约束",
                "证据锚点",
                "缺失信息",
                "推荐输入文件（selected_file_ids）",
            ]

            def finish_compose_task_context(
                context_markdown: str,
                selected_file_ids: List[str],
                missing_info: str = "",
            ):
                """
                Return composed task context in Markdown plain text.

                Args:
                    context_markdown: 任务上下文 Markdown 纯文本
                    selected_file_ids: 推荐注入的 artifact_ref 列表
                    missing_info: 缺失信息简述
                """
                pass

            default_context_lines = [
                "## 分析目标",
                final_target,
                "",
                "## 任务相关背景事实",
                conversation_context.strip() or "无",
                "",
                "## 前置约束",
                task_context or "无",
                "",
                "## 证据锚点（含 artifact 引用）",
                "无",
                "",
                "## 缺失信息",
                "无",
                "",
                "## 推荐输入文件（selected_file_ids）",
                "- (none)",
            ]
            fallback_context = "\n".join(default_context_lines)
            selected_ids: List[str] = []
            missing_info = ""

            if self.llm_client:
                system_prompt = (
                    "你是任务上下文组装器。"
                    "你的目标是围绕 analysis_target 生成“最小但充分”的任务上下文。"
                    "必须基于输入事实，禁止编造。"
                    "输出必须是 Markdown 纯文本。"
                    "selected_file_ids 只能从候选 artifact_ref 中选择。"
                    "必须调用 finish_compose_task_context 工具返回。"
                )
                user_prompt = (
                    "请生成任务上下文。\n\n"
                    "## analysis_target\n"
                    f"{final_target}\n\n"
                    "## task_id\n"
                    f"{task_id or 'N/A'}\n\n"
                    "## task_group\n"
                    f"{resolved_group or 'N/A'}\n\n"
                    "## mode\n"
                    f"{mode_value}\n\n"
                    "## required_sections\n"
                    + "\n".join(f"- {s}" for s in required_sections)
                    + "\n\n## task.analysis_context\n"
                    + (task_context or "无")
                    + "\n\n## conversation_context\n"
                    + (conversation_context.strip() or "无")
                    + "\n\n## extra_context\n"
                    + (extra_context.strip() or "无")
                    + "\n\n## 引用 artifact 内容\n"
                    + ("\n".join(artifact_blocks) if artifact_blocks else "无")
                    + "\n\n## 候选输入文件摘要\n"
                    + ("\n".join(candidate_blocks) if candidate_blocks else "无")
                    + "\n\n约束：\n"
                    "- 输出 context_markdown 必须包含 required_sections。\n"
                    "- selected_file_ids 仅允许候选 artifact_ref。\n"
                    "- 若证据不足，missing_info 写明缺口。\n"
                )
                try:
                    session_tag = self._session_id or "default"
                    tool_client = ToolBasedLLMClient(
                        llm=self.llm_client,
                        max_retries=2,
                        retry_delay=1.0,
                        verbose=False,
                        enable_logging=True,
                        session_id=self._session_id,
                        agent_id=f"context_composer_{session_tag}",
                        log_metadata={
                            "agent_type": "context_composer",
                            "target_function": final_target,
                        },
                    )
                    result = await tool_client.atool_call(
                        messages=[HumanMessage(content=user_prompt)],
                        tools=[finish_compose_task_context],
                        system_prompt=system_prompt,
                    )
                    if result and result.tool_calls:
                        args = result.tool_calls[0].get("args", {}) or {}
                        context_markdown = str(args.get("context_markdown") or "").strip()
                        raw_ids = args.get("selected_file_ids") or []
                        missing_info = str(args.get("missing_info") or "").strip()
                        allowed_id_set = set(candidate_ids)
                        selected_ids = [
                            str(fid).strip()
                            for fid in raw_ids
                            if str(fid).strip() and str(fid).strip() in allowed_id_set
                        ]
                        selected_ids = list(dict.fromkeys(selected_ids))
                        if context_markdown:
                            fallback_context = context_markdown
                except Exception:
                    pass

            context_body = fallback_context
            if missing_info and "## 缺失信息" not in context_body:
                context_body = "\n\n".join(
                    [
                        context_body,
                        "## 缺失信息",
                        missing_info,
                    ]
                )

            context_ref = ""
            if store_artifact:
                artifact = self.artifact_store.put_text(
                    content=context_body,
                    kind="task_context",
                    summary=self._build_artifact_summary(context_body),
                    task_id=task_id,
                    workflow_id=str(resolved_group or ""),
                    producer="compose_task_context",
                    metadata={
                        "kind": "task_context",
                        "task_id": task_id,
                        "task_group": str(resolved_group or ""),
                        "analysis_target": final_target,
                    },
                )
                context_ref = artifact.artifact_id
                if task_id and self._task_list_manager:
                    self._task_list_manager.set_task_artifact(task_id, "context", context_ref)

            lines = [
                "# Task Context Compose Result",
                "",
                f"- task_id: `{task_id or 'N/A'}`",
                f"- task_group: `{resolved_group or 'N/A'}`",
                f"- mode: `{mode_value}`",
                f"- context_ref: `{context_ref or 'N/A'}`",
                f"- selected_file_ids: {', '.join(selected_ids) if selected_ids else '(none)'}",
            ]
            if unresolved_artifacts:
                lines.append(f"- unresolved_artifact_refs: {', '.join(unresolved_artifacts)}")
            lines.extend(
                [
                    "",
                    "## Context Markdown",
                    "",
                    context_body,
                ]
            )
            return await self._maybe_pack_tool_output("compose_task_context", "\n".join(lines))
        except Exception as e:
            return f"[错误] compose_task_context 失败: {str(e)}"

    async def execute_task(
        self,
        task_id: str,
        task_group: Optional[str] = None,
        additional_context: str = "",
        selected_file_ids: Optional[List[str]] = None,
        context_ref: str = "",
    ) -> Any:
        """
        执行指定任务（按 task_id 精确执行）。
        """
        try:
            if not self._task_list_manager:
                return "[错误] TaskListManager 未初始化。"
            if not self.artifact_store:
                return "[错误] ArtifactStore 未初始化。"
            delegate_error = self._ensure_agent_delegate()
            if delegate_error:
                return delegate_error

            task = self._task_list_manager.get_task(task_id)
            if not task:
                return f"[错误] 任务不存在: {task_id}"
            if task_group and (task.task_group or "") != task_group:
                return (
                    f"[错误] task_group 不匹配: task_id={task_id}, "
                    f"task.task_group={task.task_group or ''}, provided={task_group}"
                )
            resolved_group = task.task_group or task_group

            if self._recovery_lock_task_id and task_id != self._recovery_lock_task_id:
                locked_task = self._task_list_manager.get_task(self._recovery_lock_task_id)
                description = locked_task.description if locked_task else ""
                task_group_locked = locked_task.task_group if locked_task else None
                return self._format_recovery_lock_error(
                    self._recovery_lock_task_id,
                    description,
                    task_group=task_group_locked,
                )

            task_status = str(getattr(getattr(task, "status", None), "value", getattr(task, "status", "")))
            if task_status != "pending":
                return f"[错误] 任务 {task_id} 当前状态为 {task_status}，仅支持执行 pending 任务。"

            agent_type = (task.agent_type or "").strip()
            if not agent_type:
                return self._format_recoverable_error(
                    error_code="MISSING_AGENT_TYPE",
                    message=f"任务 {task_id} 缺少 agent_type，无法执行。",
                    payload={"task_id": task_id, "task_group": resolved_group or ""},
                )
            if agent_type == "vuln_analysis" and not (task.function_identifier or "").strip():
                self._set_recovery_lock(task_id)
                return self._format_recoverable_error(
                    error_code="MISSING_FUNCTION_IDENTIFIER",
                    message=f"任务 {task_id} 缺少 function_identifier（vuln_analysis 必需）。",
                    payload={
                        "task_id": task_id,
                        "task_group": resolved_group or "",
                        "required_next_actions": [
                            "调用 resolve_function_identifier 获取候选标识符",
                            "调用 set_task_function_identifier 写回后重试 execute_task",
                        ],
                    },
                )
            self._clear_recovery_lock(task_id)

            claimed = self._task_list_manager.claim_task_by_id(
                task_id=task_id,
                claimant=self._claimant_id,
                lease_seconds=1200,
                task_group=resolved_group,
                expected_agent_type=agent_type,
                require_function_identifier=(agent_type == "vuln_analysis"),
            )
            if not claimed:
                return f"[错误] 任务 {task_id} 认领失败（可能已被执行、状态变化或前置条件不满足）。"

            input_override, unresolved_ids = self._resolve_selected_input_files(
                current_task_id=task_id,
                task_group=resolved_group,
                selected_file_ids=selected_file_ids,
            )

            merged_context = self._merge_task_context(
                task=claimed,
                additional_context=additional_context,
                context_ref=context_ref,
            )

            task_obj, result, output_ref = await self._execute_single_task(
                task=claimed,
                agent_type=agent_type,
                additional_context=merged_context,
                input_files_override=input_override,
                task_group=resolved_group,
            )
            base = self._format_execution_result(
                task=task_obj,
                result=result,
                output_ref=output_ref,
                task_group=resolved_group,
            )
            lines = [
                "# Execute Task",
                "",
                f"- task_id: `{task_id}`",
                f"- task_group: `{resolved_group or 'N/A'}`",
                f"- agent_type: `{agent_type}`",
                f"- context_ref: `{context_ref or 'N/A'}`",
                f"- selected_file_ids: {', '.join(selected_file_ids or []) if (selected_file_ids or []) else '(none)'}",
            ]
            if unresolved_ids:
                lines.append(f"- unresolved_selected_file_ids: {', '.join(unresolved_ids)}")
            lines.extend(
                [
                    "",
                    base,
                ]
            )
            return await self._maybe_pack_tool_output("execute_task", "\n".join(lines))
        except Exception as e:
            return f"[错误] execute_task 失败: {str(e)}"

    async def execute_tasks(
        self,
        task_ids: List[str],
        task_group: Optional[str] = None,
        additional_context: str = "",
        task_context_map: Optional[Dict[str, str]] = None,
        context_ref_map: Optional[Dict[str, str]] = None,
        task_file_map: Optional[Dict[str, List[str]]] = None,
        parallel: bool = True,
    ) -> Any:
        """
        执行一组指定任务（支持并发）。
        """
        try:
            if not self._task_list_manager:
                return "[错误] TaskListManager 未初始化。"
            if not self.artifact_store:
                return "[错误] ArtifactStore 未初始化。"
            delegate_error = self._ensure_agent_delegate()
            if delegate_error:
                return delegate_error

            ordered_ids: List[str] = []
            seen: Set[str] = set()
            for task_id in task_ids or []:
                normalized = str(task_id or "").strip()
                if not normalized or normalized in seen:
                    continue
                seen.add(normalized)
                ordered_ids.append(normalized)
            if not ordered_ids:
                return "[错误] task_ids 不能为空。"

            tasks: List[Any] = []
            for task_id in ordered_ids:
                task = self._task_list_manager.get_task(task_id)
                if not task:
                    return f"[错误] 任务不存在: {task_id}"
                if task_group and (task.task_group or "") != task_group:
                    return (
                        f"[错误] task_group 不匹配: task_id={task_id}, "
                        f"task.task_group={task.task_group or ''}, provided={task_group}"
                    )
                tasks.append(task)

            resolved_group = task_group or (tasks[0].task_group if tasks else None)
            agent_types = {(t.agent_type or "").strip() for t in tasks}
            if "" in agent_types:
                missing = next((t.id for t in tasks if not (t.agent_type or "").strip()), "")
                return f"[错误] 任务 {missing} 缺少 agent_type。"
            if len(agent_types) != 1:
                return "[错误] execute_tasks 当前仅支持同一 agent_type 的任务集合。"
            agent_type = next(iter(agent_types))

            for task in tasks:
                status = str(getattr(getattr(task, "status", None), "value", getattr(task, "status", "")))
                if status != "pending":
                    return f"[错误] 任务 {task.id} 当前状态为 {status}，仅支持执行 pending 任务。"
                if agent_type == "vuln_analysis" and not (task.function_identifier or "").strip():
                    self._set_recovery_lock(task.id)
                    return self._format_recoverable_error(
                        error_code="MISSING_FUNCTION_IDENTIFIER",
                        message=f"任务 {task.id} 缺少 function_identifier（vuln_analysis 必需）。",
                        payload={"task_id": task.id, "task_group": resolved_group or ""},
                    )

            claimed_tasks = self._task_list_manager.claim_tasks_by_ids(
                task_ids=ordered_ids,
                claimant=self._claimant_id,
                lease_seconds=1200,
                task_group=resolved_group,
                expected_agent_type=agent_type,
                require_function_identifier=(agent_type == "vuln_analysis"),
                atomic=True,
            )
            if len(claimed_tasks) != len(ordered_ids):
                return "[错误] execute_tasks 认领失败（可能存在状态变化或前置条件不满足）。"

            task_context_map = task_context_map or {}
            context_ref_map = context_ref_map or {}
            task_file_map = task_file_map or {}

            async def _run_one(task: Any):
                specific_context = task_context_map.get(task.id, "")
                merged_extra = "\n\n".join(
                    part for part in [additional_context.strip(), specific_context.strip()] if part
                )
                context_ref = context_ref_map.get(task.id, "")
                merged_context = self._merge_task_context(
                    task=task,
                    additional_context=merged_extra,
                    context_ref=context_ref,
                )
                selected_ids = task_file_map.get(task.id) or []
                input_override, _unresolved = self._resolve_selected_input_files(
                    current_task_id=task.id,
                    task_group=resolved_group,
                    selected_file_ids=selected_ids,
                )
                return await self._execute_single_task(
                    task=task,
                    agent_type=agent_type,
                    additional_context=merged_context,
                    input_files_override=input_override,
                    task_group=resolved_group,
                )

            if parallel:
                semaphore = asyncio.Semaphore(self._max_parallel_tasks(agent_type))

                async def _guarded(task: Any):
                    async with semaphore:
                        return await _run_one(task)

                results = await asyncio.gather(*[_guarded(task) for task in claimed_tasks])
            else:
                results = []
                for task in claimed_tasks:
                    results.append(await _run_one(task))

            base = self._format_batch_execution_result(results, task_group=resolved_group)
            lines = [
                "# Execute Tasks",
                "",
                f"- task_group: `{resolved_group or 'N/A'}`",
                f"- agent_type: `{agent_type}`",
                f"- parallel: `{str(bool(parallel)).lower()}`",
                f"- task_ids: {', '.join(ordered_ids)}",
                "",
                base,
            ]
            return await self._maybe_pack_tool_output("execute_tasks", "\n".join(lines))
        except Exception as e:
            return f"[错误] execute_tasks 失败: {str(e)}"

    async def get_task_status(self, task_group: Optional[str] = None) -> str:
        """获取当前任务列表状态

        读取 tasks.md，返回完整任务列表和统计信息。

        Args:
            task_group: 任务分组标识（可选）

        Returns:
            完整任务列表（Markdown 格式）+ 统计信息
        """
        try:
            # 检查是否已初始化
            if not hasattr(self, '_task_list_manager'):
                return "[错误] TaskListManager 未初始化。请先初始化 Orchestrator。"
            
            # 获取所有任务和统计信息
            all_tasks = self._task_list_manager.get_all_tasks(task_group=task_group)
            stats = self._task_list_manager.get_statistics(task_group=task_group)
            
            if not all_tasks:
                group_info = f"(task_group={task_group})" if task_group else ""
                return f"# 任务列表\n\n（无任务{group_info}）"
            
            # 格式化返回结果
            lines = [
                "# 任务列表",
                "",
            ]
            
            for task in all_tasks:
                lines.append(task.to_markdown_line())
            
            lines.extend([
                "",
                "---",
                "",
                f"**总计**: {stats['total']} 个任务",
                f"**待执行**: {stats['pending']} 个",
                f"**执行中**: {stats['in_progress']} 个",
                f"**已完成**: {stats['completed']} 个",
                f"**失败**: {stats['failed']} 个",
                f"**完成率**: {stats['completion_rate']}%",
            ])
            
            # 如果所有任务已完成，添加祝贺信息
            if self._task_list_manager.is_all_completed(task_group=task_group):
                lines.extend([
                    "",
                    "🎉 **所有任务已完成！**",
                ])
            
            return "\n".join(lines)
        
        except Exception as e:
            return f"[错误] 获取任务状态失败: {str(e)}"

    async def list_artifacts(self) -> str:
        """
        列出当前 ArtifactStore 中的摘要列表（Markdown 纯文本）
        """
        if not self.artifact_store:
            return "[错误] ArtifactStore 未初始化。"

        artifact_ids = self.artifact_store.list_artifacts()
        if not artifact_ids:
            return "当前没有可用的 artifacts。"

        lines = [
            "# Artifact 摘要列表",
            "",
            f"- 总数: {len(artifact_ids)}",
            "",
        ]
        for idx, artifact_id in enumerate(artifact_ids, 1):
            meta = self.artifact_store.read_metadata(artifact_id)
            summary = (meta.get("summary") or "").strip()
            size = meta.get("size", 0)
            created_at = meta.get("created_at", 0)
            lines.append(f"{idx}. `{artifact_id}`")
            lines.append(f"   - size: {size}")
            lines.append(f"   - created_at: {created_at}")
            if summary:
                lines.append(f"   - summary: {summary}")
            lines.append("")

        return "\n".join(lines)

    async def write_artifact_entry(
        self,
        kind: str,
        content: str,
        task_id: str = "",
        task_group: str = "",
        slot: str = "",
        summary: str = "",
    ) -> str:
        """
        写入统一 Artifact Ledger，可选绑定到任务槽位。

        Args:
            kind: Artifact 类型（如 evidence_bundle / task_context / task_note）
            content: 正文内容（Markdown 纯文本）
            task_id: 可选任务 ID
            task_group: 可选 task_group/workflow_id
            slot: 可选任务槽位（如 context/output/evidence）
            summary: 可选摘要，缺省时自动截断生成
        """
        if not self.artifact_store:
            return "[错误] ArtifactStore 未初始化。"
        normalized_kind = (kind or "").strip()
        if not normalized_kind:
            return "[错误] kind 不能为空。"
        text = str(content or "")
        if not text.strip():
            return "[错误] content 不能为空。"
        final_summary = (summary or "").strip() or self._build_artifact_summary(text)
        ref = self.artifact_store.put_text(
            content=text,
            kind=normalized_kind,
            summary=final_summary,
            task_id=(task_id or "").strip(),
            workflow_id=(task_group or "").strip(),
            producer="tool.write_artifact_entry",
            metadata={
                "kind": normalized_kind,
                "task_id": task_id,
                "task_group": task_group,
                "slot": slot,
            },
        )
        if task_id and slot and self._task_list_manager:
            self._task_list_manager.set_task_artifact(task_id, slot, ref.artifact_id)
        return "\n".join(
            [
                "# Artifact 写入成功",
                "",
                f"- artifact_ref: `{ref.artifact_id}`",
                f"- kind: `{normalized_kind}`",
                f"- task_id: `{task_id or 'N/A'}`",
                f"- task_group: `{task_group or 'N/A'}`",
                f"- slot: `{slot or 'N/A'}`",
                f"- size: {ref.size}",
            ]
        )

    async def link_task_artifact(
        self,
        task_id: str,
        slot: str,
        artifact_ref: str,
    ) -> str:
        """
        将现有 artifact_ref 绑定到任务槽位。
        """
        if not self._task_list_manager:
            return "[错误] TaskListManager 未初始化。"
        if not self.artifact_store:
            return "[错误] ArtifactStore 未初始化。"
        normalized_task_id = (task_id or "").strip()
        normalized_slot = (slot or "").strip()
        normalized_ref = self._extract_artifact_id(artifact_ref)
        if not normalized_task_id:
            return "[错误] task_id 不能为空。"
        if not normalized_slot:
            return "[错误] slot 不能为空。"
        if not normalized_ref:
            return "[错误] artifact_ref 不能为空。"
        if not self.artifact_store.exists(normalized_ref):
            return f"[错误] artifact_ref 不存在: {normalized_ref}"
        try:
            self._task_list_manager.set_task_artifact(
                task_id=normalized_task_id,
                slot=normalized_slot,
                artifact_ref=normalized_ref,
            )
        except Exception as e:
            return f"[错误] 绑定失败: {str(e)}"
        return "\n".join(
            [
                "# 任务 Artifact 绑定成功",
                "",
                f"- task_id: `{normalized_task_id}`",
                f"- slot: `{normalized_slot}`",
                f"- artifact_ref: `{normalized_ref}`",
            ]
        )

    async def list_task_artifacts(self, task_id: str) -> str:
        """
        列出任务槽位绑定的全部 Artifact。
        """
        if not self._task_list_manager:
            return "[错误] TaskListManager 未初始化。"
        if not self.artifact_store:
            return "[错误] ArtifactStore 未初始化。"
        normalized_task_id = (task_id or "").strip()
        if not normalized_task_id:
            return "[错误] task_id 不能为空。"
        mappings = self._task_list_manager.list_task_artifacts(normalized_task_id)
        if not mappings:
            return f"# 任务 Artifact 列表\n\n任务 `{normalized_task_id}` 暂无槽位绑定。"
        lines = [
            "# 任务 Artifact 列表",
            "",
            f"- task_id: `{normalized_task_id}`",
            f"- slots: {len(mappings)}",
            "",
        ]
        for slot, ref in mappings.items():
            meta = self.artifact_store.read_metadata(ref)
            lines.append(f"## {slot}")
            lines.append(f"- artifact_ref: `{ref}`")
            lines.append(f"- kind: {meta.get('kind', 'unknown')}")
            lines.append(f"- summary: {meta.get('summary', '') or '(none)'}")
            lines.append("")
        return "\n".join(lines)

    async def read_task_output(self, task_id: str) -> Any:
        """读取指定任务的输出 Artifact。
        
        根据 task_id 查找 `output` 槽位绑定的 artifact_ref 并返回内容。
        
        Args:
            task_id: 任务 ID，例如 "task_1"
        
        Returns:
            任务输出内容（Markdown 文本）。
        """
        try:
            if not self._task_list_manager:
                return "[错误] TaskListManager 未初始化。"
            if not self.artifact_store:
                return "[错误] ArtifactStore 未初始化。"
            normalized_task_id = str(task_id or "").strip()
            if not normalized_task_id:
                return self._format_recoverable_error(
                    error_code="INVALID_ARGUMENT",
                    message="task_id 不能为空。",
                    payload={
                        "required_next_actions": [
                            "传入合法 task_id（如 task_1）后重试 read_task_output",
                        ],
                    },
                )

            task = self._task_list_manager.get_task(normalized_task_id)
            if not task:
                return self._format_recoverable_error(
                    error_code="TASK_NOT_FOUND",
                    message=f"任务不存在: {normalized_task_id}",
                    payload={
                        "task_id": normalized_task_id,
                        "required_next_actions": [
                            "调用 get_task_status(task_group=...) 获取真实任务列表",
                            "确认 task_id 后再调用 read_task_output",
                        ],
                    },
                )

            task_group = str(getattr(task, "task_group", "") or "").strip()
            task_description = str(getattr(task, "description", "") or "").strip()
            task_status = str(
                getattr(getattr(task, "status", None), "value", getattr(task, "status", "unknown"))
            ).strip() or "unknown"

            execute_cmd = (
                f"execute_task(task_id=\"{normalized_task_id}\", task_group=\"{task_group}\")"
                if task_group
                else f"execute_task(task_id=\"{normalized_task_id}\")"
            )
            list_status_cmd = (
                f"get_task_status(task_group=\"{task_group}\")"
                if task_group
                else "get_task_status(task_group=...)"
            )
            list_runnable_cmd = (
                f"list_runnable_tasks(task_group=\"{task_group}\")"
                if task_group
                else "list_runnable_tasks(task_group=...)"
            )

            output_ref = self._task_list_manager.get_task_artifact(normalized_task_id, "output")
            if not output_ref:
                if task_status == "pending":
                    actions = [
                        f"先调用 {list_runnable_cmd} 确认可执行任务",
                        f"调用 {execute_cmd} 执行任务产出输出",
                        "执行成功后再调用 read_task_output",
                    ]
                elif task_status == "in_progress":
                    actions = [
                        f"调用 {list_status_cmd} 检查任务是否已完成",
                        "若任务长时间无进展，再重试 execute_task",
                    ]
                elif task_status == "failed":
                    actions = [
                        f"调用 {list_status_cmd} 查看失败原因",
                        "根据错误修复前置条件后重试 execute_task",
                    ]
                elif task_status == "completed":
                    actions = [
                        f"调用 list_task_artifacts(task_id=\"{normalized_task_id}\") 检查槽位绑定",
                        f"若确认缺失输出，重试 {execute_cmd} 重新产出 output artifact",
                    ]
                else:
                    actions = [
                        f"调用 {list_status_cmd} 确认任务状态",
                        f"必要时调用 {execute_cmd} 重新执行任务",
                    ]
                return self._format_recoverable_error(
                    error_code="MISSING_TASK_OUTPUT_ARTIFACT",
                    message=f"任务 {normalized_task_id} 尚无输出 artifact。",
                    payload={
                        "task_id": normalized_task_id,
                        "task_group": task_group,
                        "task_description": task_description,
                        "task_status": task_status,
                        "required_next_actions": actions,
                    },
                )
            if not self.artifact_store.exists(output_ref):
                return self._format_recoverable_error(
                    error_code="OUTPUT_ARTIFACT_NOT_FOUND",
                    message=f"输出 artifact 不存在: {output_ref}",
                    payload={
                        "task_id": normalized_task_id,
                        "task_group": task_group,
                        "task_description": task_description,
                        "task_status": task_status,
                        "artifact_ref": output_ref,
                        "required_next_actions": [
                            f"调用 list_task_artifacts(task_id=\"{normalized_task_id}\") 核对 output 槽位绑定",
                            f"调用 list_artifacts() 或 read_artifact(artifact_id=\"{output_ref}\") 校验 artifact 可读性",
                            f"若 artifact 已失效，重试 {execute_cmd} 重新产出输出",
                        ],
                    },
                )
            content = self.artifact_store.read(output_ref)
            meta = self.artifact_store.read_metadata(output_ref)

            # 格式化返回结果
            lines = [
                f"# 任务输出: {normalized_task_id}",
                "",
                f"**artifact_ref**: {output_ref}",
                f"**kind**: {meta.get('kind', 'task_output')}",
                "",
                "---",
                "",
                content,
            ]
            
            return "\n".join(lines)
        
        except Exception as e:
            return f"[错误] 读取任务输出失败: {str(e)}"

    # ==================== 辅助方法 ====================

    def _get_previous_task_outputs(self, current_task_id: str, task_group: Optional[str] = None) -> List[str]:
        """
        获取前置任务的输出 artifact_ref 列表
        
        Args:
            current_task_id: 当前任务 ID (如 task_2)
            task_group: 任务分组标识（可选）
        
        Returns:
            List[str]: 前置任务的输出 artifact_ref 列表
        """
        if not self._task_list_manager:
            return []
        tasks = self._task_list_manager.get_all_tasks(task_group=task_group)
        if not tasks:
            return []

        task_ids = [task.id for task in tasks]
        if current_task_id not in task_ids:
            return []

        current_index = task_ids.index(current_task_id)
        output_refs: List[str] = []
        for prev_task in tasks[:current_index]:
            ref = self._task_list_manager.get_task_artifact(prev_task.id, "output")
            if ref and self.artifact_store and self.artifact_store.exists(ref):
                output_refs.append(ref)

        return output_refs

    def _max_parallel_tasks(self, agent_type: str) -> int:
        """根据 agent_type 返回最大并发任务数（由 Agent 控制）"""
        if agent_type in {"vuln_analysis", "code_explorer"}:
            return self.max_vuln_concurrency
        return 1

    async def _execute_single_task(
        self,
        task: Any,
        agent_type: str,
        additional_context: str,
        input_files_override: Optional[List[str]] = None,
        task_group: Optional[str] = None,
    ) -> Tuple[Any, Any, str]:
        """执行单个任务并返回结果元组"""

        # 读取前置任务输出 artifact（如果有）
        input_artifacts = (
            input_files_override
            if input_files_override is not None
            else self._get_previous_task_outputs(task.id, task_group=task_group)
        )

        # 调用 AgentDelegate 执行任务
        result = await self._agent_delegate.delegate(
            agent_type=agent_type,
            task_description=task.description,
            input_artifact_refs=input_artifacts,
            context=additional_context,
            function_identifier=getattr(task, "function_identifier", None),
            task_id=task.id,
            task_group=str(task_group or ""),
        )
        output_ref = str(getattr(result, "output_ref", "") or "").strip()
        if output_ref:
            self._task_list_manager.set_task_artifact(task.id, "output", output_ref)

        # 结束认领任务（claimant 校验）
        finalized = self._task_list_manager.complete_claimed_task(
            task_id=task.id,
            claimant=self._claimant_id,
            success=bool(result.success),
            error_message=result.error_message,
        )
        if not finalized:
            # 严格保持 claim 语义：结束失败时不越权改写状态，等待 lease 超时回收。
            result.success = False
            lease_msg = (
                f"任务结束回写失败（task_id={task.id}, claimant={self._claimant_id}），"
                "已保持原状态等待 lease 回收。"
            )
            prev_msg = getattr(result, "error_message", "") or ""
            result.error_message = f"{prev_msg}; {lease_msg}".strip("; ")

        return task, result, output_ref

    def _format_batch_execution_result(
        self,
        results: List[Tuple[Any, Any, str]],
        task_group: Optional[str] = None,
    ) -> str:
        """格式化批量任务执行结果"""
        lines = [
            "## 执行结果",
            "",
            f"**批量任务数**: {len(results)}",
            "",
        ]

        for task, result, output_ref in results:
            lines.append(f"### {task.id} - {task.description}")
            if result.success:
                lines.extend([
                    f"- 状态: 已完成 ✓",
                    f"- 输出 artifact_ref: {output_ref or 'N/A'}",
                ])
            else:
                lines.extend([
                    f"- 状态: 失败 ✗",
                    f"- 错误: {result.error_message}",
                ])
            lines.append("")

        lines.extend([
            "---",
            "",
            "## 当前任务列表",
            "",
        ])

        # 添加任务列表
        all_tasks = self._task_list_manager.get_all_tasks(task_group=task_group)
        for task_item in all_tasks:
            lines.append(task_item.to_markdown_line())

        # 添加统计信息
        stats = self._task_list_manager.get_statistics(task_group=task_group)
        lines.extend([
            "",
            "---",
            "",
            f"**总计**: {stats['total']} 个任务",
            f"**已完成**: {stats['completed']} 个",
            f"**待执行**: {stats['pending']} 个",
            f"**进度**: {stats['completion_rate']}%",
        ])

        if self._task_list_manager.is_all_completed(task_group=task_group):
            lines.extend([
                "",
                "🎉 **所有任务已完成！**",
            ])

        return "\n".join(lines)

    def _format_execution_result(
        self,
        task: Any,
        result: Any,
        output_ref: str,
        task_group: Optional[str] = None,
    ) -> str:
        """
        格式化任务执行结果
        
        Args:
            task: 任务对象
            result: AgentDelegate 返回的结果
            output_ref: 输出 artifact_ref
        
        Returns:
            str: 格式化的结果文本
        """
        lines = [
            "## 执行结果",
            "",
            f"**任务**: {task.id} - {task.description}",
        ]
        
        if result.success:
            lines.extend([
                f"**状态**: 已完成 ✓",
                f"**输出 artifact_ref**: {output_ref or 'N/A'}",
                "",
            ])
            
            # 提取关键发现（从输出中提取前几行作为摘要）
            if result.output:
                summary_lines = result.output.split('\n')[:10]
                lines.extend([
                    "**关键发现**:",
                    "",
                    '\n'.join(summary_lines),
                    "",
                    "（完整结果已保存到输出 Artifact）",
                ])
        else:
            lines.extend([
                f"**状态**: 失败 ✗",
                f"**错误**: {result.error_message}",
                "",
            ])
        
        lines.extend([
            "",
            "---",
            "",
            "## 当前任务列表",
            "",
        ])
        
        # 添加任务列表
        all_tasks = self._task_list_manager.get_all_tasks(task_group=task_group)
        for task_item in all_tasks:
            lines.append(task_item.to_markdown_line())
        
        # 添加统计信息
        stats = self._task_list_manager.get_statistics(task_group=task_group)
        lines.extend([
            "",
            "---",
            "",
            f"**总计**: {stats['total']} 个任务",
            f"**已完成**: {stats['completed']} 个",
            f"**待执行**: {stats['pending']} 个",
            f"**进度**: {stats['completion_rate']}%",
        ])
        
        # 如果所有任务已完成，添加祝贺信息
        if self._task_list_manager.is_all_completed(task_group=task_group):
            lines.extend([
                "",
                "🎉 **所有任务已完成！**",
            ])
        
        return "\n".join(lines)

    def _build_query_prompt(self, query: str, context: Optional[str]) -> str:
        """构建代码查询提示词"""
        lines = [
            "你是一个代码分析助手。请根据以下信息回答问题。",
            "",
            f"查询: {query}",
        ]

        if context:
            lines.append(f"\n上下文: {context}")

        if self.workflow_context:
            lines.append(
                f"\n分析目标: {self.workflow_context.target.path if self.workflow_context.target else 'Unknown'}")

        if self.engine:
            lines.append(f"引擎类型: {self.engine.__class__.__name__}")
            if hasattr(self.engine, 'file_path'):
                lines.append(f"目标文件: {self.engine.file_path}")

        lines.append("\n请提供详细的分析结果。")

        return "\n".join(lines)

    def _normalize_workflows(self, workflows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """标准化 workflow 信息，补充默认值"""
        normalized = []
        for i, wf in enumerate(workflows, 1):
            normalized_wf = {
                "workflow_id": wf.get("workflow_id", f"workflow_{i}"),
                "workflow_name": wf.get("workflow_name", f"Workflow {i}"),
                "workflow_description": wf.get("workflow_description", ""),
                "tasks": wf["tasks"],
                "execution_mode": wf.get("execution_mode", "sequential"),
            }
            normalized.append(normalized_wf)
        return normalized

    def _flatten_workflow_tasks(self, workflows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """将多 workflow 任务展开为统一序列，保留 workflow 元信息"""
        flat_tasks: List[Dict[str, Any]] = []
        for wf in workflows:
            workflow_id = wf.get("workflow_id", "")
            workflow_name = wf.get("workflow_name", "")
            execution_mode = wf.get("execution_mode", "sequential")
            for task in wf.get("tasks", []):
                if isinstance(task, dict):
                    merged = dict(task)
                    merged["task_group"] = workflow_id
                    merged["workflow_name"] = workflow_name
                    merged["workflow_execution_mode"] = execution_mode
                    merged["analysis_context"] = task.get("analysis_context")
                    flat_tasks.append(merged)
                else:
                    flat_tasks.append({
                        "description": str(task).strip(),
                        "task_group": workflow_id,
                        "workflow_name": workflow_name,
                        "workflow_execution_mode": execution_mode,
                    })
        return flat_tasks

    def _format_single_workflow_summary(self, workflow: Dict[str, Any]) -> str:
        """格式化单 workflow 摘要"""
        tasks = workflow["tasks"]
        lines = [
            "# 任务规划完成",
            "",
            f"**模式**: 单 Workflow",
            f"**任务数量**: {len(tasks)}",
            "",
            "## 任务列表",
            "",
        ]
        
        for i, task in enumerate(tasks, 1):
            if isinstance(task, dict):
                task_desc = task.get("description", "")
            else:
                task_desc = str(task)
            lines.append(f"{i}. {task_desc}")
        
        lines.extend([
            "",
            "---",
            "",
            "✅ 任务列表已创建，可以开始执行任务。",
        ])
        
        return "\n".join(lines)

    def _format_multi_workflow_summary(self, workflows: List[Dict[str, Any]]) -> str:
        """格式化多 workflow 摘要"""
        total_tasks = sum(len(wf["tasks"]) for wf in workflows)
        
        lines = [
            "# 任务规划完成",
            "",
            f"**模式**: 多 Workflow",
            f"**Workflow 数量**: {len(workflows)}",
            f"**总任务数量**: {total_tasks}",
            "",
            "## Workflow 列表",
            "",
        ]
        
        for i, wf in enumerate(workflows, 1):
            lines.extend([
                f"### {i}. {wf['workflow_name']}",
                "",
                f"**ID**: `{wf['workflow_id']}`",
            ])
            
            if wf.get("workflow_description"):
                lines.append(f"**描述**: {wf['workflow_description']}")
            
            lines.extend([
                f"**执行模式**: {wf['execution_mode']}",
                f"**任务数量**: {len(wf['tasks'])}",
                "",
                "**任务列表**:",
                "",
            ])
            
            for j, task in enumerate(wf["tasks"], 1):
                if isinstance(task, dict):
                    task_desc = task.get("description", "")
                else:
                    task_desc = str(task)
                lines.append(f"{j}. {task_desc}")
            
            lines.append("")
        
        lines.extend([
            "---",
            "",
            "✅ 多 Workflow 规划完成，任务列表已创建，可以开始执行任务。",
        ])
        
        return "\n".join(lines)

    # 新增：供 MasterOrchestrator 查询的方法
    def get_planned_workflows(self) -> Optional[List[Dict[str, Any]]]:
        """获取规划的 workflow 列表"""
        return self._planned_workflows

    def is_multi_workflow(self) -> bool:
        """判断是否为多 workflow 模式"""
        return self._is_multi_workflow

    # ==================== LangChain Tool 导出 ====================

    def get_tools(self) -> List[Any]:
        """
        获取所有 Tool 的函数列表。
        供 OrchestratorAgent 使用。
        """
        return [
            # 简化的任务编排工具（新设计）
            self.plan_tasks,
            self.append_tasks,
            self.list_runnable_tasks,
            self.compose_task_context,
            self.execute_task,
            self.execute_tasks,
            self.resolve_function_identifier,
            self.set_task_function_identifier,
            self.get_task_status,
            self.read_task_output,
            self.list_artifacts,
            self.write_artifact_entry,
            self.link_task_artifact,
            self.list_task_artifacts,
            self.mark_compression_projection,
            # 统一的 Agent 委托接口
            self.delegate_task,
            # 数据访问工具
            self.read_artifact,
        ]

    def get_executor_tools(self) -> List[Any]:
        """
        获取执行器可用的 Tool 列表。

        TaskExecutorAgent 只允许执行任务，不允许规划与通用委托。
        仅开放受限的 `delegate_code_explorer` 用于取证。
        """
        return [
            self.list_runnable_tasks,
            self.compose_task_context,
            self.execute_task,
            self.execute_tasks,
            self.resolve_function_identifier,
            self.set_task_function_identifier,
            self.delegate_code_explorer,
            self.get_task_status,
            self.read_task_output,
            self.write_artifact_entry,
            self.link_task_artifact,
            self.list_task_artifacts,
            self.mark_compression_projection,
            self.read_artifact,
        ]


