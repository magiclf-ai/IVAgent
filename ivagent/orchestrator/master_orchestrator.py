#!/usr/bin/env python3
"""
MasterOrchestrator - 多 Workflow 协调器

负责将复杂的漏洞挖掘 workflow 拆分为多个独立的子 workflow，
并协调多个 TaskExecutorAgent 的执行（串行/并行）。
"""

from typing import Any, List, Optional, Dict
from dataclasses import dataclass, field
from pathlib import Path
import json
import asyncio
import time

from langchain_openai import ChatOpenAI

from ..models.workflow import WorkflowContext
from ..engines import create_engine, BaseStaticAnalysisEngine
from ..core import ToolBasedLLMClient
from ..core.cli_logger import CLILogger
from ..core.context import ArtifactStore
from .workflow_parser import WorkflowParser
from .planning_prompts import (
    build_planning_user_prompt,
    build_master_planning_system_prompt,
)
from .task_list_manager import TaskListManager, TaskStatus


@dataclass
class MasterOrchestratorResult:
    """MasterOrchestrator 执行结果"""
    success: bool
    total_workflows: int
    completed_workflows: int
    total_vulnerabilities: int
    execution_time: float
    summary: str
    workflow_results: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


class MasterOrchestrator:
    """Master Orchestrator - 多 Workflow 协调器"""
    
    def __init__(
        self,
        llm_client: ChatOpenAI,
        engine_type: Optional[str] = None,
        target_path: Optional[str] = None,
        source_root: Optional[str] = None,
        session_id: Optional[str] = None,
        execution_mode: str = "sequential",
        verbose: bool = True,
        enable_logging: bool = True,
    ):
        self.llm_client = llm_client
        self.engine_type = engine_type
        self.target_path = target_path
        self.source_root = source_root
        self.session_id = session_id or f"master_session_{id(self)}"
        self.execution_mode = execution_mode
        self.verbose = verbose
        self.enable_logging = enable_logging
        self._logger = CLILogger(component="MasterOrchestrator", verbose=verbose)
        
        self.engine: Optional[BaseStaticAnalysisEngine] = None
        self.workflow_context: Optional[WorkflowContext] = None
        self.session_dir = self._resolve_session_dir()
        self.session_dir.mkdir(parents=True, exist_ok=True)
        self.artifact_store = ArtifactStore(self.session_dir / "artifacts")
        
        self.llm_client_wrapper = ToolBasedLLMClient(
            llm=self.llm_client,
            max_retries=3,
            retry_delay=1.0,
            verbose=self.verbose,
            enable_logging=self.enable_logging,
            session_id=self.session_id,
            agent_id=f"master_orchestrator_{self.session_id}",
            log_metadata={
                "agent_type": "master_orchestrator",
                "session_id": self.session_id,
            },
        )
    
    def _resolve_session_dir(self) -> Path:
        """确定 session 目录路径"""
        if self.source_root:
            base_dir = Path(self.source_root) / ".ivagent" / "sessions"
        else:
            base_dir = Path.cwd() / ".ivagent" / "sessions"
        return base_dir / self.session_id
    
    def _log(self, message: str, level: str = "info"):
        """打印日志"""
        if not self.verbose:
            return
        self._logger.log(level=level, event="master.event", message=message)

    def _normalize_tool_output(self, result_data: Any) -> tuple[str, Optional[str]]:
        """
        规范化工具输出，支持 content/summary 双轨返回。

        返回:
            (content, summary) 其中 summary 可能为 None
        """
        if isinstance(result_data, dict) and ("content" in result_data or "summary" in result_data):
            content = str(result_data.get("content") or "")
            summary = (result_data.get("summary") or "").strip()
            return content, summary or None
        if isinstance(result_data, str):
            return result_data, None
        return json.dumps(result_data, ensure_ascii=False), None

    async def _guide_planning(
        self,
        orchestrator: Any,
        workflow_context: WorkflowContext
    ) -> None:
        """引导 LLM 调用 plan_tasks（允许多轮以先获取 function_identifier）

        Args:
            orchestrator: TaskOrchestratorAgent 实例
            workflow_context: Workflow 上下文
        """
        # 1. 构建规划 prompt
        planning_prompt = self._build_planning_prompt(workflow_context)

        # 2. 添加用户消息
        await orchestrator.message_manager.add_user_message(planning_prompt)

        # 3. 组装上下文并调用 LLM（允许先调用工具获取 function_identifier）
        max_rounds = 5
        planned = False
        allowed_tools = {
            "plan_tasks",
            "delegate_task",
            "read_artifact",
            "list_artifacts",
            "get_task_status",
            "read_task_output",
            "list_task_artifacts",
            "resolve_function_identifier",
            "set_task_function_identifier",
        }

        for round_id in range(1, max_rounds + 1):
            assembled_messages = await orchestrator.context_assembler.build_messages(
                system_prompt=self._get_planning_system_prompt(),
            )

            result = await orchestrator.llm_client_wrapper.atool_call(
                messages=assembled_messages,
                tools=orchestrator.tools,
                system_prompt=None,
            )

            await orchestrator.message_manager.add_ai_message(
                result.content or "",
                tool_calls=result.tool_calls,
            )

            if not result.tool_calls:
                self._log("LLM 未调用 plan_tasks，使用默认规划", "warning")
                break

            for tool_call in result.tool_calls:
                tool_name = tool_call.get("name", "")
                tool_args = tool_call.get("args", {})
                tool_id = tool_call.get("id", "")

                if tool_name == "plan_tasks":
                    self._log(f"执行 Tool: {tool_name}", "debug")
                    try:
                        result_data = await orchestrator._execute_tool(tool_name, tool_args)
                        content, summary = self._normalize_tool_output(result_data)
                        await orchestrator.message_manager.add_tool_message(
                            content=content,
                            summary=summary,
                            tool_name=tool_name,
                            tool_call_id=tool_id,
                        )
                        planned_workflows = None
                        if getattr(orchestrator, "tools_manager", None):
                            planned_workflows = orchestrator.tools_manager.get_planned_workflows()
                        if planned_workflows:
                            self._log("规划完成", "success")
                            planned = True
                        else:
                            self._log("规划未完成，等待修复后重试", "warning")
                    except Exception as e:
                        error_msg = f"规划失败: {str(e)}"
                        self._log(error_msg, "error")
                        error_content = json.dumps({"error": error_msg}, ensure_ascii=False)
                        await orchestrator.message_manager.add_tool_message(
                            content=error_content,
                            tool_name=tool_name,
                            tool_call_id=tool_id,
                        )
                    break

                if tool_name not in allowed_tools:
                    error_msg = f"规划阶段不支持调用 {tool_name}，仅允许: {', '.join(sorted(allowed_tools))}"
                    self._log(error_msg, "warning")
                    error_content = json.dumps({"error": error_msg}, ensure_ascii=False)
                    await orchestrator.message_manager.add_tool_message(
                        content=error_content,
                        tool_name=tool_name,
                        tool_call_id=tool_id,
                    )
                    continue

                if tool_name == "delegate_task":
                    if tool_args.get("agent_type") != "code_explorer":
                        error_msg = "规划阶段仅允许 delegate_task(agent_type=\"code_explorer\") 用于 search_symbol"
                        self._log(error_msg, "warning")
                        error_content = json.dumps({"error": error_msg}, ensure_ascii=False)
                        await orchestrator.message_manager.add_tool_message(
                            content=error_content,
                            tool_name=tool_name,
                            tool_call_id=tool_id,
                        )
                        continue

                self._log(f"执行 Tool: {tool_name}", "debug")
                try:
                    result_data = await orchestrator._execute_tool(tool_name, tool_args)
                    content, summary = self._normalize_tool_output(result_data)
                    await orchestrator.message_manager.add_tool_message(
                        content=content,
                        summary=summary,
                        tool_name=tool_name,
                        tool_call_id=tool_id,
                    )
                except Exception as e:
                    error_msg = f"规划阶段工具调用失败: {str(e)}"
                    self._log(error_msg, "error")
                    error_content = json.dumps({"error": error_msg}, ensure_ascii=False)
                    await orchestrator.message_manager.add_tool_message(
                        content=error_content,
                        tool_name=tool_name,
                        tool_call_id=tool_id,
                    )

            if planned:
                break

        if not planned:
            self._log("LLM 未完成 plan_tasks 规划，使用默认规划", "warning")

    def _load_task_list_manager(self) -> TaskListManager:
        """加载任务列表管理器（从 session/tasks.md 读取）"""
        tasks_file = self.session_dir / "tasks.md"
        return TaskListManager(tasks_file=tasks_file)

    def _has_completed_vuln_analysis(self, task_manager: TaskListManager) -> bool:
        """是否已完成至少一个 vuln_analysis 任务。"""
        tasks = task_manager.get_all_tasks()
        return any(
            t.agent_type == "vuln_analysis" and t.status == TaskStatus.COMPLETED
            for t in tasks
        )

    def _should_stop_cycle(self, task_manager: TaskListManager) -> bool:
        """
        Agentic 循环停止条件（最小硬门禁）：
        1) 没有 pending/in_progress 任务；
        2) 至少完成过一个 vuln_analysis 任务。
        """
        tasks = task_manager.get_all_tasks()
        if not tasks:
            return False
        has_pending = any(
            t.status in (TaskStatus.PENDING, TaskStatus.IN_PROGRESS)
            for t in tasks
        )
        if has_pending:
            return False
        if not self._has_completed_vuln_analysis(task_manager):
            return False
        return True

    def _collect_completed_code_explorer_summaries(
        self,
        tasks: List[Any],
        max_items: int = 6,
    ) -> List[str]:
        """收集已完成 code_explorer 任务摘要，供回顾阶段复用。"""
        summaries: List[str] = []
        task_manager = self._load_task_list_manager()

        completed_code = [
            t for t in tasks
            if t.agent_type == "code_explorer" and t.status == TaskStatus.COMPLETED
        ]
        for task in completed_code[:max_items]:
            output_ref = task_manager.get_task_artifact(task.id, "output")
            if not output_ref:
                continue
            meta = self.artifact_store.read_metadata(output_ref)
            summary_text = str(meta.get("summary") or "").strip()
            if not summary_text:
                raw = self.artifact_store.read(output_ref)
                summary_text = "\n".join((raw or "").splitlines()[:20]).strip()
            if not summary_text:
                continue
            summaries.append(
                "\n".join([
                    f"### {task.id}",
                    f"- artifact_ref: `{output_ref}`",
                    summary_text,
                ])
            )
        return summaries

    def _build_post_execution_review_prompt(
        self,
        tasks: List[Any],
        workflows: List[Dict[str, Any]],
        round_id: int,
        max_rounds: int,
        final_audit: bool = False,
    ) -> str:
        """构建执行后回顾提示词（追加规划）"""
        status_map = {
            TaskStatus.PENDING: "待执行",
            TaskStatus.IN_PROGRESS: "执行中",
            TaskStatus.COMPLETED: "已完成",
            TaskStatus.FAILED: "失败",
        }

        vuln_tasks = [t for t in tasks if t.agent_type == "vuln_analysis"]
        code_tasks = [t for t in tasks if t.agent_type == "code_explorer"]
        completed_vuln = [t for t in vuln_tasks if t.status == TaskStatus.COMPLETED]
        completed_code = [t for t in code_tasks if t.status == TaskStatus.COMPLETED]

        lines = [
            "# 执行后回顾",
            "",
            f"当前回顾轮次: {round_id}/{max_rounds}",
            "请基于当前证据反思：是否仍有未完成工作（尤其是漏洞挖掘覆盖与验证闭环）。",
            "若存在未完成工作，必须通过 `append_tasks(workflows)` 追加任务。",
            "若判断可结束，必须确保任务看板已无 pending/in_progress，且至少完成过一次 vuln_analysis。",
            "",
            "## 任务统计",
            "",
            f"- 总任务数: {len(tasks)}",
            f"- vuln_analysis 任务数: {len(vuln_tasks)}",
            f"- 已完成 vuln_analysis: {len(completed_vuln)}",
            f"- code_explorer 任务数: {len(code_tasks)}",
            f"- 已完成 code_explorer: {len(completed_code)}",
            "",
            "## Workflow 列表",
            "",
        ]

        if final_audit:
            lines.extend([
                "## 最终审查要求",
                "",
                "这是最终审查轮次：必须审查最终任务执行状态，并至少调用一次工具（建议先调用 `get_task_status`）。",
                "",
            ])

        for idx, wf in enumerate(workflows, 1):
            lines.append(f"{idx}. {wf.get('workflow_name', 'Workflow')} (workflow_id={wf.get('workflow_id', '')})")

        lines.extend([
            "",
            "## 任务列表",
            "",
        ])

        for task in tasks:
            status = status_map.get(task.status, task.status.value if hasattr(task.status, "value") else str(task.status))
            lines.append(
                f"- {task.id} | {task.agent_type or 'unknown'} | {status} | {task.description}"
            )

        code_summaries = self._collect_completed_code_explorer_summaries(tasks)
        if code_summaries:
            lines.extend([
                "",
                "## 已完成 code_explorer 摘要（优先复用）",
                "",
                "以下摘要来自已完成任务：若摘要出现“部分完成-迭代上限 / 未推断信息 / 需 Orchestrator 继续规划的 CodeExplorer 子任务”，必须先追加新的 `code_explorer` 任务补齐缺口。",
                "",
            ])
            for item in code_summaries:
                lines.append(item)
                lines.append("")

        lines.extend([
            "",
            "## 反思要求",
            "",
            "1. 优先复用已完成任务输出，不重复探索。",
            "2. 仅能使用 `append_tasks(workflows)` 追加任务，禁止 `plan_tasks`。",
            "3. `vuln_analysis` 任务必须提供 `function_identifier` 与 `analysis_context`。",
            "4. `analysis_context` 必须包含固定章节：目标函数、入参约束、全局变量约束、证据锚点；其中入参约束必须按参数逐条覆盖。",
            "5. 若缺少参数级入参约束、全局变量约束、证据锚点或 function_identifier，不得直接结束，先补工具调用。",
            "6. 追加任务必须指定正确的 `workflow_id`（即 task_group）。",
            "7. 必须执行“任务遗漏自检”；若存在覆盖疑点，必须追加任务，不得结束。",
            "8. 若 code_explorer 摘要包含“部分完成-迭代上限 / 未推断信息 / 需 Orchestrator 继续规划的 CodeExplorer 子任务”，必须先追加 `code_explorer`，不得直接收敛。",
            "9. 若压缩摘要出现 `## 与当前分析目标匹配的语义理解蒸馏`，必须优先依据其中“中间结论”做决策，不得回退为全量重查。",
            "10. 若压缩摘要中 `### 是否需要继续获取信息` 为“是”，必须先执行 `### 最小补充信息集` 对应的最小补证动作，再决定是否追加任务或结束。",
            "11. 若压缩摘要中 `### 是否需要继续获取信息` 为“否”，禁止继续追加与缺口无关的重复取证任务，应优先收敛（finish 或转 vuln_analysis）。",
            "12. 只输出工具调用，不输出其他文本。",
        ])

        return "\n".join(lines)

    @staticmethod
    def _extract_added_tasks_count(result_data: Any) -> Optional[int]:
        """从 append_tasks 工具返回中提取新增任务数。"""
        if not isinstance(result_data, dict):
            return None
        meta = result_data.get("meta")
        if isinstance(meta, dict):
            value = meta.get("added_tasks")
            if isinstance(value, int):
                return value
            if isinstance(value, str) and value.isdigit():
                return int(value)
        value = result_data.get("added_tasks")
        if isinstance(value, int):
            return value
        if isinstance(value, str) and value.isdigit():
            return int(value)
        return None

    async def _run_reflection_checkpoint(
        self,
        orchestrator: Any,
        workflows: List[Dict[str, Any]],
        round_id: int,
        max_rounds: int,
        final_check: bool = False,
        reason: str = "",
    ) -> Dict[str, Any]:
        """
        单一反思检查点：在同一流程中完成回顾、取证、追加与结束决策。

        返回:
            {
              "action": "append" | "continue" | "finish",
              "appended": bool,
              "reason": str,
              "missing_function_identifiers": List[str],
            }
        """
        task_manager = self._load_task_list_manager()
        tasks = task_manager.get_all_tasks()
        if not tasks:
            return {
                "action": "finish",
                "appended": False,
                "reason": "无任务可反思，默认结束。",
                "missing_function_identifiers": [],
            }

        prompt = self._build_post_execution_review_prompt(
            tasks=tasks,
            workflows=workflows,
            round_id=round_id,
            max_rounds=max_rounds,
            final_audit=final_check,
        )
        extra_lines = [
            "",
            "## 反思决策",
            "",
            "你必须在本轮调用 `mark_reflection_decision(action, reason, missing_function_identifiers)`。",
            "- action 可选：`append`（需要补任务）、`continue`（继续执行/取证）、`finish`（申请结束）。",
            "- 若任务看板仍有 pending/in_progress，`finish` 不会生效。",
        ]
        if reason:
            extra_lines.extend(["", f"本轮背景：{reason}"])
        await orchestrator.message_manager.add_user_message(prompt + "\n" + "\n".join(extra_lines))

        decision_state: Dict[str, Any] = {
            "called": False,
            "action": "continue",
            "reason": "",
            "missing_function_identifiers": [],
        }

        def mark_reflection_decision(
            action: str,
            reason: str = "",
            missing_function_identifiers: Optional[List[str]] = None,
        ):
            """
            提交反思检查点结构化决策。

            Args:
                action: append/continue/finish
                reason: 决策原因（纯文本）
                missing_function_identifiers: 可选，疑似遗漏函数标识符列表
            """
            normalized = (action or "").strip().lower()
            if normalized not in {"append", "continue", "finish"}:
                raise ValueError("action 必须是 append/continue/finish")
            decision_state["called"] = True
            decision_state["action"] = normalized
            decision_state["reason"] = (reason or "").strip()
            decision_state["missing_function_identifiers"] = list(missing_function_identifiers or [])

        allowed_tools = {
            "append_tasks",
            "delegate_task",
            "compose_task_context",
            "read_artifact",
            "get_task_status",
            "read_task_output",
            "resolve_function_identifier",
            "set_task_function_identifier",
            "list_artifacts",
            "write_artifact_entry",
            "link_task_artifact",
            "list_task_artifacts",
            "mark_reflection_decision",
        }

        max_tool_rounds = 5
        appended = False
        append_called = False
        tools_for_reflection = list(orchestrator.tools) + [mark_reflection_decision]

        for _ in range(max_tool_rounds):
            assembled_messages = await orchestrator.context_assembler.build_messages(
                system_prompt=(
                    "# 反思检查点\n"
                    "你负责在当前轮次做结构化决策：append/continue/finish。"
                    "你可以先调用工具取证，但必须在结束前调用 mark_reflection_decision。"
                    "禁止调用 plan_tasks。"
                ),
            )
            result = await orchestrator.llm_client_wrapper.atool_call(
                messages=assembled_messages,
                tools=tools_for_reflection,
                system_prompt=None,
            )
            await orchestrator.message_manager.add_ai_message(
                result.content or "",
                tool_calls=result.tool_calls,
            )
            if not result.tool_calls:
                if not decision_state["called"]:
                    await orchestrator.message_manager.add_user_message(
                        "请调用 mark_reflection_decision(action=append|continue|finish, ...) 提交本轮反思决策。"
                    )
                    continue
                break

            for tool_call in result.tool_calls:
                tool_name = tool_call.get("name", "")
                tool_args = tool_call.get("args", {})
                tool_id = tool_call.get("id", "")

                if tool_name == "mark_reflection_decision":
                    try:
                        mark_reflection_decision(**tool_args)
                        ack = json.dumps(
                            {
                                "ok": True,
                                "action": decision_state["action"],
                                "reason": decision_state["reason"],
                                "missing_function_identifiers": decision_state["missing_function_identifiers"],
                            },
                            ensure_ascii=False,
                        )
                        await orchestrator.message_manager.add_tool_message(
                            content=ack,
                            tool_name=tool_name,
                            tool_call_id=tool_id,
                        )
                    except Exception as e:
                        error_msg = f"mark_reflection_decision 参数错误: {str(e)}"
                        error_content = json.dumps({"error": error_msg}, ensure_ascii=False)
                        await orchestrator.message_manager.add_tool_message(
                            content=error_content,
                            tool_name=tool_name,
                            tool_call_id=tool_id,
                        )
                    continue

                if tool_name not in allowed_tools:
                    error_msg = f"反思检查点不支持调用 {tool_name}"
                    error_content = json.dumps({"error": error_msg}, ensure_ascii=False)
                    await orchestrator.message_manager.add_tool_message(
                        content=error_content,
                        tool_name=tool_name,
                        tool_call_id=tool_id,
                    )
                    continue

                if tool_name == "delegate_task" and tool_args.get("agent_type") != "code_explorer":
                    error_msg = "反思检查点仅允许 delegate_task(agent_type=\"code_explorer\")"
                    error_content = json.dumps({"error": error_msg}, ensure_ascii=False)
                    await orchestrator.message_manager.add_tool_message(
                        content=error_content,
                        tool_name=tool_name,
                        tool_call_id=tool_id,
                    )
                    continue

                if tool_name == "plan_tasks":
                    error_msg = "反思检查点禁止调用 plan_tasks"
                    error_content = json.dumps({"error": error_msg}, ensure_ascii=False)
                    await orchestrator.message_manager.add_tool_message(
                        content=error_content,
                        tool_name=tool_name,
                        tool_call_id=tool_id,
                    )
                    continue

                try:
                    result_data = await orchestrator._execute_tool(tool_name, tool_args)
                    content, summary = self._normalize_tool_output(result_data)
                    await orchestrator.message_manager.add_tool_message(
                        content=content,
                        summary=summary,
                        tool_name=tool_name,
                        tool_call_id=tool_id,
                    )
                    if tool_name == "append_tasks":
                        append_called = True
                        added_count = self._extract_added_tasks_count(result_data)
                        if added_count is not None and added_count > 0:
                            appended = True
                        elif added_count == 0:
                            await orchestrator.message_manager.add_user_message(
                                "append_tasks 本轮未新增任务（added_count=0），请勿重复提交相同任务，需基于缺口补充新任务。"
                            )
                        else:
                            await orchestrator.message_manager.add_user_message(
                                "append_tasks 必须返回结构化字段 meta.added_tasks（整数）用于收敛判定，请修正后再继续。"
                            )
                except Exception as e:
                    error_msg = f"反思检查点工具调用失败: {str(e)}"
                    error_content = json.dumps({"error": error_msg}, ensure_ascii=False)
                    await orchestrator.message_manager.add_tool_message(
                        content=error_content,
                        tool_name=tool_name,
                        tool_call_id=tool_id,
                    )

            if decision_state["called"]:
                break

        current_tasks = task_manager.get_all_tasks()
        has_unfinished = any(
            t.status in (TaskStatus.PENDING, TaskStatus.IN_PROGRESS)
            for t in current_tasks
        )
        missing = [str(x).strip() for x in (decision_state["missing_function_identifiers"] or []) if str(x).strip()]
        merged_missing = list(dict.fromkeys(missing))

        if not decision_state["called"]:
            fallback_action = "continue" if has_unfinished else "finish"
            fallback_reason = "反思检查点未提交结构化决策，已按任务看板状态自动判定。"
            return {
                "action": fallback_action,
                "appended": appended,
                "reason": fallback_reason,
                "missing_function_identifiers": merged_missing,
            }

        action = str(decision_state["action"] or "continue").strip().lower()
        reason_text = str(decision_state["reason"] or "").strip()

        if action == "append" and not appended:
            action = "continue" if has_unfinished else "finish"
            if not reason_text:
                reason_text = "已申请追加任务，但 append_tasks 未新增任务，改为继续执行。"

        if appended and action != "append":
            action = "append"
            if not reason_text:
                reason_text = "本轮已追加任务，进入追加执行阶段。"

        if action == "finish" and has_unfinished:
            action = "continue"
            reason_text = (
                "反思决策申请结束，但任务看板仍有未完成项，已按硬门禁自动改为 continue。"
            )

        if append_called and not appended:
            self._log("反思检查点调用 append_tasks 但未新增任务（幂等去重生效）", "warning")

        return {
            "action": action,
            "appended": appended,
            "reason": reason_text,
            "missing_function_identifiers": merged_missing,
        }

    async def _run_agentic_cycle(
        self,
        orchestrator: Any,
        workflow_context: WorkflowContext,
    ) -> MasterOrchestratorResult:
        """
        统一 Agentic 控制环：Plan -> Act -> Review -> (Append/Stop)
        """
        cycle_start = time.time()
        errors: List[str] = []
        review_round = 0
        max_review_rounds = 3
        final_followup_round = 0
        max_final_followup_rounds = 2
        cycle_converged = False

        await self._guide_planning(orchestrator, workflow_context)

        workflows = orchestrator.tools_manager.get_planned_workflows()
        if not workflows:
            raise ValueError("未获取到 workflow 规划结果，无法执行。")

        self._log(f"检测到 {len(workflows)} 个 workflow")
        aggregate_execution_time = 0.0
        aggregate_workflow_results: List[Dict[str, Any]] = []

        base_result = await self._execute_multi_workflows(
            workflows,
            self.engine,
            workflow_context,
            execution_phase="base",
        )
        aggregate_execution_time += base_result.execution_time
        errors.extend(base_result.errors or [])
        aggregate_workflow_results = self._merge_workflow_results(
            aggregate_workflow_results,
            base_result.workflow_results or [],
        )

        while True:
            task_manager = self._load_task_list_manager()
            stop_ready = self._should_stop_cycle(task_manager)

            if stop_ready:
                cycle_converged = True
                break

            if review_round >= max_review_rounds:
                errors.append(
                    f"达到最大回顾轮次 {max_review_rounds}，仍存在未完成漏洞挖掘闭环。"
                )
                break

            review_round += 1
            self._log(f"进入回顾轮次 {review_round}/{max_review_rounds}", "warning")
            reflection = await self._run_reflection_checkpoint(
                orchestrator=orchestrator,
                workflows=workflows,
                round_id=review_round,
                max_rounds=max_review_rounds,
                final_check=False,
                reason="执行后反思：判断是否需要补任务或继续取证。",
            )
            appended = bool(reflection.get("appended"))

            updated_workflows = orchestrator.tools_manager.get_planned_workflows() or workflows
            workflows = updated_workflows
            pending_workflows = self._filter_workflows_with_pending_tasks(workflows)

            if not pending_workflows:
                if not appended:
                    self._log("回顾未追加任务，继续下一轮判断是否已收敛", "warning")
                continue

            group_labels = [
                f"{wf.get('workflow_id')}({wf.get('_pending_task_count', 0)})"
                for wf in pending_workflows
            ]
            self._log(
                "回顾后执行待处理 workflow -> " + ", ".join(group_labels)
            )
            followup_result = await self._execute_multi_workflows(
                pending_workflows,
                self.engine,
                workflow_context,
                execution_phase="post_review_append",
            )
            aggregate_execution_time += followup_result.execution_time
            errors.extend(followup_result.errors or [])
            aggregate_workflow_results = self._merge_workflow_results(
                aggregate_workflow_results,
                followup_result.workflow_results or [],
            )

        # 最终反思确认：沿用同一检查点流程（不再拆分独立审计流程）。
        final_reflection: Dict[str, Any] = {
            "action": "finish",
            "appended": False,
            "reason": "",
            "missing_function_identifiers": [],
        }
        while True:
            final_reason = (
                "闭环满足，执行最终反思确认。"
                if cycle_converged
                else "闭环未收敛，执行失败前最终反思确认。"
            )
            self._log(f"[FinalReflection] {final_reason}")
            final_reflection = await self._run_reflection_checkpoint(
                orchestrator=orchestrator,
                workflows=workflows,
                round_id=review_round + 1,
                max_rounds=max_review_rounds + max_final_followup_rounds,
                final_check=True,
                reason=final_reason,
            )
            action = str(final_reflection.get("action", "continue") or "continue").strip().lower()
            if action == "finish":
                break

            if final_followup_round >= max_final_followup_rounds:
                errors.append(
                    f"最终反思连续 {max_final_followup_rounds} 轮仍要求继续，未收敛。"
                )
                cycle_converged = False
                break

            if review_round >= max_review_rounds:
                errors.append(
                    f"最终反思要求继续，但已达到最大回顾轮次 {max_review_rounds}，无法继续执行。"
                )
                cycle_converged = False
                break

            final_followup_round += 1
            review_round += 1
            self._log(
                f"[FinalReflection] 反思要求继续，进入补充轮次 {final_followup_round}/{max_final_followup_rounds}",
                "warning",
            )
            appended = bool(final_reflection.get("appended"))

            updated_workflows = orchestrator.tools_manager.get_planned_workflows() or workflows
            workflows = updated_workflows
            pending_workflows = self._filter_workflows_with_pending_tasks(workflows)

            if pending_workflows:
                group_labels = [
                    f"{wf.get('workflow_id')}({wf.get('_pending_task_count', 0)})"
                    for wf in pending_workflows
                ]
                self._log(
                    "[FinalReflection] 补充轮次执行待处理 workflow -> " + ", ".join(group_labels)
                )
                followup_result = await self._execute_multi_workflows(
                    pending_workflows,
                    self.engine,
                    workflow_context,
                    execution_phase="post_review_append",
                )
                aggregate_execution_time += followup_result.execution_time
                errors.extend(followup_result.errors or [])
                aggregate_workflow_results = self._merge_workflow_results(
                    aggregate_workflow_results,
                    followup_result.workflow_results or [],
                )
            elif not appended:
                self._log(
                    "[FinalReflection] 反思要求继续，但本轮未新增任务，继续下一轮确认。",
                    "warning",
                )

            task_manager = self._load_task_list_manager()
            cycle_converged = self._should_stop_cycle(task_manager)

        if str(final_reflection.get("action", "") or "").lower() != "finish":
            cycle_converged = False

        if not aggregate_workflow_results:
            aggregate_workflow_results = base_result.workflow_results or []

        completed_workflows = sum(
            1 for item in aggregate_workflow_results
            if isinstance(item, dict) and item.get("success", False)
        )
        total_workflows = len(aggregate_workflow_results) or len(workflows)
        total_vulns = sum(
            item.get("vulnerabilities_found", 0)
            for item in aggregate_workflow_results
            if isinstance(item, dict)
        )

        summary = self._generate_multi_workflow_summary(
            workflows=workflows,
            workflow_results=aggregate_workflow_results,
            execution_time=aggregate_execution_time,
        )

        self.artifact_store.put_text(
            content=summary,
            kind="multi_workflow_summary",
            summary="多 workflow 汇总摘要",
            workflow_id="master",
            producer="master_orchestrator",
            metadata={
                "kind": "multi_workflow_summary",
                "session_id": self.session_id,
            },
        )

        if not cycle_converged:
            self._log("Agentic 循环未收敛，按失败返回", "warning")

        return MasterOrchestratorResult(
            success=cycle_converged and completed_workflows == total_workflows,
            total_workflows=total_workflows,
            completed_workflows=completed_workflows,
            total_vulnerabilities=total_vulns,
            execution_time=aggregate_execution_time or (time.time() - cycle_start),
            summary=summary,
            workflow_results=aggregate_workflow_results,
            errors=errors,
        )

    def _filter_workflows_with_pending_tasks(
        self,
        workflows: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """筛选仍有待执行任务的 workflow 列表，并附加 pending 摘要。"""
        task_manager = self._load_task_list_manager()
        all_tasks = task_manager.get_all_tasks()
        pending_by_group: Dict[str, List[Any]] = {}
        for task in all_tasks:
            if not task.task_group:
                continue
            if task.status not in (TaskStatus.PENDING, TaskStatus.IN_PROGRESS):
                continue
            pending_by_group.setdefault(task.task_group, []).append(task)

        if not pending_by_group:
            return []

        filtered: List[Dict[str, Any]] = []
        for wf in workflows:
            workflow_id = wf.get("workflow_id")
            pending_tasks = pending_by_group.get(workflow_id, [])
            if not pending_tasks:
                continue
            pending_preview = [t.description for t in pending_tasks[:3]]
            pending_count = len(pending_tasks)
            wf_copy = dict(wf)
            wf_copy["_execution_phase"] = "post_review_append"
            wf_copy["_pending_task_count"] = pending_count
            wf_copy["_pending_task_preview"] = pending_preview
            if pending_preview:
                preview_text = "；".join(pending_preview)
                wf_copy["_workflow_run_goal"] = (
                    f"执行回顾阶段追加任务（待执行 {pending_count} 项）：{preview_text}"
                )
            else:
                wf_copy["_workflow_run_goal"] = f"执行回顾阶段追加任务（待执行 {pending_count} 项）"
            filtered.append(wf_copy)
        return filtered

    @staticmethod
    def _merge_workflow_results(
        base_results: List[Dict[str, Any]],
        extra_results: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """合并 workflow 执行结果（以 workflow_id 为键覆盖）"""
        merged = {item.get("workflow_id"): item for item in base_results if isinstance(item, dict)}
        for item in extra_results:
            if isinstance(item, dict):
                merged[item.get("workflow_id")] = item
        return list(merged.values())
    async def _execute_multi_workflows(
        self,
        workflows: List[Dict[str, Any]],
        engine: BaseStaticAnalysisEngine,
        workflow_context: WorkflowContext,
        execution_phase: str = "base",
    ) -> MasterOrchestratorResult:
        """执行多个独立的 workflow

        Args:
            workflows: 规划的 workflow 列表
            engine: 已初始化的引擎实例
            workflow_context: 原始 workflow 上下文

        Returns:
            MasterOrchestratorResult: 汇总的执行结果
        """
        start_time = time.time()
        errors = []

        try:
            phase_label = "追加任务执行" if execution_phase == "post_review_append" else "常规执行"
            # 1. 为每个 workflow 创建独立的 TaskExecutorAgent
            self._log(f"[{phase_label}] 创建 {len(workflows)} 个 TaskExecutorAgent...")
            workflow_agents = []

            for wf in workflows:
                # 创建独立的 TaskExecutorAgent
                from .task_executor_agent import TaskExecutorAgent

                agent = TaskExecutorAgent(
                    task_group=wf['workflow_id'],
                    workflow_name=wf['workflow_name'],
                    goal=wf.get("_workflow_run_goal", wf.get('workflow_description', wf['workflow_name'])),
                    llm_client=self.llm_client,
                    engine=engine,
                    session_dir=self.session_dir,
                    source_root=self.source_root,
                    verbose=self.verbose,
                    enable_logging=self.enable_logging,
                    execution_phase=wf.get("_execution_phase", execution_phase),
                )

                workflow_agents.append((wf, agent))
                pending_count = wf.get("_pending_task_count")
                if pending_count is not None:
                    self._log(
                        f"  - 创建 TaskExecutorAgent: {wf['workflow_name']} "
                        f"(task_group: {wf['workflow_id']}, pending={pending_count})"
                    )
                else:
                    self._log(f"  - 创建 TaskExecutorAgent: {wf['workflow_name']} (task_group: {wf['workflow_id']})")

            # 2. 根据执行模式执行
            execution_mode = workflows[0].get("execution_mode", "sequential") if workflows else "sequential"
            self._log(f"[{phase_label}] 执行模式: {execution_mode}")

            if execution_mode == "parallel":
                # 并行执行
                self._log(f"[{phase_label}] 并行执行所有 TaskExecutorAgent...")
                tasks = [
                    agent.run()  # 调用 TaskExecutorAgent.run()
                    for wf, agent in workflow_agents
                ]
                results = await asyncio.gather(*tasks, return_exceptions=True)

                # 处理异常
                workflow_results = []
                for i, result in enumerate(results):
                    if isinstance(result, Exception):
                        wf = workflow_agents[i][0]
                        error_msg = f"Workflow {wf['workflow_name']} 执行异常: {str(result)}"
                        self._log(error_msg, "error")
                        errors.append(error_msg)

                        # 创建失败结果
                        workflow_results.append({
                            "workflow_id": wf["workflow_id"],
                            "workflow_name": wf["workflow_name"],
                            "success": False,
                            "completed_tasks": 0,
                            "total_tasks": len(wf["tasks"]),
                            "vulnerabilities_found": 0,
                            "execution_time": 0.0,
                            "summary": error_msg,
                            "errors": [str(result)],
                        })
                    else:
                        # 将 WorkflowResult 转换为字典
                        workflow_results.append({
                            "workflow_id": result.task_group,
                            "workflow_name": result.workflow_name,
                            "success": result.success,
                            "completed_tasks": result.completed_tasks,
                            "total_tasks": result.total_tasks,
                            "vulnerabilities_found": result.vulnerabilities_found,
                            "execution_time": result.execution_time,
                            "summary": result.summary,
                            "errors": result.errors,
                        })
            else:
                # 串行执行
                self._log(f"[{phase_label}] 串行执行所有 TaskExecutorAgent...")
                workflow_results = []
                for wf, agent in workflow_agents:
                    pending_count = wf.get("_pending_task_count")
                    if pending_count is not None:
                        self._log(
                            f"[{phase_label}] 执行 Workflow: {wf['workflow_name']} "
                            f"(task_group={wf.get('workflow_id')}, pending={pending_count})"
                        )
                    else:
                        self._log(f"[{phase_label}] 执行 Workflow: {wf['workflow_name']}")
                    try:
                        result = await agent.run()  # 调用 TaskExecutorAgent.run()
                        
                        # 将 WorkflowResult 转换为字典
                        workflow_results.append({
                            "workflow_id": result.task_group,
                            "workflow_name": result.workflow_name,
                            "success": result.success,
                            "completed_tasks": result.completed_tasks,
                            "total_tasks": result.total_tasks,
                            "vulnerabilities_found": result.vulnerabilities_found,
                            "execution_time": result.execution_time,
                            "summary": result.summary,
                            "errors": result.errors,
                        })
                    except Exception as e:
                        error_msg = f"Workflow {wf['workflow_name']} 执行异常: {str(e)}"
                        self._log(error_msg, "error")
                        errors.append(error_msg)

                        # 创建失败结果
                        workflow_results.append({
                            "workflow_id": wf["workflow_id"],
                            "workflow_name": wf["workflow_name"],
                            "success": False,
                            "completed_tasks": 0,
                            "total_tasks": len(wf["tasks"]),
                            "vulnerabilities_found": 0,
                            "execution_time": 0.0,
                            "summary": error_msg,
                            "errors": [str(e)],
                        })

            # 3. 汇总结果
            end_time = time.time()
            execution_time = end_time - start_time

            total_vulnerabilities = sum(
                r.get("vulnerabilities_found", 0) if isinstance(r, dict) else r.vulnerabilities_found
                for r in workflow_results
            )
            completed_workflows = sum(
                1 for r in workflow_results
                if (r.get("success", False) if isinstance(r, dict) else r.success)
            )

            summary = self._generate_multi_workflow_summary(
                workflows=workflows,
                workflow_results=workflow_results,
                execution_time=execution_time,
            )

            # 保存摘要
            self.artifact_store.put_text(
                content=summary,
                kind="multi_workflow_summary",
                summary="多 workflow 汇总摘要",
                workflow_id="master",
                producer="master_orchestrator",
                metadata={
                    "kind": "multi_workflow_summary",
                    "session_id": self.session_id,
                    "execution_phase": execution_phase,
                },
            )

            self._log(f"[{phase_label}] 所有 workflow 执行完成", "success")

            return MasterOrchestratorResult(
                success=completed_workflows == len(workflows),
                total_workflows=len(workflows),
                completed_workflows=completed_workflows,
                total_vulnerabilities=total_vulnerabilities,
                execution_time=execution_time,
                summary=summary,
                workflow_results=workflow_results,
                errors=errors,
            )

        except Exception as e:
            error_msg = f"多 workflow 执行失败: {str(e)}"
            self._log(error_msg, "error")
            errors.append(error_msg)

            end_time = time.time()
            execution_time = end_time - start_time

            return MasterOrchestratorResult(
                success=False,
                total_workflows=len(workflows),
                completed_workflows=0,
                total_vulnerabilities=0,
                execution_time=execution_time,
                summary=error_msg,
                workflow_results=[],
                errors=errors,
            )
    
    def _generate_multi_workflow_summary(
        self,
        workflows: List[Dict[str, Any]],
        workflow_results: List[Dict[str, Any]],
        execution_time: float,
    ) -> str:
        """生成多 workflow 执行摘要
        
        Args:
            workflows: Workflow 信息列表
            workflow_results: 执行结果列表
            execution_time: 总执行时间
            
        Returns:
            str: Markdown 格式的摘要
        """
        lines = [
            f"# 多 Workflow 执行摘要",
            "",
            f"**Session ID**: {self.session_id}",
            f"**总执行时间**: {execution_time:.2f}s",
            "",
            "## 执行统计",
            "",
            f"- 总 Workflow 数: {len(workflow_results)}",
        ]
        
        # 统计成功/失败
        success_count = sum(
            1 for r in workflow_results 
            if (r.get("success", False) if isinstance(r, dict) else r.success)
        )
        failed_count = len(workflow_results) - success_count
        
        lines.extend([
            f"- 成功: {success_count}",
            f"- 失败: {failed_count}",
        ])
        
        # 统计漏洞
        total_vulnerabilities = sum(
            r.get("vulnerabilities_found", 0) if isinstance(r, dict) else r.vulnerabilities_found
            for r in workflow_results
        )
        lines.append(f"- 总漏洞数: {total_vulnerabilities}")
        lines.append("")
        
        # 详细结果
        lines.append("## Workflow 详情")
        lines.append("")
        
        for i, result in enumerate(workflow_results, 1):
            if isinstance(result, dict):
                success = result.get("success", False)
                workflow_name = result.get("workflow_name", "Unknown")
                workflow_id = result.get("workflow_id", "unknown")
                completed = result.get("completed_tasks", 0)
                total = result.get("total_tasks", 0)
                vulns = result.get("vulnerabilities_found", 0)
                exec_time = result.get("execution_time", 0.0)
            else:
                success = result.success
                workflow_name = result.workflow_name
                workflow_id = result.task_group
                completed = result.completed_tasks
                total = result.total_tasks
                vulns = result.vulnerabilities_found
                exec_time = result.execution_time
            
            status = "✅" if success else "❌"
            
            lines.extend([
                f"### {i}. {workflow_name} {status}",
                "",
                f"- Workflow ID: {workflow_id}",
                f"- 完成任务: {completed}/{total}",
                f"- 发现漏洞: {vulns}",
                f"- 执行时间: {exec_time:.2f}s",
                "",
            ])
        
        return "\n".join(lines)
    
    def _build_planning_prompt(self, workflow_context: WorkflowContext) -> str:
        """构建规划 prompt

        Args:
            workflow_context: Workflow 上下文

        Returns:
            规划 prompt 字符串
        """
        return build_planning_user_prompt(workflow_context)
    
    def _get_planning_system_prompt(self) -> str:
        """获取规划阶段的 system prompt

        Returns:
            System prompt 字符串
        """
        return build_master_planning_system_prompt()

    
    async def execute_workflow(self, workflow_path: str, target_path: str = None) -> MasterOrchestratorResult:
        """执行 Workflow 文档
        
        流程：
        1. 解析 workflow 文档
        2. 初始化引擎
        3. 创建 TaskOrchestratorAgent
        4. 执行 Agentic 控制环（Plan -> Act -> Review -> Append/Stop）
        5. 返回汇总结果
        """
        start_time = time.time()
        errors = []
        
        try:
            # 1. 解析 workflow 文档
            self._log(f"读取 Workflow 文档: {workflow_path}")
            parser = WorkflowParser()
            self.workflow_context = parser.parse_and_validate(workflow_path)
            
            self._log(f"Workflow 名称: {self.workflow_context.name}")
            
            # 保存原始 workflow 文档
            self.artifact_store.put_text(
                content=self.workflow_context.raw_markdown,
                kind="master_workflow_source",
                summary=self.workflow_context.name or "workflow",
                workflow_id="master",
                producer="master_orchestrator",
                metadata={
                    "kind": "master_workflow_source",
                    "workflow_name": self.workflow_context.name,
                },
            )
            
            # 2. 初始化引擎
            final_target = target_path or self.target_path or (
                self.workflow_context.target.path 
                if self.workflow_context.target and self.workflow_context.target.path 
                else None
            )
            
            if not final_target:
                raise ValueError("目标路径未指定")
            
            if not self.engine_type:
                raise ValueError("引擎类型未指定")
            
            self._log(f"初始化引擎: {self.engine_type}")
            
            self.engine = create_engine(
                engine_type=self.engine_type,
                target_path=final_target,
                source_root=self.source_root,
                max_concurrency=10,
                llm_client=self.llm_client,
                logger=self._logger,
            )
            
            initialized = await self.engine.initialize()
            if not initialized:
                raise ValueError(f"引擎初始化失败: {self.engine_type}")
            
            self._log("引擎初始化成功", "success")
            
            # 3. 创建 TaskOrchestratorAgent
            self._log("创建 TaskOrchestratorAgent...")
            from .orchestrator_agent import TaskOrchestratorAgent
            
            orchestrator = TaskOrchestratorAgent(
                llm_client=self.llm_client,
                engine_type=self.engine_type,
                target_path=final_target,
                source_root=self.source_root,
                workflow_context=self.workflow_context,
                session_id=self.session_id,
                verbose=self.verbose,
                enable_logging=self.enable_logging,
            )
            
            # 复用已初始化的引擎
            orchestrator.tools_manager.engine = self.engine
            orchestrator.tools_manager._initialized = True
            # 重新初始化编排组件，确保 AgentDelegate 被创建
            orchestrator._init_orchestrator_components(emit_log=False)

            self._log("启动 Agentic 控制环...")
            result = await self._run_agentic_cycle(orchestrator, self.workflow_context)
            if result.execution_time <= 0:
                result.execution_time = time.time() - start_time
            return result
        
        except Exception as e:
            error_msg = f"执行失败: {str(e)}"
            self._log(error_msg, "error")
            errors.append(error_msg)
            
            end_time = time.time()
            execution_time = end_time - start_time
            
            return MasterOrchestratorResult(
                success=False,
                total_workflows=0,
                completed_workflows=0,
                total_vulnerabilities=0,
                execution_time=execution_time,
                summary=f"执行失败: {str(e)}",
                workflow_results=[],
                errors=errors,
            )


async def run_master_workflow(
    workflow_path: str,
    llm_client: ChatOpenAI,
    engine_type: str,
    target_path: str,
    source_root: Optional[str] = None,
    session_id: Optional[str] = None,
    execution_mode: str = "sequential",
    verbose: bool = True,
    enable_logging: bool = True,
) -> MasterOrchestratorResult:
    """便捷函数：执行多 Workflow 模式"""
    master = MasterOrchestrator(
        llm_client=llm_client,
        engine_type=engine_type,
        target_path=target_path,
        source_root=source_root,
        session_id=session_id,
        execution_mode=execution_mode,
        verbose=verbose,
        enable_logging=enable_logging,
    )
    return await master.execute_workflow(workflow_path, target_path=target_path)


__all__ = [
    "MasterOrchestrator",
    "MasterOrchestratorResult",
    "run_master_workflow",
]
