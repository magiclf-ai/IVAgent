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
from langchain_core.messages import HumanMessage

from ..models.workflow import WorkflowContext
from ..engines import create_engine, BaseStaticAnalysisEngine
from ..core import ToolBasedLLMClient
from .workflow_parser import WorkflowParser
from .planning_prompts import (
    build_planning_user_prompt,
    build_master_planning_system_prompt,
)
from .task_list_manager import TaskListManager, TaskStatus


@dataclass
class SubWorkflowInfo:
    """子 Workflow 信息"""
    id: str
    name: str
    description: str
    tasks: List[Dict[str, Any]]


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
        
        self.engine: Optional[BaseStaticAnalysisEngine] = None
        self.workflow_context: Optional[WorkflowContext] = None
        self.sub_workflows: List[SubWorkflowInfo] = []
        
        self.session_dir = self._resolve_session_dir()
        self.session_dir.mkdir(parents=True, exist_ok=True)
        
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
        if self.verbose:
            prefix = "[MasterOrchestrator]"
            if level == "error":
                print(f"[X] {prefix} {message}")
            elif level == "warning":
                print(f"[!] {prefix} {message}")
            elif level == "success":
                print(f"[+] {prefix} {message}")
            else:
                print(f"[*] {prefix} {message}")

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
        last_recoverable_error: Optional[Dict[str, Any]] = None
        allowed_tools = {
            "plan_tasks",
            "delegate_task",
            "read_artifact",
            "get_task_status",
            "read_task_output",
            "resolve_function_identifier",
            "set_task_function_identifier",
        }

        def _extract_recoverable_error(content: str) -> Optional[Dict[str, Any]]:
            if not content or "```json" not in content:
                return None
            try:
                start = content.index("```json") + len("```json")
                end = content.index("```", start)
                raw = content[start:end].strip()
                payload = json.loads(raw)
                if isinstance(payload, dict) and payload.get("recoverable") is True:
                    return payload
            except Exception:
                return None
            return None

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
                if last_recoverable_error:
                    self._log("LLM 未按要求修复可恢复错误，继续引导", "warning")
                    error_code = last_recoverable_error.get("error_code", "")
                    await orchestrator.message_manager.add_user_message(
                        "上轮工具返回可恢复错误，必须按 required_next_actions 修复后再继续规划。"
                        f"错误码: {error_code}。"
                    )
                    continue
                self._log("LLM 未调用 plan_tasks，使用默认规划", "warning")
                break

            for tool_call in result.tool_calls:
                tool_name = tool_call.get("name", "")
                tool_args = tool_call.get("args", {})
                tool_id = tool_call.get("id", "")

                if tool_name == "plan_tasks":
                    self._log(f"执行 Tool: {tool_name}")
                    try:
                        result_data = await orchestrator._execute_tool(tool_name, tool_args)
                        content, summary = self._normalize_tool_output(result_data)
                        await orchestrator.message_manager.add_tool_message(
                            content=content,
                            summary=summary,
                            tool_name=tool_name,
                            tool_call_id=tool_id,
                        )
                        last_recoverable_error = _extract_recoverable_error(content)
                        planned_workflows = None
                        if getattr(orchestrator, "tools_manager", None):
                            planned_workflows = orchestrator.tools_manager.get_planned_workflows()
                        if planned_workflows:
                            self._log("规划完成", "success")
                            planned = True
                            last_recoverable_error = None
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

                self._log(f"执行 Tool: {tool_name}")
                try:
                    result_data = await orchestrator._execute_tool(tool_name, tool_args)
                    content, summary = self._normalize_tool_output(result_data)
                    await orchestrator.message_manager.add_tool_message(
                        content=content,
                        summary=summary,
                        tool_name=tool_name,
                        tool_call_id=tool_id,
                    )
                    recoverable = _extract_recoverable_error(content)
                    if recoverable:
                        last_recoverable_error = recoverable
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

    def _needs_post_execution_review(self, task_manager: TaskListManager) -> bool:
        """判断是否需要执行后回顾（未执行过 vuln_analysis 即触发）"""
        tasks = task_manager.get_all_tasks()
        if not tasks:
            return False
        vuln_tasks = [t for t in tasks if t.agent_type == "vuln_analysis"]
        completed_vuln = [t for t in vuln_tasks if t.status == TaskStatus.COMPLETED]
        return len(completed_vuln) == 0

    def _collect_completed_code_explorer_summaries(
        self,
        tasks: List[Any],
        max_items: int = 3,
    ) -> List[str]:
        """收集已完成 code_explorer 任务摘要，供回顾阶段复用。"""
        summaries: List[str] = []
        artifacts_dir = self.session_dir / "artifacts"
        if not artifacts_dir.exists():
            return summaries

        completed_code = [
            t for t in tasks
            if t.agent_type == "code_explorer" and t.status == TaskStatus.COMPLETED
        ]
        for task in completed_code[:max_items]:
            summary_path = artifacts_dir / f"{task.id}_output.summary.md"
            if not summary_path.exists():
                continue
            try:
                summary_text = summary_path.read_text(encoding="utf-8").strip()
            except Exception:
                continue
            if not summary_text:
                continue
            summaries.append(
                "\n".join([
                    f"### {task.id}",
                    summary_text,
                ])
            )
        return summaries

    def _build_post_execution_review_prompt(
        self,
        tasks: List[Any],
        workflows: List[Dict[str, Any]],
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
            "请评估是否需要追加漏洞挖掘任务。",
            "若未执行过漏洞挖掘任务，必须追加 `vuln_analysis` 任务。",
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
                "以下摘要来自已完成任务，请先据此追加 `vuln_analysis`，仅在函数标识符缺失时再调用 `delegate_task(code_explorer)`。",
                "",
            ])
            for item in code_summaries:
                lines.append(item)
                lines.append("")

        lines.extend([
            "",
            "## 追加规划要求",
            "",
            "1. 仅能使用 `append_tasks(workflows)` 追加任务，不能调用 `plan_tasks`。",
            "2. 先复用已完成 `code_explorer` 输出；仅在缺少 function_identifier 时再使用 `delegate_task(agent_type=\"code_explorer\")` 获取标准标识符。",
            "3. `vuln_analysis` 任务必须提供 `function_identifier` 与 `analysis_context`。",
            "4. `analysis_context` 必须包含固定章节：目标函数、攻击者可控性、输入与边界约束、全局/状态/认证约束、风险操作与漏洞假设、可利用性前提、证据锚点、未知项与待验证。",
            "5. 若 `analysis_context` 缺少可控性/边界约束/证据锚点，先补工具调用取证再追加任务。",
            "6. 追加任务必须指定正确的 `workflow_id`（即 task_group）。",
            "7. 只输出工具调用，不输出其他文本。",
        ])

        return "\n".join(lines)

    def _get_post_execution_review_system_prompt(self) -> str:
        """执行后回顾阶段系统提示词"""
        return """# 角色定义

你是一个执行后回顾规划器，目标是补齐漏洞挖掘闭环任务。
你可以在内部思考，但不要输出思考过程。
最终输出必须是工具调用。

# 约束

- 只允许追加任务：使用 `append_tasks(workflows)`。
- 优先复用现有已完成 `code_explorer` 输出；仅在缺少 function_identifier 时才调用 `delegate_task(agent_type="code_explorer")`。
- 追加的 `vuln_analysis` 必须提供 `function_identifier` 与 `analysis_context`。
- `analysis_context` 必须包含以下章节（标题不可省略）：
  - `## 目标函数`
  - `## 攻击者可控性`
  - `## 输入与边界约束`
  - `## 全局/状态/认证约束`
  - `## 风险操作与漏洞假设`
  - `## 可利用性前提`
  - `## 证据锚点`
  - `## 未知项与待验证`
- 质量门禁：若缺少可控性、边界约束或证据锚点，不得追加 `vuln_analysis`，应先补工具调用取证。
- 禁止调用 `plan_tasks`。
"""

    async def _guide_post_execution_review(
        self,
        orchestrator: Any,
        workflows: List[Dict[str, Any]],
    ) -> bool:
        """执行后回顾并尝试追加任务，返回是否追加成功"""
        task_manager = self._load_task_list_manager()
        tasks = task_manager.get_all_tasks()
        if not tasks:
            return False

        prompt = self._build_post_execution_review_prompt(tasks, workflows)
        await orchestrator.message_manager.add_user_message(prompt)

        allowed_tools = {
            "append_tasks",
            "delegate_task",
            "read_artifact",
            "get_task_status",
            "read_task_output",
            "resolve_function_identifier",
            "set_task_function_identifier",
        }

        def _extract_recoverable_error(content: str) -> Optional[Dict[str, Any]]:
            if not content or "```json" not in content:
                return None
            try:
                start = content.index("```json") + len("```json")
                end = content.index("```", start)
                raw = content[start:end].strip()
                payload = json.loads(raw)
                if isinstance(payload, dict) and payload.get("recoverable") is True:
                    return payload
            except Exception:
                return None
            return None

        max_rounds = 5
        appended = False
        last_recoverable_error: Optional[Dict[str, Any]] = None
        total_before = len(tasks)

        for _ in range(max_rounds):
            assembled_messages = await orchestrator.context_assembler.build_messages(
                system_prompt=self._get_post_execution_review_system_prompt(),
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
                if last_recoverable_error:
                    await orchestrator.message_manager.add_user_message(
                        "上轮工具返回可恢复错误，必须按 required_next_actions 修复后再继续追加。"
                    )
                    continue
                break

            for tool_call in result.tool_calls:
                tool_name = tool_call.get("name", "")
                tool_args = tool_call.get("args", {})
                tool_id = tool_call.get("id", "")

                if tool_name not in allowed_tools:
                    error_msg = f"回顾阶段不支持调用 {tool_name}"
                    error_content = json.dumps({"error": error_msg}, ensure_ascii=False)
                    await orchestrator.message_manager.add_tool_message(
                        content=error_content,
                        tool_name=tool_name,
                        tool_call_id=tool_id,
                    )
                    continue

                if tool_name == "delegate_task" and tool_args.get("agent_type") != "code_explorer":
                    error_msg = "回顾阶段仅允许 delegate_task(agent_type=\"code_explorer\")"
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
                    recoverable = _extract_recoverable_error(content)
                    if recoverable:
                        last_recoverable_error = recoverable
                    if tool_name == "append_tasks":
                        task_manager = self._load_task_list_manager()
                        total_after = task_manager.get_statistics().get("total", 0)
                        if total_after > total_before:
                            appended = True
                            total_before = total_after
                except Exception as e:
                    error_msg = f"回顾阶段工具调用失败: {str(e)}"
                    error_content = json.dumps({"error": error_msg}, ensure_ascii=False)
                    await orchestrator.message_manager.add_tool_message(
                        content=error_content,
                        tool_name=tool_name,
                        tool_call_id=tool_id,
                    )

            if appended:
                break

        return appended

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
            summary_file = self.session_dir / "multi_workflow_summary.md"
            summary_file.write_text(summary, encoding="utf-8")

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
    
    def _create_sub_workflow_context(
        self,
        workflow_context: WorkflowContext,
        workflow_info: Dict[str, Any]
    ) -> WorkflowContext:
        """为子 workflow 创建 WorkflowContext
        
        Args:
            workflow_context: 原始 workflow 上下文
            workflow_info: 子 workflow 信息字典
            
        Returns:
            WorkflowContext: 子 workflow 的上下文
        """
        # 构建子 workflow 的 raw_markdown
        lines = [
            f"# {workflow_info.get('workflow_name', 'Sub Workflow')}",
            "",
            f"{workflow_info.get('workflow_description', '')}",
            "",
        ]
        
        if workflow_info.get("tasks"):
            lines.extend([
                "## 任务列表",
                "",
            ])
            for i, task in enumerate(workflow_info["tasks"], 1):
                if isinstance(task, dict):
                    desc = task.get("description", "")
                    agent_type = task.get("agent_type")
                    if agent_type:
                        lines.append(f"{i}. [{agent_type}] {desc}")
                    else:
                        lines.append(f"{i}. {desc}")
                else:
                    lines.append(f"{i}. {task}")
            lines.append("")
        
        raw_markdown = "\n".join(lines)
        
        # 创建新的 WorkflowContext，继承原始上下文的大部分信息
        sub_context = WorkflowContext(
            name=workflow_info.get("workflow_name", "Sub Workflow"),
            description=workflow_info.get("workflow_description", ""),
            version=workflow_context.version,
            target=workflow_context.target,
            scope=workflow_context.scope,
            strategy_hints=workflow_context.strategy_hints,
            vulnerability_focus=workflow_context.vulnerability_focus,
            background_knowledge=workflow_context.background_knowledge,
            raw_markdown=raw_markdown,
        )
        
        return sub_context
    
    async def _execute_single_workflow(
        self,
        orchestrator: Any
    ) -> MasterOrchestratorResult:
        """继续执行单 workflow（任务已规划）

        Args:
            orchestrator: TaskOrchestratorAgent 实例（已完成规划）

        Returns:
            MasterOrchestratorResult: 执行结果
        """
        start_time = time.time()
        errors = []

        try:
            # 任务列表已经通过 _guide_planning 创建，直接进入执行循环
            self._log("开始执行任务...")

            max_iterations = 20
            iteration = 0

            while True:
                iteration += 1
                self._log(f"执行迭代 {iteration}/{max_iterations}")

                # 检查是否超过最大迭代次数
                if iteration > max_iterations:
                    self._log(f"达到最大迭代次数 {max_iterations}，结束执行", "warning")
                    break

                # 组装上下文并调用 LLM
                assembled_messages = await orchestrator.context_assembler.build_messages(
                    system_prompt=orchestrator._get_simplified_system_prompt(),
                )

                result = await orchestrator.llm_client_wrapper.atool_call(
                    messages=assembled_messages,
                    tools=orchestrator.tools,
                    system_prompt=None,
                )

                # 记录 AI 消息
                await orchestrator.message_manager.add_ai_message(
                    result.content or "",
                    tool_calls=result.tool_calls,
                )

                # 检查是否有 Tool 调用
                if not result.tool_calls:
                    # 如果没有 tool calls，说明 LLM 认为任务已完成
                    self._log("LLM 完成执行，结束", "success")
                    break

                # 执行所有 Tool 调用
                for tool_call in result.tool_calls:
                    tool_name = tool_call.get("name", "")
                    tool_args = tool_call.get("args", {})
                    tool_id = tool_call.get("id", "")

                    self._log(f"Tool 调用: {tool_name}")

                    try:
                        result_data = await orchestrator._execute_tool(tool_name, tool_args)

                        if isinstance(result_data, dict) and result_data.get("error"):
                            self._log(f"Tool 错误: {result_data['error']}", "warning")
                            errors.append(f"{tool_name}: {result_data['error']}")

                        content, summary = self._normalize_tool_output(result_data)

                        await orchestrator.message_manager.add_tool_message(
                            content=content,
                            summary=summary,
                            tool_name=tool_name,
                            tool_call_id=tool_id,
                        )

                    except Exception as e:
                        error_msg = str(e)
                        self._log(f"Tool 执行失败: {error_msg}", "error")
                        errors.append(f"{tool_name}: {error_msg}")

                        error_content = json.dumps({"error": error_msg}, ensure_ascii=False)
                        await orchestrator.message_manager.add_tool_message(
                            content=error_content,
                            tool_name=tool_name,
                            tool_call_id=tool_id,
                        )

            # 汇总结果
            end_time = time.time()
            execution_time = end_time - start_time

            # 获取任务统计
            tasks = orchestrator.tools_manager._task_list_manager.get_all_tasks()
            total_tasks = len(tasks)
            completed_tasks = sum(1 for task in tasks if task.status == "completed")

            # 获取漏洞数量（如果有）
            vulnerabilities_found = 0
            # TODO: 从 orchestrator 的结果中提取漏洞数量

            # 生成摘要
            summary = f"""# 单 Workflow 执行摘要

## 执行统计

- **总任务数**: {total_tasks}
- **完成任务数**: {completed_tasks}
- **发现漏洞数**: {vulnerabilities_found}
- **执行时间**: {execution_time:.2f} 秒

## 任务列表

"""
            for i, task in enumerate(tasks, 1):
                status_icon = "✓" if task.status == "completed" else "✗"
                summary += f"{i}. [{status_icon}] {task.description} ({task.status})\n"

            if errors:
                summary += "\n## 错误信息\n\n"
                for error in errors:
                    summary += f"- {error}\n"

            # 保存摘要
            summary_file = self.session_dir / "single_workflow_summary.md"
            summary_file.write_text(summary, encoding="utf-8")

            self._log("单 workflow 执行完成", "success")

            return MasterOrchestratorResult(
                success=completed_tasks == total_tasks,
                total_workflows=1,
                completed_workflows=1 if completed_tasks == total_tasks else 0,
                total_vulnerabilities=vulnerabilities_found,
                execution_time=execution_time,
                summary=summary,
                workflow_results=[{
                    "workflow_id": "single_workflow",
                    "workflow_name": self.workflow_context.name if self.workflow_context else "Single Workflow",
                    "success": completed_tasks == total_tasks,
                    "completed_tasks": completed_tasks,
                    "total_tasks": total_tasks,
                    "vulnerabilities_found": vulnerabilities_found,
                    "execution_time": execution_time,
                    "summary": summary,
                    "errors": errors,
                }],
                errors=errors,
            )

        except Exception as e:
            error_msg = f"单 workflow 执行失败: {str(e)}"
            self._log(error_msg, "error")
            errors.append(error_msg)

            end_time = time.time()
            execution_time = end_time - start_time

            return MasterOrchestratorResult(
                success=False,
                total_workflows=1,
                completed_workflows=0,
                total_vulnerabilities=0,
                execution_time=execution_time,
                summary=error_msg,
                workflow_results=[],
                errors=errors,
            )
    
    async def _execute_workflow_agent(
        self,
        workflow_info: Dict[str, Any],
        agent: Any
    ) -> Dict[str, Any]:
        """执行单个 workflow agent
        
        Args:
            workflow_info: Workflow 信息字典
            agent: TaskOrchestratorAgent 实例（已初始化，引擎已设置）
            
        Returns:
            Dict: 执行结果字典
        """
        start_time = time.time()
        errors = []
        
        try:
            # 1. 调用 plan_tasks 创建任务列表
            self._log(f"规划 Workflow: {workflow_info['workflow_name']}")
            await agent.tools_manager.plan_tasks(workflows=[workflow_info])
            
            # 2. 获取任务列表
            tasks = agent.tools_manager._task_list_manager.get_all_tasks()
            
            if not tasks:
                return {
                    "workflow_id": workflow_info["workflow_id"],
                    "workflow_name": workflow_info["workflow_name"],
                    "success": False,
                    "completed_tasks": 0,
                    "total_tasks": 0,
                    "vulnerabilities_found": 0,
                    "execution_time": time.time() - start_time,
                    "summary": "没有任务需要执行",
                    "errors": [],
                }
            
            self._log(f"开始执行 {len(tasks)} 个任务...")
            
            # 3. 执行任务循环（复用 _execute_single_workflow 的逻辑）
            max_iterations = 20
            iteration = 0
            
            while True:
                iteration += 1
                
                # 检查是否超过最大迭代次数
                if iteration > max_iterations:
                    self._log(f"Workflow {workflow_info['workflow_name']} 达到最大迭代次数", "warning")
                    break
                
                # 组装上下文并调用 LLM
                assembled_messages = await agent.context_assembler.build_messages(
                    system_prompt=agent._get_simplified_system_prompt(),
                )
                
                result = await agent.llm_client_wrapper.atool_call(
                    messages=assembled_messages,
                    tools=agent.tools,
                    system_prompt=None,
                )
                
                # 记录 AI 消息
                await agent.message_manager.add_ai_message(
                    result.content or "",
                    tool_calls=result.tool_calls,
                )
                
                # 检查是否有 Tool 调用
                if not result.tool_calls:
                    self._log(f"Workflow {workflow_info['workflow_name']} 完成", "success")
                    break
                
                # 并发执行所有 Tool 调用
                async def execute_single_tool(tool_call: Dict[str, Any]):
                    """执行单个 tool call"""
                    tool_name = tool_call.get("name", "")
                    tool_args = tool_call.get("args", {})
                    tool_id = tool_call.get("id", "")
                    
                    try:
                        result_data = await agent._execute_tool(tool_name, tool_args)
                        
                        if isinstance(result_data, dict) and result_data.get("error"):
                            errors.append(f"{tool_name}: {result_data['error']}")
                        
                        content, summary = self._normalize_tool_output(result_data)
                        
                        await agent.message_manager.add_tool_message(
                            content=content,
                            summary=summary,
                            tool_name=tool_name,
                            tool_call_id=tool_id,
                        )
                        
                    except Exception as e:
                        error_msg = str(e)
                        errors.append(f"{tool_name}: {error_msg}")
                        
                        error_content = json.dumps({"error": error_msg}, ensure_ascii=False)
                        await agent.message_manager.add_tool_message(
                            content=error_content,
                            tool_name=tool_name,
                            tool_call_id=tool_id,
                        )
                
                # 并发执行所有 tool calls
                if result.tool_calls:
                    tool_tasks = [execute_single_tool(tc) for tc in result.tool_calls]
                    await asyncio.gather(*tool_tasks)
            
            # 4. 汇总结果
            end_time = time.time()
            execution_time = end_time - start_time
            
            # 获取任务统计
            tasks = agent.tools_manager._task_list_manager.get_all_tasks()
            total_tasks = len(tasks)
            completed_tasks = sum(1 for task in tasks if task.status.value == "completed")
            
            # 获取漏洞数量
            vulnerabilities_found = len(agent.tools_manager.vulnerabilities)
            
            return {
                "workflow_id": workflow_info["workflow_id"],
                "workflow_name": workflow_info["workflow_name"],
                "success": completed_tasks == total_tasks,
                "completed_tasks": completed_tasks,
                "total_tasks": total_tasks,
                "vulnerabilities_found": vulnerabilities_found,
                "execution_time": execution_time,
                "summary": f"完成 {completed_tasks}/{total_tasks} 个任务，发现 {vulnerabilities_found} 个漏洞",
                "errors": errors,
            }
            
        except Exception as e:
            end_time = time.time()
            execution_time = end_time - start_time
            
            error_msg = f"Workflow {workflow_info['workflow_name']} 执行失败: {str(e)}"
            self._log(error_msg, "error")
            
            return {
                "workflow_id": workflow_info["workflow_id"],
                "workflow_name": workflow_info["workflow_name"],
                "success": False,
                "completed_tasks": 0,
                "total_tasks": len(workflow_info.get("tasks", [])),
                "vulnerabilities_found": 0,
                "execution_time": execution_time,
                "summary": error_msg,
                "errors": [str(e)],
            }
    async def _execute_single_workflow(
            self,
            orchestrator: Any
        ) -> MasterOrchestratorResult:
            """继续执行单 workflow（任务已规划）

            Args:
                orchestrator: TaskOrchestratorAgent 实例（已完成规划）

            Returns:
                MasterOrchestratorResult: 执行结果
            """
            start_time = time.time()
            errors = []

            try:
                # 任务列表已经通过 _guide_planning 创建，直接进入执行循环
                self._log("开始执行任务...")

                max_iterations = 20
                iteration = 0

                while True:
                    iteration += 1
                    self._log(f"执行迭代 {iteration}/{max_iterations}")

                    # 检查是否超过最大迭代次数
                    if iteration > max_iterations:
                        self._log(f"达到最大迭代次数 {max_iterations}，结束执行", "warning")
                        break

                    # 组装上下文并调用 LLM
                    assembled_messages = await orchestrator.context_assembler.build_messages(
                        system_prompt=orchestrator._get_simplified_system_prompt(),
                    )

                    result = await orchestrator.llm_client_wrapper.atool_call(
                        messages=assembled_messages,
                        tools=orchestrator.tools,
                        system_prompt=None,
                    )

                    # 记录 AI 消息
                    await orchestrator.message_manager.add_ai_message(
                        result.content or "",
                        tool_calls=result.tool_calls,
                    )

                    # 检查是否有 Tool 调用
                    if not result.tool_calls:
                        # 如果没有 tool calls，说明 LLM 认为任务已完成
                        self._log("LLM 完成执行，结束", "success")
                        break

                    # 执行所有 Tool 调用
                    for tool_call in result.tool_calls:
                        tool_name = tool_call.get("name", "")
                        tool_args = tool_call.get("args", {})
                        tool_id = tool_call.get("id", "")

                        self._log(f"Tool 调用: {tool_name}")

                        try:
                            result_data = await orchestrator._execute_tool(tool_name, tool_args)

                            if isinstance(result_data, dict) and result_data.get("error"):
                                self._log(f"Tool 错误: {result_data['error']}", "warning")
                                errors.append(f"{tool_name}: {result_data['error']}")

                            content, summary = self._normalize_tool_output(result_data)

                            await orchestrator.message_manager.add_tool_message(
                                content=content,
                                summary=summary,
                                tool_name=tool_name,
                                tool_call_id=tool_id,
                            )

                        except Exception as e:
                            error_msg = str(e)
                            self._log(f"Tool 执行失败: {error_msg}", "error")
                            errors.append(f"{tool_name}: {error_msg}")

                            error_content = json.dumps({"error": error_msg}, ensure_ascii=False)
                            await orchestrator.message_manager.add_tool_message(
                                content=error_content,
                                tool_name=tool_name,
                                tool_call_id=tool_id,
                            )

                # 汇总结果
                end_time = time.time()
                execution_time = end_time - start_time

                # 获取任务统计
                tasks = orchestrator.tools_manager._task_list_manager.get_all_tasks()
                total_tasks = len(tasks)
                completed_tasks = sum(1 for task in tasks if task.status == "completed")

                # 获取漏洞数量（如果有）
                vulnerabilities_found = 0
                # TODO: 从 orchestrator 的结果中提取漏洞数量

                # 生成摘要
                summary = f"""# 单 Workflow 执行摘要

    ## 执行统计

    - **总任务数**: {total_tasks}
    - **完成任务数**: {completed_tasks}
    - **发现漏洞数**: {vulnerabilities_found}
    - **执行时间**: {execution_time:.2f} 秒

    ## 任务列表

    """
                for i, task in enumerate(tasks, 1):
                    status_icon = "✓" if task.status == "completed" else "✗"
                    summary += f"{i}. [{status_icon}] {task.description} ({task.status})\n"

                if errors:
                    summary += "\n## 错误信息\n\n"
                    for error in errors:
                        summary += f"- {error}\n"

                # 保存摘要
                summary_file = self.session_dir / "single_workflow_summary.md"
                summary_file.write_text(summary, encoding="utf-8")

                self._log("单 workflow 执行完成", "success")

                return MasterOrchestratorResult(
                    success=completed_tasks == total_tasks,
                    total_workflows=1,
                    completed_workflows=1 if completed_tasks == total_tasks else 0,
                    total_vulnerabilities=vulnerabilities_found,
                    execution_time=execution_time,
                    summary=summary,
                    workflow_results=[{
                        "workflow_id": "single_workflow",
                        "workflow_name": self.workflow_context.name if self.workflow_context else "Single Workflow",
                        "success": completed_tasks == total_tasks,
                        "completed_tasks": completed_tasks,
                        "total_tasks": total_tasks,
                        "vulnerabilities_found": vulnerabilities_found,
                        "execution_time": execution_time,
                        "summary": summary,
                        "errors": errors,
                    }],
                    errors=errors,
                )

            except Exception as e:
                error_msg = f"单 workflow 执行失败: {str(e)}"
                self._log(error_msg, "error")
                errors.append(error_msg)

                end_time = time.time()
                execution_time = end_time - start_time

                return MasterOrchestratorResult(
                    success=False,
                    total_workflows=1,
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
        
        新的执行流程：
        1. 解析 workflow 文档
        2. 初始化引擎
        3. 创建 TaskOrchestratorAgent
        4. 调用 _guide_planning 让 LLM 规划任务
        5. 检查 tools_manager.is_multi_workflow()
           - 如果是多 workflow：调用 _execute_multi_workflows
           - 如果是单 workflow：调用 _execute_single_workflow
        6. 返回汇总结果
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
            master_workflow_file = self.session_dir / "master_workflow.md"
            master_workflow_file.write_text(
                self.workflow_context.raw_markdown,
                encoding="utf-8"
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
                llm_client=self.llm_client
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
            orchestrator._init_orchestrator_components()
            
            # 4. 引导 LLM 调用 plan_tasks
            self._log("引导 LLM 规划任务...")
            await self._guide_planning(orchestrator, self.workflow_context)
            
            # 5. 获取规划结果并执行
            workflows = orchestrator.tools_manager.get_planned_workflows()
            if not workflows:
                raise ValueError("未获取到 workflow 规划结果，无法执行。")

            self._log(f"检测到 {len(workflows)} 个 workflow")
            base_result = await self._execute_multi_workflows(workflows, self.engine, self.workflow_context)

            # 执行后回顾（仅一次）：未执行过 vuln_analysis 则尝试追加任务
            task_manager = self._load_task_list_manager()
            if self._needs_post_execution_review(task_manager):
                self._log("执行后回顾：未执行过漏洞挖掘任务，尝试追加规划", "warning")
                appended = await self._guide_post_execution_review(orchestrator, workflows)
                if appended:
                    updated_workflows = orchestrator.tools_manager.get_planned_workflows() or workflows
                    pending_workflows = self._filter_workflows_with_pending_tasks(updated_workflows)
                    if pending_workflows:
                        group_labels = [
                            f"{wf.get('workflow_id')}({wf.get('_pending_task_count', 0)})"
                            for wf in pending_workflows
                        ]
                        self._log(
                            "执行后回顾追加任务：仅执行仍有待处理任务的 workflow -> "
                            + ", ".join(group_labels)
                        )
                        followup_result = await self._execute_multi_workflows(
                            pending_workflows,
                            self.engine,
                            self.workflow_context,
                            execution_phase="post_review_append",
                        )
                        combined_results = self._merge_workflow_results(
                            base_result.workflow_results,
                            followup_result.workflow_results,
                        )
                        total_vulns = sum(r.get("vulnerabilities_found", 0) for r in combined_results)
                        completed_workflows = sum(1 for r in combined_results if r.get("success", False))
                        total_workflows = len(combined_results)
                        combined_summary = self._generate_multi_workflow_summary(
                            workflows=updated_workflows,
                            workflow_results=combined_results,
                            execution_time=base_result.execution_time + followup_result.execution_time,
                        )
                        return MasterOrchestratorResult(
                            success=completed_workflows == total_workflows,
                            total_workflows=total_workflows,
                            completed_workflows=completed_workflows,
                            total_vulnerabilities=total_vulns,
                            execution_time=base_result.execution_time + followup_result.execution_time,
                            summary=combined_summary,
                            workflow_results=combined_results,
                            errors=base_result.errors + followup_result.errors,
                        )

            return base_result
        
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

    
    async def _identify_sub_workflows(self) -> List[SubWorkflowInfo]:
        """调用 LLM 识别子 workflow"""
        prompt = self._build_identification_prompt()
        system_prompt = self._get_identification_system_prompt()
        
        try:
            response = await self.llm_client_wrapper.atext_call(
                messages=[HumanMessage(content=prompt)],
                system_prompt=system_prompt,
            )
            
            sub_workflows = self._parse_sub_workflows_response(response)
            return sub_workflows
        
        except Exception as e:
            self._log(f"识别子 workflow 失败: {str(e)}", "error")
            return []
    
    def _build_identification_prompt(self) -> str:
        """构建识别子 workflow 的 prompt"""
        lines = [
            "# 任务：识别独立的漏洞挖掘 Workflow",
            "",
            "请分析以下 workflow 文档，识别出独立的漏洞挖掘场景。",
            "",
            "## Workflow 文档",
            "",
            f"### 名称",
            f"{self.workflow_context.name}",
            "",
            f"### 描述",
            f"{self.workflow_context.description}",
            "",
        ]
        
        if self.workflow_context.vulnerability_focus:
            lines.extend([
                f"### 漏洞关注点",
                "",
            ])
            for i, vuln in enumerate(self.workflow_context.vulnerability_focus, 1):
                lines.append(f"{i}. {vuln}")
            lines.append("")
        
        lines.extend([
            "## 输出格式",
            "",
            "请以 JSON 格式输出。",
        ])
        
        return "\n".join(lines)
    
    def _get_identification_system_prompt(self) -> str:
        """获取识别子 workflow 的 system prompt"""
        return """你是一个漏洞挖掘 workflow 分析专家。
识别出独立的漏洞挖掘场景，每个场景包含完整的流程。
直接输出 JSON 格式。"""
    
    def _parse_sub_workflows_response(self, response: str) -> List[SubWorkflowInfo]:
        """解析 LLM 返回的子 workflow JSON"""
        try:
            import re
            json_match = re.search(r'```(?:json)?\s*(\[.*?\])\s*```', response, re.DOTALL)
            if json_match:
                json_str = json_match.group(1)
            else:
                json_str = response.strip()
            
            data = json.loads(json_str)
            
            if not isinstance(data, list):
                return []
            
            sub_workflows = []
            for item in data:
                if not isinstance(item, dict):
                    continue
                
                sub_workflow = SubWorkflowInfo(
                    id=item.get("id", f"workflow_{len(sub_workflows) + 1}"),
                    name=item.get("name", "未命名 Workflow"),
                    description=item.get("description", ""),
                    tasks=item.get("tasks", []),
                )
                sub_workflows.append(sub_workflow)
            
            return sub_workflows
        
        except Exception as e:
            self._log(f"解析子 workflow 失败: {str(e)}", "error")
            return []
    
    
    
    
    
    def _generate_master_summary(
        self,
        workflow_results: List[Any],
        execution_time: float,
    ) -> str:
        """生成总体执行摘要"""
        lines = [
            f"# {self.workflow_context.name} - 总体执行摘要",
            "",
            f"**Session ID**: {self.session_id}",
            f"**总执行时间**: {execution_time:.2f}s",
            "",
            "## 执行统计",
            "",
            f"- 总 Workflow 数: {len(workflow_results)}",
            f"- 成功: {sum(1 for r in workflow_results if r.success)}",
            f"- 失败: {sum(1 for r in workflow_results if not r.success)}",
            f"- 总漏洞数: {sum(r.vulnerabilities_found for r in workflow_results)}",
            "",
        ]
        
        for i, result in enumerate(workflow_results, 1):
            status = "✅" if result.success else "❌"
            lines.extend([
                f"### {i}. {result.workflow_name} {status}",
                "",
                f"- Task Group: {result.task_group}",
                f"- 完成任务: {result.completed_tasks}/{result.total_tasks}",
                "",
            ])
        
        return "\n".join(lines)


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
    "SubWorkflowInfo",
    "run_master_workflow",
]
