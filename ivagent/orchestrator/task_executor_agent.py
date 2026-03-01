#!/usr/bin/env python3
"""
TaskExecutorAgent - 任务执行 Agent

仅负责执行任务列表，不负责规划与拆分。
"""

from typing import Any, Dict, List, Optional
from dataclasses import dataclass
from pathlib import Path
import json
import time

from langchain_openai import ChatOpenAI
from ..engines import BaseStaticAnalysisEngine
from ..core import ToolBasedLLMClient, SummaryService
from ..core.cli_logger import CLILogger
from ..core.context import MessageManager, ContextAssembler, ContextCompressor, ArtifactStore, ReadArtifactPruner
from ..core.agent_logger import get_agent_log_manager, AgentStatus
from .tools import OrchestratorTools
from .task_list_manager import TaskListManager
from .agent_delegate import AgentDelegate


@dataclass
class TaskExecutorResult:
    """任务执行结果"""
    task_group: str
    workflow_name: str
    goal: str
    success: bool
    completed_tasks: int
    total_tasks: int
    vulnerabilities_found: int
    execution_time: float
    summary: str
    errors: List[str]


class TaskExecutorAgent:
    """
    任务执行器

    核心特点：
    1. 只执行任务列表，不负责规划
    2. 只处理指定 task_group 的任务
    3. 使用统一任务看板
    """

    def __init__(
        self,
        task_group: str,
        workflow_name: str,
        goal: str,
        llm_client: ChatOpenAI,
        engine: BaseStaticAnalysisEngine,
        session_dir: Path,
        source_root: Optional[str] = None,
        verbose: bool = True,
        enable_logging: bool = True,
        execution_phase: str = "base",
    ):
        """
        初始化 TaskExecutorAgent

        Args:
            task_group: 任务分组标识（通常由 workflow_id 映射而来）
            workflow_name: Workflow 名称
            goal: 目标描述
            llm_client: LLM 客户端
            engine: 静态分析引擎（已初始化）
            session_dir: Session 目录
            source_root: 源代码根目录
            verbose: 是否打印日志
            enable_logging: 是否启用日志记录
            execution_phase: 执行阶段标识（base/post_review_append）
        """
        self.task_group = task_group
        self.workflow_name = workflow_name
        self.goal = goal
        self.llm_client = llm_client
        self.engine = engine
        self.session_dir = session_dir
        self.source_root = source_root
        self.verbose = verbose
        self.enable_logging = enable_logging
        self.execution_phase = execution_phase or "base"
        self.agent_id = f"task_executor_{self.task_group}"
        self._logger = CLILogger(component=f"TaskExecutor:{self.task_group}", verbose=verbose)
        self.target_function = (
            f"task_group: {self.task_group}"
            if self.task_group
            else (self.goal or self.workflow_name)
        )

        # 创建执行器目录（用于摘要与 artifact）
        self.executor_dir = session_dir / task_group
        self.executor_dir.mkdir(parents=True, exist_ok=True)

        # 统一 artifact 目录（session 级）
        self.artifact_dir = self.session_dir / "artifacts"
        self.artifact_dir.mkdir(parents=True, exist_ok=True)

        # 状态
        self.completed = False
        self.result = None
        self.errors: List[str] = []

        # 初始化 agent logger
        if self.enable_logging:
            self.agent_log_manager = get_agent_log_manager()
        else:
            self.agent_log_manager = None

        # 初始化组件
        self._init_components()

    def _init_components(self) -> None:
        """初始化执行器组件"""
        # 1. Artifact Store（用于上下文与 read_artifact）
        self.artifact_store = ArtifactStore(
            base_dir=self.artifact_dir,
        )

        # 2. LLM 客户端包装器
        self.llm_client_wrapper = ToolBasedLLMClient(
            llm=self.llm_client,
            max_retries=3,
            retry_delay=1.0,
            verbose=self.verbose,
            enable_logging=self.enable_logging,
            session_id=self.task_group,
            agent_id=self.agent_id,
            log_metadata={
                "agent_type": "task_executor",
                "task_group": self.task_group,
                "workflow_name": self.workflow_name,
                "target_function": self.target_function,
            },
        )

        # 3. 摘要服务
        self.summary_service = SummaryService(
            llm_client=self.llm_client,
            max_retries=2,
            retry_delay=1.0,
            enable_logging=self.enable_logging,
            verbose=self.verbose,
            session_id=self.task_group,
            agent_id=self.agent_id,
            agent_type="task_executor",
            target_function=self.target_function,
        )

        # 4. 消息管理器
        self.message_manager = MessageManager(
            artifact_store=self.artifact_store,
            max_inline_chars=4000,
        )
        self.context_compressor = ContextCompressor(
            summary_service=self.summary_service,
            compression_profile="task_executor",
            consumer_agent="task_executor",
            compression_purpose="task execution progression and recovery",
        )
        self.read_artifact_pruner = ReadArtifactPruner()

        # 5. 上下文组装器
        self.context_assembler = ContextAssembler(
            message_manager=self.message_manager,
            compressor=self.context_compressor,
            read_artifact_pruner=self.read_artifact_pruner,
            token_threshold=8000,
            compression_profile="task_executor",
            compression_consumer="task_executor",
            compression_purpose="task execution progression and recovery",
        )

        # 6. 任务列表管理器（统一任务看板）
        tasks_file = self.session_dir / "tasks.md"
        self.task_list_manager = TaskListManager(
            tasks_file=tasks_file,
        )

        # 7. Agent 委托器
        self.agent_delegate: AgentDelegate = AgentDelegate(
            engine=self.engine,
            llm_client=self.llm_client,
            artifact_store=self.artifact_store,
            verbose=self.verbose,
        )

        # 8. 工具管理器
        self.tools_manager = OrchestratorTools(
            llm_client=self.llm_client,
            workflow_context=None,
            engine_type=None,
            target_path=None,
            source_root=self.source_root,
            artifact_store=self.artifact_store,
            session_id=self.task_group,
            summary_service=self.summary_service,
            tool_output_summary_threshold=self.message_manager.max_inline_chars,
            verbose=self.verbose,
            logger=self._logger,
        )
        self.tools_manager.set_message_manager(self.message_manager)

        # 10. 设置已初始化的引擎
        self.tools_manager.engine = self.engine
        engine_cls = self.engine.__class__.__name__.lower()
        if "ida" in engine_cls:
            self.tools_manager.engine_name = "ida"
        elif "jeb" in engine_cls:
            self.tools_manager.engine_name = "jeb"
        elif "abc" in engine_cls:
            self.tools_manager.engine_name = "abc"
        elif "source" in engine_cls:
            self.tools_manager.engine_name = "source"
        else:
            self.tools_manager.engine_name = engine_cls
        self.tools_manager._initialized = True

        # 10. 设置组件引用
        self.tools_manager._task_list_manager = self.task_list_manager
        self.tools_manager._agent_delegate = self.agent_delegate

        # 11. 创建工具列表（仅执行器工具）
        self.tools = self.tools_manager.get_executor_tools()

    def _log(self, message: str, level: str = "info") -> None:
        """打印日志"""
        if not self.verbose:
            return
        self._logger.log(level=level, event="task_executor.event", message=message)

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

    def _get_system_prompt(self) -> str:
        """获取系统提示词（执行器模式）"""
        return """# 任务执行器

你是一个**漏洞挖掘任务执行器**，只负责执行任务列表，不负责规划。
请严格依据任务描述与工具返回结果行动，**优先通过 tool call 获取证据**，禁止以经验推断代替代码事实。

# 可用工具

- `list_runnable_tasks(task_group, agent_type)`: 查看可执行任务与阻塞原因
- `compose_task_context(analysis_target, task_id, artifact_refs, conversation_context, extra_context, required_sections, mode, task_group)`: 组装任务上下文（analysis_target 可留空并回退到任务描述）
- `execute_task(task_id, task_group, additional_context, selected_file_ids, context_ref)`: 执行指定任务（`selected_file_ids` 传 `artifact_ref` 列表）
- `execute_tasks(task_ids, task_group, ...)`: 执行指定任务集合（支持并发）
- `get_task_status(task_group)`: 获取任务列表状态
- `read_task_output(task_id)`: 读取指定任务输出
- `resolve_function_identifier(task_id, query_hint)`: 解析 function_identifier 候选
- `set_task_function_identifier(task_id, function_identifier, source="search_symbol")`: 写回 function_identifier
- `delegate_code_explorer(query, context, max_iterations)`: 受限委托 code_explorer 做探索取证
- `read_artifact(artifact_id)`: 读取已归档内容
- `mark_compression_projection(remove_message_ids, fold_message_ids, reason)`: 提交上下文裁切清单（按消息ID）

# 执行要求

1. **只执行任务，不要规划**：禁止调用 `plan_tasks`、`append_tasks`、通用 `delegate_task`。
2. **必须带 task_group**：所有执行相关调用必须显式传入当前任务分组的 `task_group`。
3. **按任务执行**：优先使用 `list_runnable_tasks -> compose_task_context -> execute_task`。
4. **agent_type 必须匹配当前待执行任务**：从任务看板读取目标任务的 agent_type，禁止猜测或固定写 `vuln_analysis`。
5. **任务未完成禁止结束**：只要当前 task_group 还有 pending / in_progress，必须继续执行。
6. **上下文摘要必须基于事实**：analysis_context 只能包含目标函数约束与证据等代码事实，禁止编造或“应当/需要”类描述。
7. **当传递 additional_context 时必须结构化**：优先使用并保持以下章节标题
   - `## 目标函数`
   - `## 入参约束`
   - `## 全局变量约束`
   - `## 证据锚点`
   其中 `## 入参约束` 必须按参数逐条给出：来源/可控性/污点/边界/校验/证据。
   且入参约束仅允许目标函数签名参数，局部变量只能作为证据锚点。
   若缺约束或证据锚点，不要补写推断，先通过工具取证。
8. **优先最小动作推进**：若任务列表已给出，首轮优先执行 `list_runnable_tasks` 后直接 `execute_task`。
9. **避免无效重试**：同一错误码连续出现 2 次且无新证据时，必须切换策略（读取产物或调用 `delegate_code_explorer`）。
10. **禁止空转**：连续 5 轮任务状态无变化时，输出失败摘要并停止。
11. **特殊错误处理指南（必须遵守）**：
    - `MISSING_FUNCTION_IDENTIFIER`：先 `resolve_function_identifier`，再 `set_task_function_identifier`，然后重试执行。
    - `INVALID_ARGUMENT`：先修正参数，再重试；不要在参数错误状态下做无关调用。
    - `MISSING_TASK_GROUP`：先确认并传入正确 `task_group` 后再执行。
    - `RECOVERY_LOCK_ACTIVE`：优先处理被锁定任务，禁止跳过。
    - `MISSING_TASK_OUTPUT_ARTIFACT`：不要重复调用 `read_task_output`；先看 `task_status`，必要时 `list_task_artifacts` / `get_task_status`，再执行 `execute_task` 产出输出。
    - `OUTPUT_ARTIFACT_NOT_FOUND`：先核对 `artifact_ref` 与槽位绑定，必要时重试 `execute_task` 重新生成输出。
    - `INSUFFICIENT_CONTEXT` / `MISSING_ANALYSIS_CONTEXT`：先 `read_task_output`/`read_artifact` 取证，不足再 `delegate_code_explorer`，然后按需 `compose_task_context` 后重试。
    - `ENGINE_NOT_READY` / `LLM_CLIENT_UNAVAILABLE`：视为环境阻塞，立即停止并上报。

# 压缩信号驱动（必须遵守）

若上下文包含压缩摘要章节：
- `## 与当前分析目标匹配的语义理解蒸馏`
- `### 是否需要继续获取信息`
- `### 最小补充信息集`
- `## LLM 驱动裁切上下文`

则必须按以下规则执行：
1. `是否需要继续获取信息 = 是`：优先执行最小补证动作，不得直接宣告完成。
2. `是否需要继续获取信息 = 否`：默认禁止重复取证，优先推进当前可执行任务闭环。
3. 裁切上下文章节仅用于去重与降噪，不得删除对未完成任务仍关键的证据链。
4. 若需要提交裁切清单，必须使用消息首行的 `消息ID: ...` 作为 `remove_message_ids` / `fold_message_ids`。
5. 提交裁切清单时必须规避 tool call 链断裂：assistant tool_call 与 ToolMessage 需保持成对可追踪关系。
6. 对于会破坏链路的长消息，优先使用 `fold_message_ids` 折叠，不要删除。

现在开始执行你的任务。"""

    async def run(self) -> TaskExecutorResult:
        """
        执行任务直到完成

        Returns:
            TaskExecutorResult: 执行结果
        """
        start_time = time.time()

        # 记录执行开始
        if self.agent_log_manager:
            self.agent_log_manager.log_execution_start(
                agent_id=self.agent_id,
                agent_type="task_executor",
                target_function=self.target_function,
                parent_id=None,
                call_stack=[],
                metadata={
                    "workflow_name": self.workflow_name,
                    "goal": self.goal,
                    "task_group": self.task_group,
                },
            )

        try:
            phase_label = "追加任务执行" if self.execution_phase == "post_review_append" else "常规执行"
            self._log(f"开始执行任务分组: {self.task_group}（{phase_label}）")
            self._log(f"目标: {self.goal}")

            # 检查任务列表是否为空
            group_tasks = self.task_list_manager.get_all_tasks(task_group=self.task_group)
            if not group_tasks:
                error_msg = f"任务列表为空（task_group={self.task_group}），无法执行。"
                self.errors.append(error_msg)
                self._log(error_msg, "error")
                return TaskExecutorResult(
                    task_group=self.task_group,
                    workflow_name=self.workflow_name,
                    goal=self.goal,
                    success=False,
                    completed_tasks=0,
                    total_tasks=0,
                    vulnerabilities_found=0,
                    execution_time=time.time() - start_time,
                    summary=error_msg,
                    errors=self.errors,
                )

            # 仅展示当前 task_group 的真实待执行状态，避免误解为重跑
            pending_tasks = [t for t in group_tasks if t.status.value in {"pending", "in_progress"}]
            completed_count = sum(1 for t in group_tasks if t.status.value == "completed")
            self._log(
                f"任务状态概览: total={len(group_tasks)}, pending={len(pending_tasks)}, completed={completed_count}"
            )
            if pending_tasks:
                preview = "；".join(t.description for t in pending_tasks[:3])
                self._log(f"待执行任务摘要: {preview}")

            # 1. 初始化消息：告诉执行器任务约束（任务清单以 list_runnable_tasks 为唯一权威来源）
            await self.message_manager.add_user_message(
                f"""你的任务分组是：{self.task_group}

目标：{self.goal}

执行规则：
- 只执行任务，不要规划。
- 所有执行相关调用必须显式传入 task_group="{self.task_group}"。
- 优先调用 list_runnable_tasks 后使用 execute_task 推进。
- 上下文优先使用 compose_task_context 生成。
- 首轮先调用 list_runnable_tasks 获取权威任务列表，不要先调用 get_task_status。
- agent_type 必须使用目标任务要求的类型，禁止固定为 vuln_analysis。
- 若遇到证据不足，可先 read_task_output/read_artifact，再按需调用 delegate_code_explorer。
- 若出现 MISSING_FUNCTION_IDENTIFIER，先 resolve_function_identifier，再 set_task_function_identifier，然后重试执行。
- 若同一错误连续出现且无新证据，请切换策略，不要重复无效调用。
- 若出现 MISSING_AGENT_TYPE，请回到规划阶段补齐。
"""
            )

            # 2. 自主循环
            max_iterations = 30
            iteration = 0
            stall_rounds = 0
            no_progress_rounds = 0
            last_stats = self.task_list_manager.get_statistics(task_group=self.task_group)

            while True:
                iteration += 1
                self._log(f"迭代 {iteration}/{max_iterations}", "debug")

                if iteration > max_iterations:
                    self._log(f"达到最大迭代次数 {max_iterations}，结束执行", "warning")
                    break

                # 硬收敛：当前 task_group 无 pending/in_progress 时立即结束，避免空转
                current_stats = self.task_list_manager.get_statistics(task_group=self.task_group)
                if current_stats.get("pending", 0) == 0 and current_stats.get("in_progress", 0) == 0:
                    if current_stats.get("failed", 0) == 0 and current_stats.get("total", 0) > 0:
                        self._log("检测到任务组已无待执行项，提前收敛结束", "success")
                        self.completed = True
                    else:
                        self._log("检测到任务组无待执行项但存在失败任务，提前终止", "warning")
                        self.errors.append("任务组无待执行项但存在失败任务，停止继续工具循环。")
                    break

                assembled_messages = await self.context_assembler.build_messages(
                    system_prompt=self._get_system_prompt(),
                )

                result = await self.llm_client_wrapper.atool_call(
                    messages=assembled_messages,
                    tools=self.tools,
                    system_prompt=None,
                )

                await self.message_manager.add_ai_message(
                    result.content or "",
                    tool_calls=result.tool_calls,
                )

                if not result.tool_calls:
                    if not self.task_list_manager.is_all_completed(task_group=self.task_group):
                        stall_rounds += 1
                        self._log(
                            f"未收到 tool call 且任务未完成，进入恢复引导 ({stall_rounds}/3)",
                            "warning",
                        )
                        await self.message_manager.add_user_message(
                            "任务尚未完成，必须继续调用工具。"
                            "请根据最近错误原因选择下一步，避免重复无效调用。"
                            "若证据不足，请先 read_task_output/read_artifact，必要时调用 delegate_code_explorer。"
                        )
                        if stall_rounds >= 3:
                            self.errors.append("连续 3 轮无工具调用且任务未完成，保护性终止。")
                            break
                        continue
                    self._log("任务已完成", "success")
                    self.completed = True
                    break

                stall_rounds = 0
                executed_task_in_round = False
                for tool_call in result.tool_calls:
                    tool_name = tool_call.get("name", "")
                    tool_args = tool_call.get("args", {})
                    tool_id = tool_call.get("id", "")

                    self._log(f"Tool 调用: {tool_name}", "debug")
                    if tool_name in {"execute_task", "execute_tasks"}:
                        executed_task_in_round = True

                    try:
                        result_data = await self._execute_tool(tool_name, tool_args)

                        if isinstance(result_data, dict) and result_data.get("error"):
                            self._log(f"Tool 错误: {result_data['error']}", "warning")
                            self.errors.append(f"{tool_name}: {result_data['error']}")

                        content, summary = self._normalize_tool_output(result_data)
                        await self.message_manager.add_tool_message(
                            content=content,
                            summary=summary,
                            tool_name=tool_name,
                            tool_call_id=tool_id,
                        )

                    except Exception as e:
                        error_msg = str(e)
                        self._log(f"Tool 执行失败: {error_msg}", "error")
                        self.errors.append(f"{tool_name}: {error_msg}")

                        error_content = json.dumps({"error": error_msg}, ensure_ascii=False)
                        await self.message_manager.add_tool_message(
                            content=error_content,
                            tool_name=tool_name,
                            tool_call_id=tool_id,
                        )

                # 进度感知收敛：若连续多轮状态无变化，避免 read_task_output/get_task_status 空转
                current_stats = self.task_list_manager.get_statistics(task_group=self.task_group)
                progressed = (
                    current_stats.get("completed", 0) != last_stats.get("completed", 0)
                    or current_stats.get("pending", 0) != last_stats.get("pending", 0)
                    or current_stats.get("failed", 0) != last_stats.get("failed", 0)
                )
                has_unfinished = (
                    current_stats.get("pending", 0) > 0
                    or current_stats.get("in_progress", 0) > 0
                )

                if progressed:
                    no_progress_rounds = 0
                elif has_unfinished:
                    no_progress_rounds += 1
                    self._log(
                        f"检测到任务状态无进展 ({no_progress_rounds}/5)",
                        "warning",
                    )
                    if not executed_task_in_round and no_progress_rounds >= 2:
                        await self.message_manager.add_user_message(
                            "当前任务状态未推进。请根据最近错误码先补齐缺失前置条件，"
                            "或先取证（read_task_output/read_artifact/delegate_code_explorer）后再重试执行。"
                        )
                    if no_progress_rounds >= 5:
                        self.errors.append("连续 5 轮有工具调用但任务状态无进展，保护性终止。")
                        self._log("连续 5 轮无进展，保护性终止。", "warning")
                        break
                else:
                    no_progress_rounds = 0

                last_stats = current_stats

            # 3. 汇总结果
            end_time = time.time()
            execution_time = end_time - start_time

            tasks = self.task_list_manager.get_all_tasks(task_group=self.task_group)
            total_tasks = len(tasks)
            completed_tasks = sum(1 for task in tasks if task.status.value == "completed")
            vulnerabilities_found = len(self.tools_manager.vulnerabilities)

            summary = f"""# 任务分组执行摘要

## 基本信息

- **Task Group**: {self.task_group}
- **Workflow 名称**: {self.workflow_name}
- **目标**: {self.goal}

## 执行统计

- **总任务数**: {total_tasks}
- **完成任务数**: {completed_tasks}
- **发现漏洞数**: {vulnerabilities_found}
- **执行时间**: {execution_time:.2f} 秒
- **迭代次数**: {iteration}

## 任务列表

"""
            for i, task in enumerate(tasks, 1):
                status_icon = "✓" if task.status.value == "completed" else "✗"
                summary += f"{i}. [{status_icon}] {task.description} ({task.status.value})\n"

            if self.errors:
                summary += "\n## 错误信息\n\n"
                for error in self.errors:
                    summary += f"- {error}\n"

            summary_ref = self.artifact_store.put_text(
                content=summary,
                kind="task_group_summary",
                summary=f"{self.task_group} 执行摘要",
                workflow_id=self.task_group,
                producer="task_executor",
                metadata={
                    "kind": "task_group_summary",
                    "task_group": self.task_group,
                    "workflow_name": self.workflow_name,
                    "execution_phase": self.execution_phase,
                },
            ).artifact_id
            self._log(f"已写入任务组摘要 artifact: {summary_ref}")

            self._log(f"执行完成: {completed_tasks}/{total_tasks} 任务完成", "success")

            if self.agent_log_manager:
                status = AgentStatus.COMPLETED if completed_tasks == total_tasks else AgentStatus.FAILED
                self.agent_log_manager.log_execution_end(
                    agent_id=self.agent_id,
                    status=status,
                    vulnerabilities_found=vulnerabilities_found,
                    summary=f"completed_tasks={completed_tasks}, total_tasks={total_tasks}, vulnerabilities_found={vulnerabilities_found}",
                    error_message="; ".join(self.errors) if self.errors else None,
                )

            return TaskExecutorResult(
                task_group=self.task_group,
                workflow_name=self.workflow_name,
                goal=self.goal,
                success=completed_tasks == total_tasks,
                completed_tasks=completed_tasks,
                total_tasks=total_tasks,
                vulnerabilities_found=vulnerabilities_found,
                execution_time=execution_time,
                summary=summary,
                errors=self.errors,
            )

        except Exception as e:
            end_time = time.time()
            execution_time = end_time - start_time
            error_msg = f"任务执行失败: {str(e)}"
            self._log(error_msg, "error")
            self.errors.append(error_msg)

            if self.agent_log_manager:
                self.agent_log_manager.log_execution_end(
                    agent_id=self.agent_id,
                    status=AgentStatus.FAILED,
                    summary=error_msg,
                    error_message=error_msg,
                )

            return TaskExecutorResult(
                task_group=self.task_group,
                workflow_name=self.workflow_name,
                goal=self.goal,
                success=False,
                completed_tasks=0,
                total_tasks=0,
                vulnerabilities_found=0,
                execution_time=execution_time,
                summary=error_msg,
                errors=self.errors,
            )

    async def _execute_tool(self, tool_name: str, tool_args: Dict[str, Any]) -> Any:
        """执行工具调用"""
        tool_method = getattr(self.tools_manager, tool_name, None)
        if tool_method is None:
            return {"error": f"Unknown tool: {tool_name}"}
        if tool_name in {
            "list_runnable_tasks",
            "compose_task_context",
            "execute_task",
            "execute_tasks",
        } and "task_group" not in tool_args:
            tool_args["task_group"] = self.task_group
        try:
            result = await tool_method(**tool_args)
            return result
        except Exception as e:
            return {"error": str(e)}


__all__ = [
    "TaskExecutorAgent",
    "TaskExecutorResult",
]
