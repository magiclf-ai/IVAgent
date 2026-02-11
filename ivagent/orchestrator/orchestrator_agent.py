#!/usr/bin/env python3
"""
TaskOrchestratorAgent - LLM 驱动的任务规划 Agent

通过 Tools 暴露能力，由 LLM 自主决策执行流程。
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass
import json
import asyncio

from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage, AIMessage, BaseMessage

from ..models.workflow import WorkflowContext
from ..core import ToolBasedLLMClient
from ..agents.prompts import ORCHESTRATOR_SYSTEM_PROMPT, build_orchestrator_planning_prompt
from .workflow_parser import WorkflowParser
from .tools import OrchestratorTools


@dataclass
class OrchestratorResult:
    """Orchestrator 执行结果"""
    success: bool
    vulnerabilities_found: int
    report: str
    summary: str
    errors: List[str] = None

    def __post_init__(self):
        if self.errors is None:
            self.errors = []


class TaskOrchestratorAgent:
    """
    任务规划 Agent - LLM 驱动架构
    
    核心原则:
    - 不做任何硬编码决策，全部委托给 LLM
    - 通过 Tools 暴露能力，让 LLM 决定何时调用
    - Workflow 是"意图描述"，不是"配置"
    """

    def __init__(
        self,
        llm_client: ChatOpenAI,
        engine_type: Optional[str] = None,
        target_path: Optional[str] = None,
        source_root: Optional[str] = None,
        workflow_context: Optional[WorkflowContext] = None,
        verbose: bool = True,
        enable_logging: bool = True,
        session_id: Optional[str] = None,
    ):
        self.llm = llm_client
        self.workflow_context = workflow_context
        self.verbose = verbose
        self.enable_logging = enable_logging
        self.session_id = session_id
        self.agent_id = f"orchestrator_{id(self)}"
        
        # 初始化 Tools（如果提供了 engine_type 和 target_path 则立即初始化 engine）
        self.tools_manager = OrchestratorTools(
            llm_client=llm_client,
            workflow_context=workflow_context,
            engine_type=engine_type,
            target_path=target_path,
            source_root=source_root,
        )
        self.tools = self.tools_manager.get_tools()
        
        # 确定目标函数显示内容
        if target_path:
            target_function = target_path
        elif workflow_context and workflow_context.target and workflow_context.target.path:
            target_function = workflow_context.target.path
        elif workflow_context and workflow_context.name:
            target_function = f"workflow: {workflow_context.name}"
        else:
            target_function = "orchestrator"

        # 初始化 LLM Client Wrapper
        self.llm_client_wrapper = ToolBasedLLMClient(
            llm=self.llm,
            max_retries=3,
            retry_delay=1.0,
            verbose=self.verbose,
            enable_logging=self.enable_logging,
            session_id=self.session_id,
            agent_id=self.agent_id,
            log_metadata={
                "agent_type": "orchestrator",
                "target_function": target_function,
            },
        )

    def _log(self, message: str, level: str = "info"):
        """打印日志"""
        if self.verbose:
            prefix = "[Orchestrator]"
            if level == "error":
                print(f"  [X] {prefix} {message}")
            elif level == "warning":
                print(f"  [!] {prefix} {message}")
            elif level == "success":
                print(f"  [+] {prefix} {message}")
            else:
                print(f"  [*] {prefix} {message}")

    async def execute_workflow(self, workflow_path: str, target_path: str = None) -> OrchestratorResult:
        """
        执行 Workflow 文档

        Args:
            workflow_path: Workflow 文件路径
            target_path: 目标程序路径（可选，如果 workflow 中未指定）

        Returns:
            OrchestratorResult 执行结果
        """
        # 解析 Workflow
        self._log(f"读取 Workflow 文档: {workflow_path}")

        try:
            parser = WorkflowParser()
            self.workflow_context = parser.parse_and_validate(workflow_path)
        except Exception as e:
            return OrchestratorResult(
                success=False,
                vulnerabilities_found=0,
                report="",
                summary=f"Failed to parse workflow: {e}",
                errors=[str(e)],
            )

        # 异步初始化引擎（如果有待处理的引擎配置）
        if not self.tools_manager._initialized:
            self._log("正在初始化分析引擎...")
            try:
                # 从 workflow 或参数获取目标路径
                workflow_target = None
                if self.workflow_context and self.workflow_context.target:
                    workflow_target = self.workflow_context.target.path
                final_target = target_path or workflow_target

                initialized = await self.tools_manager.initialize(target_path=final_target)
                if not initialized:
                    return OrchestratorResult(
                        success=False,
                        vulnerabilities_found=0,
                        report="",
                        summary="Failed to initialize engine: no engine configuration provided",
                        errors=["Engine initialization failed: engine_type and target_path are required"],
                    )
                self._log("分析引擎初始化成功", "success")
            except Exception as e:
                return OrchestratorResult(
                    success=False,
                    vulnerabilities_found=0,
                    report="",
                    summary=f"Engine initialization failed: {e}",
                    errors=[str(e)],
                )

        # 更新 Tools 的 Workflow 上下文
        self.tools_manager.workflow_context = self.workflow_context

        self._log("Workflow 解析成功")
        self._log(f"名称: {self.workflow_context.name}")

        # 使用运行时传入的 target_path 或 workflow 中的 target
        final_target = target_path or (self.workflow_context.target.path if self.workflow_context.target else None)
        if final_target:
            self._log(f"目标: {final_target}")

        # 构建规划 Prompt
        planning_prompt = self._build_planning_prompt(target_path=final_target)

        # 让 LLM 自主规划并执行
        messages: List[BaseMessage] = [
            SystemMessage(content=self._get_system_prompt()),
            HumanMessage(content=planning_prompt),
        ]

        max_iterations = 20
        iteration = 0
        errors = []

        try:
            while True:
                iteration += 1
                self._log(f"执行迭代 {iteration}/{max_iterations}")

                # 检查任务状态
                task_summary = self.tools_manager.task_manager.get_progress_summary()
                current_task = self.tools_manager.task_manager.get_current_task()

                # 日志输出任务进度
                if task_summary['total'] > 0:
                    self._log(
                        f"任务进度: {task_summary['completed']}/{task_summary['total']} "
                        f"完成 ({task_summary['completion_rate']}%), "
                        f"进行中: {task_summary['in_progress']}, "
                        f"待执行: {task_summary['pending']}"
                    )

                # 检查是否所有任务已完成
                if task_summary['total'] > 0 and task_summary['pending'] == 0 and task_summary['in_progress'] == 0:
                    self._log("所有任务已完成，结束执行", "success")
                    break

                # 如果超过最大迭代次数且没有进行中或待执行任务，退出
                if iteration > max_iterations:
                    if task_summary['in_progress'] == 0 and task_summary['pending'] == 0:
                        self._log(f"达到最大迭代次数 {max_iterations} 且无活动任务，结束执行", "warning")
                        break
                    else:
                        self._log(f"已达到最大迭代次数 {max_iterations}，但仍有未完成任务，继续执行...", "warning")

                # 添加任务状态到 Prompt（如果有任务）
                task_context = ""
                if task_summary['total'] > 0:
                    task_context = self._build_task_status_prompt(task_summary, current_task)

                # 构建包含任务状态的 Prompt
                if task_context:
                    # 添加任务状态信息到消息历史
                    last_human_msg = messages[-1] if messages and isinstance(messages[-1], HumanMessage) else None
                    if last_human_msg:
                        updated_content = f"{task_context}\n\n{last_human_msg.content}"
                        messages[-1] = HumanMessage(content=updated_content)

                # 调用 LLM
                result = await self.llm_client_wrapper.atool_call(
                    messages=messages,
                    tools=self.tools,
                    system_prompt=None,
                )

                # 构造 AI 消息
                response = self._create_ai_message_from_result(result)

                # 检查是否有 Tool 调用
                if not result.tool_calls:
                    # 如果没有任务，说明 LLM 完成了整体规划
                    # 如果有任务但没有 tool_calls，可能是所有任务完成，需要检查
                    if task_summary['total'] == 0:
                        self._log("LLM 完成规划，结束执行", "success")
                        break
                    elif task_summary['pending'] == 0 and task_summary['in_progress'] == 0:
                        self._log("所有任务已完成，结束执行", "success")
                        break

                # 添加 AI 消息到历史
                messages.append(response)

                # 并发执行所有 Tool 调用
                async def execute_single_tool(tool_call: Dict[str, Any]) -> ToolMessage:
                    """执行单个 tool call 并返回 ToolMessage"""
                    tool_name = tool_call.get("name", "")
                    tool_args = tool_call.get("args", {})
                    tool_id = tool_call.get("id", "")

                    self._log(f"Tool 调用: {tool_name}")

                    try:
                        result_data = await self._execute_tool(tool_name, tool_args)

                        if isinstance(result_data, dict) and result_data.get("error"):
                            self._log(f"Tool 错误: {result_data['error']}", "warning")
                            errors.append(f"{tool_name}: {result_data['error']}")

                        # Tool 返回字符串时直接传递，其他类型序列化为 JSON
                        if isinstance(result_data, str):
                            content = result_data
                        else:
                            content = json.dumps(result_data, ensure_ascii=False)

                        return ToolMessage(
                            content=content,
                            tool_call_id=tool_id,
                            name=tool_name,
                        )

                    except Exception as e:
                        error_msg = str(e)
                        self._log(f"Tool 执行失败: {error_msg}", "error")
                        errors.append(f"{tool_name}: {error_msg}")

                        return ToolMessage(
                            content=json.dumps({"error": error_msg}),
                            tool_call_id=tool_id,
                            name=tool_name,
                        )

                # 并发执行所有 tool calls
                if result.tool_calls:
                    tool_tasks = [
                        execute_single_tool(tc) for tc in result.tool_calls
                    ]
                    tool_results = await asyncio.gather(*tool_tasks)
                    messages.extend(tool_results)

            # 最终任务进度报告
            final_task_summary = self.tools_manager.task_manager.get_progress_summary()
            self._log("任务执行完成", "success")
            self._log(
                f"最终进度: {final_task_summary['completed']}/{final_task_summary['total']} "
                f"完成 ({final_task_summary['completion_rate']}%)"
            )

            return OrchestratorResult(
                success=True,
                vulnerabilities_found=len(self.tools_manager.vulnerabilities),
                report=json.dumps(final_task_summary, ensure_ascii=False),
                summary="分析完成",
                errors=errors,
            )

        except Exception as e:
            error_msg = str(e)
            self._log(f"执行失败: {error_msg}", "error")
            return OrchestratorResult(
                success=False,
                vulnerabilities_found=0,
                report="",
                summary=f"Execution failed: {error_msg}",
                errors=errors + [error_msg],
            )

    def _create_ai_message_from_result(self, result) -> AIMessage:
        """从 ToolCallResult 构造 AIMessage"""
        if result.tool_calls:
            tool_calls_formatted = [
                {
                    "id": tc.get("id", ""),
                    "name": tc.get("name", ""),
                    "args": tc.get("args", {}),
                }
                for tc in result.tool_calls
            ]
            return AIMessage(
                content=result.content or "",
                tool_calls=tool_calls_formatted,
            )
        else:
            return AIMessage(content=result.content or "")

    async def _execute_tool(self, tool_name: str, tool_args: Dict[str, Any]) -> Dict[str, Any]:
        """执行指定的 Tool"""
        tool_map = {
            # 任务管理工具
            "create_task": self.tools_manager.create_task,
            "update_task_status": self.tools_manager.update_task_status,
            "get_task": self.tools_manager.get_task,
            "list_tasks": self.tools_manager.list_tasks,
            "get_current_task": self.tools_manager.get_current_task,
            # 分析工具
            "query_code": self.tools_manager.query_code,
            "get_function_code": self.tools_manager.get_function_code,
            "get_xref": self.tools_manager.get_xref,
            "search_symbol": self.tools_manager.search_symbol,
            "read_file": self.tools_manager.read_file,
            "run_vuln_analysis": self.tools_manager.run_vuln_analysis,
        }

        tool_func = tool_map.get(tool_name)
        if not tool_func:
            return {"error": f"Unknown tool: {tool_name}"}

        return await tool_func(**tool_args)

    def _get_system_prompt(self) -> str:
        """获取 Orchestrator 的系统提示词"""
        return ORCHESTRATOR_SYSTEM_PROMPT

    def _build_task_status_prompt(self, task_summary: Dict[str, Any], current_task: Any) -> str:
        """构建任务状态提示信息

        Args:
            task_summary: 任务统计信息
            current_task: 当前正在执行的任务

        Returns:
            str: 格式化的任务状态信息
        """
        lines = [
            "【当前任务进度】",
            f"总任务数: {task_summary['total']}",
            f"已完成: {task_summary['completed']}",
            f"进行中: {task_summary['in_progress']}",
            f"待执行: {task_summary['pending']}",
            f"完成率: {task_summary['completion_rate']}%",
        ]

        if current_task:
            lines.extend([
                "",
                "【当前正在执行】",
                f"- 任务: {current_task.description}",
                f"- ID: {current_task.id}",
                "",
                "请继续执行当前任务，完成后使用 update_task_status 标记为 completed。"
            ])
        elif task_summary['pending'] > 0:
            lines.extend([
                "",
                "【待执行任务】",
                "请使用 get_current_task 查看待执行任务列表，",
                "然后使用 update_task_status 开始执行某个任务。"
            ])
        else:
            lines.extend([
                "",
                "【任务状态】",
                "所有任务已完成，可以结束工作或创建新的分析任务。"
            ])

        return "\n".join(lines)

    def _build_planning_prompt(self, target_path: str = None) -> str:
        """构建规划 Prompt"""
        if not self.workflow_context:
            return "No workflow context available."

        # 确定目标路径
        final_target = target_path or (
            self.workflow_context.target.path 
            if self.workflow_context.target and self.workflow_context.target.path 
            else None
        )

        return build_orchestrator_planning_prompt(
            name=self.workflow_context.name,
            description=self.workflow_context.description,
            target_path=final_target or "(待运行时指定)",
            scope=self.workflow_context.scope.description if self.workflow_context.scope else None,
            vulnerability_focus=self.workflow_context.vulnerability_focus,
            background_knowledge=self.workflow_context.background_knowledge,
            raw_markdown=self.workflow_context.raw_markdown,
        )


# 便捷函数
async def run_workflow(
    workflow_path: str,
    llm_client: ChatOpenAI,
    engine_type: str,
    target_path: str,
    source_root: Optional[str] = None,
    verbose: bool = True,
    enable_logging: bool = True,
    session_id: Optional[str] = None,
) -> OrchestratorResult:
    """
    便捷函数：执行 Workflow
    
    Args:
        workflow_path: Workflow 文件路径
        llm_client: LLM 客户端
        engine_type: 引擎类型 (ida, jeb, abc, source)
        target_path: 目标程序路径
        source_root: 源代码根目录（可选）
        verbose: 是否打印详细日志
        enable_logging: 是否启用 LLM 交互日志记录
        session_id: 会话 ID（用于日志追踪）
        
    Returns:
        执行结果
    """
    orchestrator = TaskOrchestratorAgent(
        llm_client=llm_client,
        engine_type=engine_type,
        target_path=target_path,
        source_root=source_root,
        verbose=verbose,
        enable_logging=enable_logging,
        session_id=session_id,
    )
    return await orchestrator.execute_workflow(workflow_path, target_path=target_path)
