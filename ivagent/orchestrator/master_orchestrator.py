#!/usr/bin/env python3
"""
MasterOrchestrator - 多 Workflow 协调器

负责将复杂的漏洞挖掘 workflow 拆分为多个独立的子 workflow，
并协调多个 TaskOrchestratorAgent 的执行（串行/并行）。
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


@dataclass
class SubWorkflowInfo:
    """子 Workflow 信息"""
    id: str
    name: str
    description: str
    tasks: List[str]


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
        allowed_tools = {"plan_tasks", "delegate_task", "read_artifact", "get_task_status", "read_task_output"}

        for round_id in range(1, max_rounds + 1):
            assembled_messages = orchestrator.context_assembler.build_messages(
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
                    self._log(f"执行 Tool: {tool_name}")
                    try:
                        result_data = await orchestrator._execute_tool(tool_name, tool_args)
                        content = result_data if isinstance(result_data, str) else json.dumps(result_data, ensure_ascii=False)
                        await orchestrator.message_manager.add_tool_message(
                            content=content,
                            tool_name=tool_name,
                            tool_call_id=tool_id,
                        )
                        self._log("规划完成", "success")
                        planned = True
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
                    content = result_data if isinstance(result_data, str) else json.dumps(result_data, ensure_ascii=False)
                    await orchestrator.message_manager.add_tool_message(
                        content=content,
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
    async def _execute_multi_workflows(
        self,
        workflows: List[Dict[str, Any]],
        engine: BaseStaticAnalysisEngine,
        workflow_context: WorkflowContext
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
            # 1. 为每个 workflow 创建独立的 WorkflowAgent
            self._log(f"创建 {len(workflows)} 个 WorkflowAgent...")
            workflow_agents = []

            for wf in workflows:
                # 创建独立的 WorkflowAgent
                from .workflow_agent import WorkflowAgent

                agent = WorkflowAgent(
                    workflow_id=wf['workflow_id'],
                    workflow_name=wf['workflow_name'],
                    goal=wf.get('workflow_description', wf['workflow_name']),
                    tasks=wf['tasks'],
                    llm_client=self.llm_client,
                    engine=engine,
                    session_dir=self.session_dir,
                    source_root=self.source_root,
                    verbose=self.verbose,
                    enable_logging=self.enable_logging,
                )

                workflow_agents.append((wf, agent))

                self._log(f"  - 创建 WorkflowAgent: {wf['workflow_name']} (ID: {wf['workflow_id']})")

            # 2. 根据执行模式执行
            execution_mode = workflows[0].get("execution_mode", "sequential") if workflows else "sequential"
            self._log(f"执行模式: {execution_mode}")

            if execution_mode == "parallel":
                # 并行执行
                self._log("并行执行所有 WorkflowAgent...")
                tasks = [
                    agent.run()  # 调用 WorkflowAgent.run()
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
                            "workflow_id": result.workflow_id,
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
                self._log("串行执行所有 WorkflowAgent...")
                workflow_results = []
                for wf, agent in workflow_agents:
                    self._log(f"执行 Workflow: {wf['workflow_name']}")
                    try:
                        result = await agent.run()  # 调用 WorkflowAgent.run()
                        
                        # 将 WorkflowResult 转换为字典
                        workflow_results.append({
                            "workflow_id": result.workflow_id,
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

            self._log("所有 workflow 执行完成", "success")

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
                assembled_messages = orchestrator.context_assembler.build_messages(
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

                        # Tool 返回字符串时直接传递，其他类型序列化为 JSON
                        if isinstance(result_data, str):
                            content = result_data
                        else:
                            content = json.dumps(result_data, ensure_ascii=False)

                        await orchestrator.message_manager.add_tool_message(
                            content=content,
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
                assembled_messages = agent.context_assembler.build_messages(
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
                        
                        # Tool 返回字符串时直接传递，其他类型序列化为 JSON
                        if isinstance(result_data, str):
                            content = result_data
                        else:
                            content = json.dumps(result_data, ensure_ascii=False)
                        
                        await agent.message_manager.add_tool_message(
                            content=content,
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
                    assembled_messages = orchestrator.context_assembler.build_messages(
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

                            # Tool 返回字符串时直接传递，其他类型序列化为 JSON
                            if isinstance(result_data, str):
                                content = result_data
                            else:
                                content = json.dumps(result_data, ensure_ascii=False)

                            await orchestrator.message_manager.add_tool_message(
                                content=content,
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
                workflow_id = result.workflow_id
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
        lines = [
            "# Workflow 规划任务",
            "",
            f"## 名称",
            f"{workflow_context.name}",
            "",
            f"## 描述",
            f"{workflow_context.description}",
            "",
        ]

        if workflow_context.target and workflow_context.target.path:
            lines.extend([
                f"## 目标",
                f"{workflow_context.target.path}",
                "",
            ])

        if workflow_context.scope:
            lines.extend([
                f"## 分析范围",
                f"{workflow_context.scope.description}",
                "",
            ])

        if workflow_context.vulnerability_focus:
            lines.extend([
                f"## 漏洞关注点",
                f"{workflow_context.vulnerability_focus}",
                "",
            ])

        if workflow_context.background_knowledge:
            lines.extend([
                f"## 背景知识",
                f"{workflow_context.background_knowledge}",
                "",
            ])

        if workflow_context.raw_markdown:
            lines.extend([
                f"## 完整 Workflow 文档",
                f"```markdown",
                f"{workflow_context.raw_markdown}",
                f"```",
                "",
            ])

        lines.extend([
            "## 你的任务",
            "",
            "分析上述 Workflow 文档，判断是否需要拆分为多个独立的子 workflow。",
            "",
            "### 判断标准",
            "",
            "使用**单 workflow 模式**的场景：",
            "- 整个分析是一个连贯的流程",
            "- 任务之间有明确的依赖关系",
            "- 需要共享分析上下文",
            "",
            "使用**多 workflow 模式**的场景：",
            "- 存在多个独立的分析目标（如多个组件、多个漏洞类型）",
            "- 各个分析流程可以完全独立执行",
            "- 可以并行执行以提高效率",
            "",
            "### 输出要求",
            "",
            "调用 `plan_tasks(workflows)` 工具进行规划。",
            "若存在 vuln_analysis 且 function_identifier 未明确：先调用 `delegate_task(agent_type=\"code_explorer\")` 使用 `search_symbol` 获取标准标识符，再调用 `plan_tasks`。",
            "",
            "**单 workflow 示例**：",
            "```json",
            "{",
            '    "workflows": [',
            "        {",
            '            "tasks": [',
            '                "任务1描述",',
            '                "任务2描述"',
            "            ]",
            "        }",
            "    ]",
            "}",
            "```",
            "",
            "**多 workflow 示例**：",
            "```json",
            "{",
            '    "workflows": [',
            "        {",
            '            "workflow_id": "wf_component_a",',
            '            "workflow_name": "组件A分析",',
            '            "workflow_description": "分析组件A的安全问题",',
            '            "tasks": ["搜索组件A", "分析组件A的漏洞"]',
            "        },",
            "        {",
            '            "workflow_id": "wf_component_b",',
            '            "workflow_name": "组件B分析",',
            '            "workflow_description": "分析组件B的安全问题",',
            '            "tasks": ["搜索组件B", "分析组件B的漏洞"]',
            "        }",
            "    ]",
            "}",
            "```",
            "",
            "现在开始规划。",
        ])

        return "\n".join(lines)
    
    def _get_planning_system_prompt(self) -> str:
        """获取规划阶段的 system prompt

        Returns:
            System prompt 字符串
        """
        return """# 角色定义

你是一个 Workflow 规划专家，负责分析漏洞挖掘 workflow 并决定执行策略。

# 工作职责

1. 分析 Workflow 文档，理解分析目标和要求
2. 识别独立的分析目标（如不同的组件、不同的漏洞类型、不同的攻击面）
3. 根据分析目标的独立性，决定是否拆分为多个 workflow
4. 调用 `plan_tasks(workflows)` 工具进行规划
5. **若存在 vuln_analysis 但 function_identifier 未明确：必须先调用 `delegate_task(agent_type="code_explorer", ...)`，要求使用 `search_symbol` 查找并返回标准标识符，然后再调用 `plan_tasks`**

# 关于任务描述中的 Agent 类型标识

任务描述可能包含 Agent 类型标识，格式为：`任务X（agent_type）：任务内容`

常见的 Agent 类型：
- `code_explorer`：代码搜索和探索任务
- `vuln_analysis`：漏洞分析任务  
- `function_summary`：函数摘要任务

**重要**：Agent 类型标识只是说明该任务由哪个 agent 执行，**不是拆分 workflow 的依据**。

一个完整的漏洞挖掘流程通常包含：
1. 搜索阶段（code_explorer）：定位目标代码
2. 分析阶段（vuln_analysis）：分析安全风险

这两个阶段应该在同一个 workflow 中，因为它们针对同一个分析目标。

# 判断标准

## 单 Workflow 模式

当满足以下条件时，使用单 workflow：
- 整个分析针对单一的目标或漏洞类型
- 任务之间有明确的依赖关系
- 需要共享分析上下文
- 分析流程是连贯的

## 多 Workflow 模式

当满足以下条件时，使用多 workflow：
- 存在多个独立的分析目标（如多个组件、多个漏洞类型、多个攻击面）
- 各个分析流程可以完全独立执行，互不依赖
- 可以并行执行以提高效率
- 每个子 workflow 有明确的边界

# 拆分策略

## 识别独立的分析目标

通过分析任务内容，识别不同的分析目标。例如：
- 任务1-3 都针对"组件A"的漏洞 → 分析目标1
- 任务4-6 都针对"组件B"的漏洞 → 分析目标2
- 任务7-9 都针对"漏洞类型X" → 分析目标3

## 分组原则

1. **按分析目标分组**：将针对同一分析目标的任务分到同一个 workflow
2. **保持完整流程**：每个 workflow 应包含完整的"搜索 → 分析"流程
3. **保持任务顺序**：同一 workflow 内的任务保持原有顺序
4. **清理任务描述**：从任务描述中移除 Agent 类型标识，只保留任务内容

## 示例

### 输入任务列表：
```
任务1（code_explorer）：搜索所有网络请求处理函数
任务2（vuln_analysis）：分析网络请求中的命令注入风险
任务3（code_explorer）：搜索所有文件操作相关函数
任务4（vuln_analysis）：分析文件操作中的路径遍历风险
任务5（code_explorer）：搜索所有加密算法使用位置
任务6（vuln_analysis）：分析加密实现的安全性
```

### 分析过程：
- 任务1-2：针对"网络请求"的漏洞挖掘（搜索 + 分析）
- 任务3-4：针对"文件操作"的漏洞挖掘（搜索 + 分析）
- 任务5-6：针对"加密算法"的安全分析（搜索 + 分析）

这是 3 个独立的分析目标，应该拆分为 3 个 workflow。

### 输出（多 Workflow 模式）：
```json
{
  "workflows": [
    {
      "workflow_id": "workflow_1",
      "workflow_name": "网络请求安全分析",
      "workflow_description": "分析网络请求处理中的命令注入风险",
      "tasks": [
        "搜索所有网络请求处理函数",
        "分析网络请求中的命令注入风险"
      ]
    },
    {
      "workflow_id": "workflow_2",
      "workflow_name": "文件操作安全分析",
      "workflow_description": "分析文件操作中的路径遍历风险",
      "tasks": [
        "搜索所有文件操作相关函数",
        "分析文件操作中的路径遍历风险"
      ]
    },
    {
      "workflow_id": "workflow_3",
      "workflow_name": "加密算法安全分析",
      "workflow_description": "分析加密实现的安全性",
      "tasks": [
        "搜索所有加密算法使用位置",
        "分析加密实现的安全性"
      ]
    }
  ]
}
```

注意：
- 每个 workflow 包含完整的"搜索 + 分析"流程
- 任务描述中的 Agent 类型标识已被移除
- 每个 workflow 有明确的分析目标

# 规划原则

1. **分析目标优先**：优先根据分析目标的独立性拆分 workflow
2. **保持流程完整**：每个 workflow 应包含完整的分析流程
3. **合理粒度**：每个子 workflow 应该有明确的目标和边界
4. **任务清晰**：每个任务描述应该具体、可执行，移除 Agent 类型标识
5. **避免过度拆分**：不要为了拆分而拆分，保持合理的粒度

# 输出要求

必须调用 `plan_tasks(workflows)` 工具，不要输出其他内容。
若需要 function_identifier，可先调用 `delegate_task(agent_type="code_explorer")` 使用 `search_symbol` 验证获取，再在 plan_tasks 中原样填写。

现在开始你的工作。
"""

    
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
            
            # 5. 检查规划结果，决定执行模式
            if orchestrator.tools_manager.is_multi_workflow():
                # 多 workflow 模式
                workflows = orchestrator.tools_manager.get_planned_workflows()
                self._log(f"检测到多 workflow 模式，共 {len(workflows)} 个 workflow")
                return await self._execute_multi_workflows(workflows, self.engine, self.workflow_context)
            else:
                # 单 workflow 模式
                self._log("检测到单 workflow 模式")
                return await self._execute_single_workflow(orchestrator)
        
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
        workflow_results: List[WorkflowAgentResult],
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
                f"- Workflow ID: {result.workflow_id}",
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
