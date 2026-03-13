#!/usr/bin/env python3
"""
TaskOrchestratorAgent - LLM 驱动的任务规划 Agent

通过 Tools 暴露能力，由 LLM 自主决策执行流程。
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from pathlib import Path
import json
import asyncio

from langchain_openai import ChatOpenAI
from langchain_core.messages import ToolMessage


from ..models.skill import SkillContext
from ..core.summary_service import SummaryService
from ..core.tool_llm_client import ToolBasedLLMClient
from ..core.cli_logger import CLILogger
from ..core.context import ArtifactStore, MessageManager, ContextAssembler, ContextCompressor, ReadArtifactPruner
from .tools import OrchestratorTools
from .planning_prompts import (
    build_execution_system_prompt,
    build_planning_user_prompt,
)




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

    职责定义:
    - 根据用户请求规划漏洞挖掘任务并拆分子任务
    - 通过 plan_tasks 记录规划结果
    - 执行过程中根据子 Agent 返回动态追加任务（append_tasks）

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
        skill_context: Optional[SkillContext] = None,
        verbose: bool = True,
        enable_logging: bool = True,
        session_id: Optional[str] = None,
        context_token_threshold: int = 24000,
        max_inline_chars: int = 4000,
        artifacts_dir: Optional[str] = None,
    ):

        self.llm = llm_client
        self.skill_context = skill_context
        self.verbose = verbose
        self.enable_logging = enable_logging
        self.session_id = session_id or f"session_{id(self)}"
        self.agent_id = f"orchestrator_{id(self)}"
        self.context_token_threshold = context_token_threshold
        self.max_inline_chars = max_inline_chars
        self.artifacts_dir = artifacts_dir
        self.source_root = source_root
        self._logger = CLILogger(component="Orchestrator", verbose=verbose)
        
        # 初始化 Tools（如果提供了 engine_type 和 target_path 则立即初始化 engine）
        self.tools_manager = OrchestratorTools(
            llm_client=llm_client,
            skill_context=skill_context,
            engine_type=engine_type,
            target_path=target_path,
            source_root=source_root,
            session_id=self.session_id,
            verbose=verbose,
            logger=self._logger,
        )
        self.tools: List[Any] = []
        
        # 确定目标函数显示内容
        if target_path:
            target_function = target_path
        elif skill_context and skill_context.name:
            target_function = f"skill: {skill_context.name}"
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

        # 初始化摘要服务
        self.summary_service = SummaryService(
            llm_client=self.llm,
            max_retries=2,
            retry_delay=1.0,
            enable_logging=self.enable_logging,
            verbose=self.verbose,
            session_id=self.session_id,
            agent_id=self.agent_id,
            agent_type="orchestrator",
            target_function=target_function,
        )
        self.tools_manager.summary_service = self.summary_service
        self.tools_manager.tool_output_summary_threshold = self.max_inline_chars

        # 初始化上下文管理组件
        artifact_dir = self._resolve_artifact_dir(source_root)
        self.artifact_store = ArtifactStore(artifact_dir)
        self.message_manager = MessageManager(
            artifact_store=self.artifact_store,
            max_inline_chars=self.max_inline_chars,
        )
        self.context_compressor = ContextCompressor(
            summary_service=self.summary_service,
            compression_profile="orchestrator",
            consumer_agent="orchestrator",
            compression_purpose="workflow orchestration and task execution continuity",
        )
        self.read_artifact_pruner = ReadArtifactPruner()
        self.context_assembler = ContextAssembler(
            message_manager=self.message_manager,
            compressor=self.context_compressor,
            read_artifact_pruner=self.read_artifact_pruner,
            token_threshold=self.context_token_threshold,
            compression_profile="orchestrator",
            compression_consumer="orchestrator",
            compression_purpose="workflow orchestration and task execution continuity",
        )
        self.tools_manager.set_artifact_store(self.artifact_store)
        self.tools_manager.set_message_manager(self.message_manager)
        
        # 初始化新的任务编排组件（简化设计）
        self._init_orchestrator_components(emit_log=True)
        
        self.tools = self.tools_manager.get_tools()


    def _log(self, message: str, level: str = "info"):
        """打印日志"""
        if not self.verbose:
            return
        self._logger.log(level=level, event="orchestrator.event", message=message)

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

    def _init_orchestrator_components(self, emit_log: bool = True):
        """初始化简化的任务编排组件（TaskListManager, AgentDelegate）"""
        # 确定 session 目录
        session_dir = self._resolve_session_dir()
        
        # 初始化 OrchestratorTools 的新组件
        self.tools_manager.initialize_orchestrator_components(session_dir)
        
        if emit_log:
            self._log(f"初始化 session 目录: {session_dir}")

    def _resolve_session_dir(self) -> Path:
        """确定 session 目录路径"""
        if self.artifacts_dir:
            base_dir = Path(self.artifacts_dir)
        else:
            base_root = Path(self.source_root) if self.source_root else Path.cwd()
            base_dir = base_root / ".ivagent" / "sessions"
        
        return base_dir / self.session_id

    def _resolve_artifact_dir(self, source_root: Optional[str]) -> Path:
        """确定统一 Artifact 落盘目录（session 级）。"""
        return self._resolve_session_dir() / "artifacts"

    async def execute_skill(self, skill: Optional[SkillContext] = None, target_path: str = None) -> OrchestratorResult:
        """
        执行 Skill（简化版）

        新的执行流程：
        1. 使用 SkillContext（如果提供了 skill）
        2. 引导 LLM 调用 plan_tasks() 规划任务（如果提供了 skill）
        3. 循环引导 LLM 调用 execute_task()/execute_tasks() 执行任务
        4. 检测所有任务完成后结束

        Args:
            skill: Skill 上下文（可选，如果为 None 则跳过规划）
            target_path: 目标程序路径（可选）

        Returns:
            OrchestratorResult 执行结果
        """
        if skill:
            self.skill_context = skill

            # 异步初始化引擎（如果有待处理的引擎配置）
            if not self.tools_manager._initialized:
                self._log("正在初始化分析引擎...")
                try:
                    final_target = target_path

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
                    
                    # 重新初始化 orchestrator 组件（需要 engine）
                    self._init_orchestrator_components()
                    
                except Exception as e:
                    return OrchestratorResult(
                        success=False,
                        vulnerabilities_found=0,
                        report="",
                        summary=f"Engine initialization failed: {e}",
                        errors=[str(e)],
                    )

            # 更新 Tools 的 Skill 上下文
            self.tools_manager.skill_context = self.skill_context

            self._log("Skill 加载成功")
            self._log(f"名称: {self.skill_context.name}")

            final_target = target_path
            if final_target:
                self._log(f"目标: {final_target}")

            # 构建规划 Prompt（引导 LLM 使用简化的 Tools）
            planning_prompt = self._build_simplified_planning_prompt(target_path=final_target)

            # 让 LLM 自主规划并执行
            await self.message_manager.add_user_message(planning_prompt)
        else:
            self._log("跳过 Skill 规划，直接进入任务执行循环")

        max_iterations = 20
        iteration = 0
        errors = []
        stall_rounds = 0
        forced_stop_reason: Optional[str] = None

        try:
            while True:
                iteration += 1
                self._log(f"执行迭代 {iteration}/{max_iterations}")

                # 检查是否超过最大迭代次数
                if iteration > max_iterations:
                    self._log(f"达到最大迭代次数 {max_iterations}，结束执行", "warning")
                    break

                # 组装上下文并调用 LLM
                assembled_messages = await self.context_assembler.build_messages(
                    system_prompt=self._get_simplified_system_prompt(),
                )
                
                result = await self.llm_client_wrapper.atool_call(
                    messages=assembled_messages,
                    tools=self.tools,
                    system_prompt=None,
                )

                # 记录 AI 消息
                await self.message_manager.add_ai_message(
                    result.content or "",
                    tool_calls=result.tool_calls,
                )

                # 检查是否有 Tool 调用
                if not result.tool_calls:
                    task_manager = getattr(self.tools_manager, "_task_list_manager", None)
                    if task_manager and not task_manager.is_all_completed():
                        stall_rounds += 1
                        self._log(
                            f"LLM 未调用工具且任务未完成，进入恢复引导 ({stall_rounds}/3)",
                            "warning",
                        )
                        await self.message_manager.add_user_message(
                            "任务尚未完成，必须继续调用工具。"
                            "如果工具返回错误，请先根据错误码和错误原因修复后再继续。"
                            "不要重复无效调用；必要时先取证再重试执行。"
                        )
                        if stall_rounds >= 3:
                            forced_stop_reason = "LLM 连续 3 轮未调用工具且任务未完成，保护性终止。"
                            errors.append(forced_stop_reason)
                            break
                        continue
                    # 如果没有 tool calls，说明 LLM 认为任务已完成
                    self._log("LLM 完成执行，结束", "success")
                    break

                # 并发执行所有 Tool 调用
                stall_rounds = 0
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

                        content, summary = self._normalize_tool_output(result_data)
                        await self.message_manager.add_tool_message(
                            content=content,
                            summary=summary,
                            tool_name=tool_name,
                            tool_call_id=tool_id,
                        )

                        return ToolMessage(
                            content=content,
                            tool_call_id=tool_id,
                            name=tool_name,
                        )

                    except Exception as e:
                        error_msg = str(e)
                        self._log(f"Tool 执行失败: {error_msg}", "error")
                        errors.append(f"{tool_name}: {error_msg}")

                        error_content = json.dumps({"error": error_msg}, ensure_ascii=False)
                        await self.message_manager.add_tool_message(
                            content=error_content,
                            tool_name=tool_name,
                            tool_call_id=tool_id,
                        )

                        return ToolMessage(
                            content=error_content,
                            tool_call_id=tool_id,
                            name=tool_name,
                        )

                # 并发执行所有 tool calls
                if result.tool_calls:
                    tool_tasks = [
                        execute_single_tool(tc) for tc in result.tool_calls
                    ]
                    await asyncio.gather(*tool_tasks)

            # 最终结果报告
            self._log("任务执行完成", "success")
            task_manager = getattr(self.tools_manager, "_task_list_manager", None)
            tasks_completed = True
            if task_manager:
                tasks_completed = task_manager.is_all_completed()
            success = tasks_completed and forced_stop_reason is None
            if not success:
                self._log("任务未全部完成，执行结束为失败状态", "warning")

            return OrchestratorResult(
                success=success,
                vulnerabilities_found=len(self.tools_manager.vulnerabilities),
                report="分析完成",
                summary="分析完成" if success else "执行结束，但任务未全部完成",
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

    async def _execute_tool(self, tool_name: str, tool_args: Dict[str, Any]) -> Dict[str, Any]:

        """执行指定的 Tool"""
        tool_map = {
            # 简化的任务编排工具（新设计）
            "plan_tasks": self.tools_manager.plan_tasks,
            "append_tasks": self.tools_manager.append_tasks,
            "list_runnable_tasks": self.tools_manager.list_runnable_tasks,
            "compose_task_context": self.tools_manager.compose_task_context,
            "execute_task": self.tools_manager.execute_task,
            "execute_tasks": self.tools_manager.execute_tasks,
            "resolve_function_identifier": self.tools_manager.resolve_function_identifier,
            "set_task_function_identifier": self.tools_manager.set_task_function_identifier,
            "get_task_status": self.tools_manager.get_task_status,
            "read_task_output": self.tools_manager.read_task_output,
            # 统一的 Agent 委托接口
            "delegate_task": self.tools_manager.delegate_task,
            # 数据访问工具
            "read_artifact": self.tools_manager.read_artifact,
            "list_artifacts": self.tools_manager.list_artifacts,
            "mark_compression_projection": self.tools_manager.mark_compression_projection,

        }

        tool_func = tool_map.get(tool_name)
        if not tool_func:
            return {"error": f"Unknown tool: {tool_name}"}

        return await tool_func(**tool_args)

    def _get_simplified_system_prompt(self) -> str:

        """获取简化版的 Orchestrator 系统提示词"""
        return build_execution_system_prompt()

    def _build_simplified_planning_prompt(self, target_path: str = None) -> str:
        """构建简化版的规划 Prompt"""
        if not self.skill_context:
            return "No skill context available."
        return build_planning_user_prompt(
            skill_context=self.skill_context,
            target_path=target_path,
        )
