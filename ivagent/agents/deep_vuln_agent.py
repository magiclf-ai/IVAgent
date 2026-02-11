#!/usr/bin/env python3
"""
DeepVulnAgent - 深度漏洞挖掘 Agent（Tool Call 模式）

基于 Tool Call 机制的深度漏洞检测系统。
支持约束传播、并发任务执行和可视化日志追踪。

工作流程:
    1. 获取目标函数源码和调用点信息
    2. LLM 分析源码，通过 Tool Call 获取子函数摘要或创建子 Agent
    3. 并发执行 Tool Call 请求
    4. LLM 基于收集的信息输出漏洞检测结果
    5. 递归创建子 Agent 挖掘深层次漏洞

特性:
    - 使用 Tool Call 替代结构化输出
    - 纯文本格式的参数约束传播
    - 调用栈追踪，防止递归死循环
    - 漏洞评分：置信度(1-10)、危害等级(低/中/高)
    - 完整的日志追踪和可视化
"""

from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
import asyncio
import uuid
import time
import json
from datetime import datetime

from pydantic import BaseModel, Field
from langchain_core.messages import HumanMessage, SystemMessage, BaseMessage, AIMessage, ToolMessage
from langchain_openai import ChatOpenAI
from langchain_core.tools import tool

from .base import BaseAgent
from .program_analyzer import ProgramAnalyzer
from .function_summary_agent import FunctionSummaryAgent
from .prompts import (
    get_vuln_agent_system_prompt,
    build_iteration_prompt,
)
from ..core.tool_llm_client import ToolBasedLLMClient, SimpleJSONLLMClient
from ..core.llm_logger import get_log_manager
from ..core.agent_logger import get_agent_log_manager, AgentStatus
from ..core.vuln_storage import get_vulnerability_manager
from ..models import (
    Vulnerability,
    VulnerabilityType,
    DataFlowPath,
    SimpleFunctionSummary,
    FunctionContext,
    Precondition,
    CallStackFrame,
)
from ..models.callsite import CallsiteInfo, ResolvedCallsite


# ============================================================================
# Tool Call 工具函数定义
# ============================================================================

def get_function_summary_tool(
        line_number: int,
        column_number: int,
        function_identifier: str,
        arguments: List[str],
        call_text: str,
) -> Dict[str, Any]:
    """获取子函数摘要。
    
    当需要了解子函数的行为和参数约束时调用此工具。
    通过提供调用点的位置信息（行号、列号、函数名等），Agent 会自动解析出具体的函数。
    
    Parameters:
        line_number: 调用所在行号（从代码左侧的方括号中获取，如 [ 8] 表示第8行）
        column_number: 调用所在列号（函数名开始的列）
        function_identifier: 目标函数唯一标识符（如 "sub_13E15CC"）
        arguments: 参数表达式列表（如 ["ptr", "size", "data"]）
        call_text: 完整调用文本（包含参数和调用语句，如 "result = func(ptr, size);")
    
    Example:
        对于代码：
        ```
        [   8]   result = sub_13E15CC(**(*(result + 272) + 72LL), *a2, &v3);
        ```
        
        调用参数：
        - line_number: 8
        - column_number: 16
        - function_identifier: "sub_13E15CC"
        - arguments: ["**(*(result + 272) + 72LL)", "*a2", "&v3"]
        - call_text: "result = sub_13E15CC(**(*(result + 272) + 72LL), *a2, &v3);"
    """
    # Returns: 函数摘要信息，包含 behavior_summary, param_constraints 等
    return {
        "callsite": {
            "line_number": line_number,
            "column_number": column_number,
            "function_identifier": function_identifier,
            "arguments": arguments,
            "call_text": call_text,
        }
    }


def create_sub_agent_tool(
        line_number: int,
        column_number: int,
        function_identifier: str,
        arguments: List[str],
        call_text: str,
        caller_function: str = "",
        argument_constraints: Optional[List[str]] = None,
        reason: str = "",
) -> Dict[str, Any]:
    """创建子 Agent 深入分析子函数。
    
    当污点数据传播到子函数中，或需要深入分析子函数时调用。
    通过提供调用点的位置信息（行号、列号、函数名等），Agent 会自动解析出具体的函数。
    
    Parameters:
        line_number: 调用所在行号（从代码左侧的方括号中获取，如 [ 8] 表示第8行）
        column_number: 调用所在列号（函数名开始的列）
        function_identifier: 目标函数唯一标识符
        arguments: 参数表达式列表（如 ["ptr", "size", "data"]）
        call_text: 完整调用文本（包含参数和调用语句，如 "result = func(ptr, size);")
        caller_function: 调用者函数名
        argument_constraints: 参数约束列表（纯文本格式）
        reason: 创建原因
    
    Example:
        对于代码：
        ```
        [   8]   result = sub_13E15CC(**(*(result + 272) + 72LL), *a2, &v3);
        ```
        
        调用参数：
        - line_number: 8
        - column_number: 16
        - function_identifier: "sub_13E15CC"
        - arguments: ["**(*(result + 272) + 72LL)", "*a2", "&v3"]
        - call_text: "result = sub_13E15CC(**(*(result + 272) + 72LL), *a2, &v3);"
        - caller_function: "sub_13E16E8"
        - argument_constraints: ["参数1: 污点数据"]
        - reason: "污点数据传播到子函数"
    """
    # Returns: 子 Agent 创建结果
    return {
        "callsite": {
            "line_number": line_number,
            "column_number": column_number,
            "function_identifier": function_identifier,
            "arguments": arguments,
            "call_text": call_text,
        },
        "caller_function": caller_function,
        "argument_constraints": argument_constraints or [],
        "reason": reason,
    }


def report_vulnerability_tool(
        vuln_type: str,
        name: str,
        description: str,
        location: str,
        confidence: int,
        severity: str,
        data_flow_source: str = "",
        data_flow_sink: str = "",
        data_flow_intermediate: Optional[List[str]] = None,
        remediation: str = "",
        evidence: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """报告发现的漏洞。
    
    当你在当前函数中发现安全漏洞时，调用此工具报告漏洞详情。
    可以在任意分析迭代轮次中调用，无需等到最后。
    
    Parameters:
        vuln_type: 漏洞类型，如 BUFFER_OVERFLOW, ARRAY_OOB, NULL_POINTER, FORMAT_STRING 等
        name: 漏洞名称
        description: 详细描述，包括漏洞原理、利用条件等
        location: 漏洞位置，如 "第 15 行 memcpy 调用"
        confidence: 置信度 1-10（10 表示非常确定）
        severity: 危害等级 LOW/MEDIUM/HIGH
        data_flow_source: 污点源变量名
        data_flow_sink: 汇聚点（漏洞点）变量名
        data_flow_intermediate: 中间传播节点列表
        remediation: 修复建议
        evidence: 证据代码行列表
    
    Example:
        report_vulnerability_tool(
            vuln_type="BUFFER_OVERFLOW",
            name="缓冲区溢出",
            description="函数使用 memcpy 拷贝数据时未检查长度，导致缓冲区溢出",
            location="第 15 行 memcpy(dst, src, len)",
            confidence=8,
            severity="HIGH",
            data_flow_source="src（用户输入）",
            data_flow_sink="dst（局部缓冲区）",
            data_flow_intermediate=["len"],
            remediation="添加长度检查：if (len > sizeof(dst)) return -1;",
            evidence=["[  15]     memcpy(buf, input, len);"]
        )
    """
    # Returns: 漏洞报告确认
    return {
        "vulnerability": {
            "type": vuln_type,
            "name": name,
            "description": description,
            "location": location,
            "confidence": confidence,
            "severity": severity,
            "data_flow": {
                "source": data_flow_source,
                "sink": data_flow_sink,
                "intermediate": data_flow_intermediate or [],
            },
            "remediation": remediation,
            "evidence": evidence or [],
        }
    }


def finalize_analysis_tool(
        analysis_summary: str = "",
        constraints_extracted: Optional[List[str]] = None,
        taint_sources_identified: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """完成分析并输出最终漏洞报告。
    
    当你认为已经收集了足够的信息，可以输出最终漏洞分析结果时调用此工具。
    这是分析的最后一个步骤，调用后将结束当前的迭代循环。
    
    注意：如果你已经在分析过程中通过 `report_vulnerability_tool` 报告了漏洞，
    此处只需提供分析总结，无需重复列出漏洞详情。
    
    Parameters:
        analysis_summary: 分析总结
        constraints_extracted: 提取的约束条件列表
        taint_sources_identified: 识别的污点源列表
    
    Example:
        finalize_analysis_tool(
            analysis_summary="函数存在缓冲区溢出漏洞...",
            constraints_extracted=["size <= 1024", "ptr != NULL"],
            taint_sources_identified=["user_input", "param_1"]
        )
    """
    # Returns: 最终分析结果标记
    return {
        "analysis_summary": analysis_summary,
        "constraints_extracted": constraints_extracted or [],
        "taint_sources_identified": taint_sources_identified or [],
        "finalize": True,
    }


# ============================================================================
# 简化数据结构（用于最终报告）
# ============================================================================

class DataFlowNode(BaseModel):
    """数据流节点"""
    variable: str = Field(description="变量名")
    line_number: int = Field(default=0, description="代码行号")
    code_line: str = Field(default="", description="该行完整代码")
    function: str = Field(default="", description="所在函数")


class DataFlowInfo(BaseModel):
    """数据流信息"""
    source: str = Field(default="", description="污点源")
    source_node: Optional[DataFlowNode] = Field(default=None, description="污点源节点详情")
    intermediate: List[str] = Field(default_factory=list, description="中间变量")
    intermediate_nodes: List[DataFlowNode] = Field(default_factory=list, description="中间节点详情")
    sink: str = Field(default="", description="漏洞点")
    sink_node: Optional[DataFlowNode] = Field(default=None, description="漏洞点节点详情")


class VulnerabilityResult(BaseModel):
    """
    漏洞检测结果（最终报告阶段使用，简化结构）
    """
    type: str = Field(description="漏洞类型")
    name: str = Field(description="漏洞名称")
    description: str = Field(description="详细描述")
    location: str = Field(description="位置")
    confidence: int = Field(ge=1, le=10, description="置信度 1-10")
    severity: str = Field(description="危害等级: LOW/MEDIUM/HIGH")
    evidence: List[str] = Field(default_factory=list, description="证据列表")
    evidence_code_lines: List[Dict[str, Any]] = Field(default_factory=list)
    data_flow: DataFlowInfo = Field(default_factory=DataFlowInfo)
    remediation: str = Field(default="", description="修复建议")
    constraints_satisfied: bool = Field(default=False)


class FinalAnalysisOutput(BaseModel):
    """最终分析输出（简化结构）"""
    vulnerabilities: List[VulnerabilityResult] = Field(default_factory=list)
    constraints_extracted: List[str] = Field(default_factory=list, description="纯文本约束列表")
    taint_sources_identified: List[str] = Field(default_factory=list)
    summary: str = Field(default="", description="分析总结")


# ============================================================================
# Agent 执行状态
# ============================================================================

@dataclass
class AgentExecutionState:
    """Agent 执行状态"""
    agent_id: str
    parent_id: Optional[str]
    function_identifier: str
    call_stack: List[str]
    depth: int
    start_time: datetime
    status: str = "running"  # running, completed, failed
    vulnerabilities_found: int = 0
    sub_agents_created: int = 0
    llm_calls: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "parent_id": self.parent_id,
            "function_identifier": self.function_identifier,
            "call_stack": self.call_stack,
            "depth": self.depth,
            "start_time": self.start_time.isoformat(),
            "status": self.status,
            "vulnerabilities_found": self.vulnerabilities_found,
            "sub_agents_created": self.sub_agents_created,
            "llm_calls": self.llm_calls,
        }


# ============================================================================
# DeepVulnAgent 主类
# ============================================================================

class DeepVulnAgent(BaseAgent):
    """
    深度漏洞挖掘 Agent
    
    基于多轮 LLM 交互和递归子 Agent 分析的漏洞检测系统。
    
    核心设计:
    1. LLM 驱动: LLM 决定需要获取哪些子函数信息
    2. 并发执行: 单轮中所有 task 并行执行
    3. 递归分析: 创建子 Agent 深入分析调用链
    4. 约束传播: 父 Agent 向子 Agent 传递约束条件
    5. 循环检测: 调用栈追踪防止死循环
    """

    # 类级别的执行状态追踪（用于可视化）
    _execution_states: Dict[str, AgentExecutionState] = {}
    _states_lock = asyncio.Lock()

    def __init__(
            self,
            engine: Any,
            llm_client: ChatOpenAI,
            max_iterations: int = 10,
            verbose: bool = False,
            max_concurrency: int = 5,
            max_depth: int = 3,
            parent_id: Optional[str] = None,
            call_stack: Optional[List[str]] = None,
            call_stack_detailed: Optional[List[CallStackFrame]] = None,
            precondition: Optional[Precondition] = None,
            progress_logger: Optional[Any] = None,
            source_root: Optional[str] = None,
            system_prompt: Optional[str] = None,
    ):
        """
        初始化 DeepVulnAgent
        
        Args:
            engine: 分析引擎
            llm_client: LLM 客户端
            max_iterations: 最大 LLM 交互轮数
            verbose: 是否打印详细日志
            max_concurrency: 最大并发数
            max_depth: 最大递归深度
            parent_id: 父 Agent ID
            call_stack: 当前调用栈（简单版本，函数签名列表）
            call_stack_detailed: 详细调用栈，包含调用点信息
            precondition: 前置条件定义
            progress_logger: 进度日志回调函数，接收 (message, level) 参数
            source_root: 源码根目录（用于 CallsiteAgent）
            system_prompt: 自定义系统提示词（用于 Orchestrator 动态注入）
        """
        super().__init__(
            engine=engine,
            llm_client=llm_client,
            max_iterations=max_iterations,
            verbose=verbose,
            max_concurrency=max_concurrency,
        )

        # 自定义系统提示词（用于 Orchestrator 动态注入）
        self._custom_system_prompt = system_prompt

        # 源码根目录，用于 CallsiteAgent
        self.source_root = source_root or getattr(engine, 'project_root', '.')

        # Determine engine type
        engine_cls = self.engine.__class__.__name__.lower()
        if 'jeb' in engine_cls:
            self.engine_type = 'jeb'
            self.code_lang = 'java'
        elif 'abc' in engine_cls:
            self.engine_type = 'abc'
            self.code_lang = 'typescript'
        else:
            self.engine_type = 'ida'
            self.code_lang = 'c'

        # Agent ID
        self.agent_id = str(uuid.uuid4())

        # Tool Call LLM 客户端
        self.tool_llm = ToolBasedLLMClient(
            llm=llm_client,
            max_retries=3,
            verbose=verbose,
            session_id=str(uuid.uuid4()),
            agent_id=self.agent_id,
        )

        # JSON 模式客户端（兼容模式）
        self.json_llm = SimpleJSONLLMClient(
            llm=llm_client,
            max_retries=3,
            verbose=verbose,
        )

        # 递归控制
        self.max_depth = max_depth
        self.parent_id = parent_id

        # 调用栈 - 支持两种格式
        self.call_stack = call_stack or []
        self.call_stack_detailed: List[CallStackFrame] = call_stack_detailed or []

        # 确保两种调用栈格式同步
        self._sync_call_stack_formats()

        # 前置条件
        self.precondition = precondition

        # 程序分析器
        self.program_analyzer = ProgramAnalyzer(
            engine=engine,
            llm_client=llm_client,
            max_iterations=5,
            verbose=verbose,
            max_concurrency=max_concurrency,
        )

        # 函数摘要 Agent
        self.summary_agent = FunctionSummaryAgent(
            engine=engine,
            llm_client=llm_client,
            max_depth=2,
            verbose=verbose,
            source_root=self.source_root,
        )

        # 执行状态
        self.execution_state: Optional[AgentExecutionState] = None

        # 结果存储
        self.vulnerabilities: List[Vulnerability] = []
        self.sub_summaries: Dict[str, SimpleFunctionSummary] = {}
        self._vuln_lock = asyncio.Lock()

        # 子 Agent 任务列表（用于等待所有子任务完成）
        self._sub_agent_tasks: List[asyncio.Task] = []

        # 追踪重复请求的函数（用于多轮对话反馈）
        self._duplicate_requests: List[Dict[str, Any]] = []

        # 进度日志回调
        self._progress_logger = progress_logger

        # Agent 日志管理器
        self._agent_logger = get_agent_log_manager()

    def _sync_call_stack_formats(self):
        """同步两种调用栈格式"""
        if self.call_stack and not self.call_stack_detailed:
            # 从简单格式构建详细格式（信息可能不完整）
            self.call_stack_detailed = [
                CallStackFrame(function_identifier=sig)
                for sig in self.call_stack
            ]
        elif self.call_stack_detailed and not self.call_stack:
            # 从详细格式构建简单格式
            self.call_stack = [
                frame.function_identifier for frame in self.call_stack_detailed
            ]

    def _log_progress(self, message: str, level: str = "info"):
        """
        记录进度日志

        Args:
            message: 日志消息
            level: 日志级别 (info, warning, error, success)
        """
        # 如果有外部日志回调，交给外部处理，避免重复打印
        if self._progress_logger:
            try:
                self._progress_logger(message, level)
            except Exception:
                pass
            return

        # 构建有意义的标识符：函数名 + Agent类型
        if self.execution_state and self.execution_state.function_identifier:
            # 提取函数名（从标识符中提取）
            func_sig = self.execution_state.function_identifier
            # 尝试提取简单函数名
            if '(' in func_sig:
                func_name = func_sig[:func_sig.index('(')].strip()
            else:
                func_name = func_sig
            # 如果太长，截断
            if len(func_name) > 30:
                func_name = "..." + func_name[-27:]
            prefix = f"[{func_name} | 漏洞挖掘Agent]"
        else:
            prefix = "[初始化 | 漏洞挖掘Agent]"

        if level == "error":
            print(f"  [X] {prefix} {message}")
        elif level == "warning":
            print(f"  [!] {prefix} {message}")
        elif level == "success":
            print(f"  [+] {prefix} {message}")
        else:
            print(f"  [*] {prefix} {message}")

    async def _register_execution_state(self, function_identifier: str):
        """注册执行状态"""
        self.execution_state = AgentExecutionState(
            agent_id=self.agent_id,
            parent_id=self.parent_id,
            function_identifier=function_identifier,
            call_stack=self.call_stack.copy(),
            depth=len(self.call_stack),
            start_time=datetime.now(),
        )
        async with DeepVulnAgent._states_lock:
            DeepVulnAgent._execution_states[self.agent_id] = self.execution_state

        # 记录到 Agent 日志系统
        self._agent_logger.log_execution_start(
            agent_id=self.agent_id,
            agent_type="DeepVulnAgent",
            target_function=function_identifier,
            parent_id=self.parent_id,
            call_stack=self.call_stack.copy(),
        )

    async def _update_execution_state(self, **kwargs):
        """更新执行状态"""
        if self.execution_state:
            for key, value in kwargs.items():
                if hasattr(self.execution_state, key):
                    setattr(self.execution_state, key, value)

    async def run(
            self,
            function_identifier: str,
            context: Optional[FunctionContext] = None,
    ) -> Dict[str, Any]:
        """
        执行漏洞挖掘
        
        Args:
            function_identifier: 目标函数唯一标识符（全局唯一）
            context: 函数分析上下文（包含约束、污点源等）
        
        Returns:
            包含漏洞列表和约束信息的字典
        """
        await self._register_execution_state(function_identifier)

        self._log_progress(f"开始分析函数: {function_identifier}")
        self._log_progress(f"调用深度: {len(self.call_stack)}/{self.max_depth}")

        if self.precondition:
            self._log_progress(f"前置条件: {self.precondition.name}", "info")

        result = None
        try:
            result = await self._deep_analysis(function_identifier, context)
            await self._update_execution_state(status="completed")
            vuln_count = len(result.get("vulnerabilities", []))
            self._agent_logger.log_execution_end(
                agent_id=self.agent_id,
                status=AgentStatus.COMPLETED,
                vulnerabilities_found=vuln_count,
                llm_calls=self.execution_state.llm_calls if self.execution_state else 0,
                summary=f"Deep analysis completed, found {vuln_count} vulnerabilities"
            )
            self._log_progress(f"深度分析完成，发现 {vuln_count} 个漏洞", "success")

        except Exception as e:
            error_msg = str(e)
            self._log_progress(f"分析失败: {error_msg}", "error")
            await self._update_execution_state(status="failed")
            self._agent_logger.log_execution_end(
                agent_id=self.agent_id,
                status=AgentStatus.FAILED,
                llm_calls=self.execution_state.llm_calls if self.execution_state else 0,
                summary=f"Analysis failed: {error_msg}",
                error_message=error_msg
            )
            result = {"vulnerabilities": [], "constraints": [], "error": error_msg}

        finally:
            # 等待所有子 Agent 任务完成
            if self._sub_agent_tasks:
                self._log_progress(f"等待 {len(self._sub_agent_tasks)} 个子 Agent 完成...")
                await asyncio.gather(*self._sub_agent_tasks, return_exceptions=True)
                self._log_progress("所有子 Agent 已完成")

        return result

    async def _deep_analysis(
            self,
            function_identifier: str,
            context: Optional[FunctionContext],
    ) -> Dict[str, Any]:
        """
        深度漏洞分析 - 多轮对话模式
        
        工作流程：
        1. 初始化多轮对话，构建包含完整上下文的 messages 列表
        2. LLM 分析源码，通过 Tool Call 获取子函数摘要或创建子 Agent
        3. 将工具执行结果作为新消息追加到 messages
        4. 继续下一轮对话，直到分析完成
        
        改造要点：
        - 维护 messages 列表作为对话历史
        - 第一轮提供完整上下文（源码、调用点等）
        - 后续每轮只提供增量信息（工具执行结果）
        - 避免 LLM 重复请求已提供的信息
        """
        # 获取函数信息
        func_def = await self.engine.get_function_def(function_identifier)
        if not func_def:
            self._log_progress(f"获取方法定义失败: {function_identifier}")
            return {"vulnerabilities": [], "constraints": [], "error": "Failed to get function definition"}

        # 初始化上下文
        if context is None:
            context = FunctionContext(
                function_identifier=function_identifier,
                function_name=func_def.name,
                call_stack=self.call_stack + [function_identifier],
                call_stack_detailed=self.call_stack_detailed,
                depth=len(self.call_stack),
                max_depth=self.max_depth,
                precondition=self.precondition,
            )
        elif self.precondition and context.precondition is None:
            context.precondition = self.precondition

        # 如果前置条件定义了污点源，添加到上下文
        if self.precondition and self.precondition.taint_sources:
            for taint in self.precondition.taint_sources:
                if taint not in context.taint_sources:
                    context.taint_sources.append(taint)
            self._log_progress(f"从前置条件添加污点源: {context.taint_sources}")

        # 多轮对话状态
        all_vulnerabilities: List[VulnerabilityResult] = []
        sub_summaries: Dict[str, SimpleFunctionSummary] = {}

        # 跟踪已创建的子 Agent，避免重复创建
        created_sub_agents: Set[str] = set()
        created_sub_agent_signatures: List[str] = []

        # 跟踪已请求的函数摘要，避免重复请求
        requested_summaries: Set[str] = set()

        self._log_progress(f"开始多轮对话分析 (最多 {self.max_iterations} 轮)")

        # 初始化多轮对话的 messages 列表
        # 第一轮：使用 build_iteration_prompt 构建完整上下文
        initial_prompt = build_iteration_prompt(
            func_def=func_def,
            context=context,
            previous_results=[],
            iteration=0,
            sub_summaries={},  # 第一轮没有已获取的摘要
            created_subagents=[],
            is_max_depth=context.depth >= context.max_depth,
            duplicate_requests=[],
            code_lang=self.code_lang,
        )

        messages: List[BaseMessage] = [HumanMessage(content=initial_prompt)]

        for iteration in range(self.max_iterations):

            # LLM 分析迭代（多轮对话模式）
            tool_calls_result = await self._llm_analyze_with_messages(
                messages=messages,
                context=context,
                iteration=iteration,
            )

            await self._update_execution_state(llm_calls=self.execution_state.llm_calls + 1)

            # 添加 AI 回复到对话历史（包含 tool_calls 和文本回复）
            ai_message_content = tool_calls_result.get('content', '')
            ai_tool_calls = tool_calls_result.get('tool_calls', [])

            # 构建 AIMessage，包含 tool_calls
            ai_message = AIMessage(
                content=ai_message_content,
                additional_kwargs={
                    'tool_calls': [
                        {
                            'id': f"call_{iteration}_{idx}",
                            'type': 'function',
                            'function': {
                                'name': tc.get('name', ''),
                                'arguments': json.dumps(tc.get('args', {}))
                            }
                        }
                        for idx, tc in enumerate(ai_tool_calls)
                    ]
                } if ai_tool_calls else {}
            )
            messages.append(ai_message)

            # 处理 Tool Call
            summary_calls = []
            subagent_calls = []
            finalize_called = False

            for tc in ai_tool_calls:
                name = tc.get('name', '')
                args = tc.get('args', {})

                if name == 'get_function_summary_tool' or 'get_function_summary' in name:
                    summary_calls.append(args)
                elif name == 'create_sub_agent_tool' or 'create_sub_agent' in name:
                    subagent_calls.append(args)
                elif name == 'finalize_analysis_tool' or 'finalize_analysis' in name:
                    finalize_called = True

            self._log_progress(
                f"[Tool Call] 获取摘要: {len(summary_calls)}, 创建子Agent: {len(subagent_calls)}, 完成分析: {finalize_called}"
            )

            # 处理报告的漏洞 - 立即保存到数据库（增量保存）
            reported_vulns = tool_calls_result.get('reported_vulnerabilities', [])
            if reported_vulns:
                for vuln_args in reported_vulns:
                    try:
                        # 处理 evidence 可能是 JSON 字符串的情况
                        evidence = vuln_args.get('evidence', [])
                        if isinstance(evidence, str):
                            try:
                                evidence = json.loads(evidence)
                            except json.JSONDecodeError:
                                evidence = [evidence] if evidence else []
                        elif not isinstance(evidence, list):
                            evidence = []

                        vuln_result = VulnerabilityResult(
                            type=vuln_args.get('vuln_type', 'UNKNOWN'),
                            name=vuln_args.get('name', 'Unnamed Vulnerability'),
                            description=vuln_args.get('description', ''),
                            location=vuln_args.get('location', ''),
                            confidence=vuln_args.get('confidence', 5),
                            severity=vuln_args.get('severity', 'MEDIUM'),
                            evidence=evidence,
                            data_flow=DataFlowInfo(
                                source=vuln_args.get('data_flow', {}).get('source', ''),
                                sink=vuln_args.get('data_flow', {}).get('sink', ''),
                            ) if vuln_args.get('data_flow') else DataFlowInfo(),
                            remediation=vuln_args.get('remediation', ''),
                        )
                        all_vulnerabilities.append(vuln_result)
                        self._log_progress(
                            f"[漏洞报告] {vuln_result.name} ({vuln_result.severity}) @ {vuln_result.location}",
                            "warning"
                        )

                        # 立即保存到数据库（增量保存）
                        try:
                            vuln_manager = get_vulnerability_manager()
                            vuln_obj = self._convert_single_vulnerability(
                                vuln_result, function_identifier
                            )
                            if vuln_obj:
                                vuln_manager.import_from_agent_result(
                                    vulnerabilities=[vuln_obj],
                                    function_identifier=function_identifier,
                                    agent_id=self.agent_id,
                                    parent_agent_id=self.parent_id,
                                )
                                self._log_progress(
                                    f"[漏洞同步] 已保存漏洞到数据库: {vuln_result.name}",
                                    "success"
                                )
                        except Exception as e:
                            self._log_progress(f"[漏洞同步] 保存失败: {e}", "warning")

                    except Exception as e:
                        self._log_progress(f"[漏洞报告] 解析漏洞失败: {e}", "warning")

            # 后台启动子 Agent（带去重检查）
            if subagent_calls:
                unique_subagent_calls = []
                for call_args in subagent_calls:
                    func_name = call_args.get('function_identifier', '')
                    line_num = call_args.get('line_number', 0)
                    dedup_key = f"{func_name}:{line_num}"

                    if dedup_key in created_sub_agents:
                        self._log_progress(f"[去重跳过] 子 Agent {func_name} (行 {line_num}) 已创建")
                        continue

                    created_sub_agents.add(dedup_key)
                    unique_subagent_calls.append(call_args)
                    created_sub_agent_signatures.append(func_name)

                if unique_subagent_calls:
                    self._log_progress(f"[后台启动] {len(unique_subagent_calls)} 个子 Agent")
                    for call_args in unique_subagent_calls:
                        self._start_sub_agent_background(call_args, context, func_def.code if func_def else None)

            # 执行摘要任务并为每个 tool_call 添加 ToolMessage
            summary_results_map: Dict[str, Tuple[str, Optional[SimpleFunctionSummary]]] = {}
            if summary_calls:
                # 去重：过滤掉已经请求过的函数摘要
                unique_summary_calls = []
                for call_args in summary_calls:
                    func_name = call_args.get('function_identifier', '')
                    line_num = call_args.get('line_number', 0)
                    dedup_key = f"{func_name}:{line_num}"

                    if func_name in requested_summaries:
                        self._log_progress(f"[去重跳过] 函数 {func_name} 的摘要已在之前轮次请求过")
                        # 记录空结果用于 ToolMessage
                        summary_results_map[func_name] = (func_name, None)
                        continue

                    requested_summaries.add(func_name)
                    unique_summary_calls.append(call_args)

                if unique_summary_calls:
                    self._log_progress(f"[执行任务] {len(unique_summary_calls)} 个摘要任务")
                    summary_results = await self._execute_summary_tasks(
                        unique_summary_calls,
                        caller_identifier=context.function_identifier if context else None,
                        caller_code=func_def.code if func_def else None
                    )

                    # 合并到子函数摘要，并构建结果映射
                    for func_sig, summary in summary_results:
                        sub_summaries[func_sig] = summary
                        summary_results_map[func_sig] = (func_sig, summary)

            # 为每个 tool_call 添加 ToolMessage
            for idx, tc in enumerate(ai_tool_calls):
                name = tc.get('name', '')
                args = tc.get('args', {})
                tool_call_id = f"call_{iteration}_{idx}"

                if 'get_function_summary' in name:
                    func_name = args.get('function_identifier', 'unknown')
                    # 查找该函数的执行结果
                    result = summary_results_map.get(func_name)
                    if result:
                        func_sig, summary = result
                        if summary:
                            tool_content = self._format_summary_as_tool_result(func_sig, summary)
                        else:
                            tool_content = f"无法获取函数 {func_name} 的摘要信息，请基于源码可见逻辑进行分析。"
                    else:
                        tool_content = f"函数 {func_name} 的摘要请求未执行或已去重。"

                    messages.append(ToolMessage(
                        content=tool_content,
                        tool_call_id=tool_call_id,
                        name=name
                    ))
                elif 'create_sub_agent' in name:
                    func_name = args.get('function_identifier', 'unknown')
                    messages.append(ToolMessage(
                        content=f"子 Agent 已启动分析函数: {func_name}。该 Agent 将在后台独立执行深度分析。",
                        tool_call_id=tool_call_id,
                        name=name
                    ))
                elif 'report_vulnerability' in name:
                    vuln_name = args.get('name', '未知漏洞')
                    messages.append(ToolMessage(
                        content=f"漏洞 '{vuln_name}' 已记录。",
                        tool_call_id=tool_call_id,
                        name=name
                    ))
                elif 'finalize_analysis' in name:
                    messages.append(ToolMessage(
                        content="分析已完成。",
                        tool_call_id=tool_call_id,
                        name=name
                    ))

            # 检查是否完成
            has_tool_calls = len(ai_tool_calls) > 0
            should_finalize = finalize_called

            # 如果没有 tool call 但有 content，提示 LLM 调用工具完成分析
            if not has_tool_calls and not should_finalize:
                self._log_progress(f"[提示] LLM 返回分析内容但未调用工具，提示调用 finalize_analysis_tool 完成分析")
                messages.append(HumanMessage(
                    content="你已完成分析并在上述内容中描述了发现，但尚未调用工具来报告结果。"
                            "请调用 `report_vulnerability_tool` 报告发现的漏洞，"
                            "或调用 `finalize_analysis_tool` 完成分析。"
                ))
                continue  # 继续下一轮，让 LLM 调用工具

            if should_finalize:
                self._log_progress(f"分析完成于第 {iteration + 1} 轮")
                break

        # 分析完成，转换所有漏洞为 Vulnerability 对象用于返回
        vulnerabilities = self._convert_to_vulnerabilities(
            all_vulnerabilities,
            function_identifier,
        )

        # 更新执行状态
        await self._update_execution_state(vulnerabilities_found=len(vulnerabilities))

        # 生成分析摘要
        summary = f"分析完成于第 {iteration + 1} 轮，共发现 {len(vulnerabilities)} 个漏洞"
        if sub_summaries:
            summary += f"，分析了 {len(sub_summaries)} 个子函数"

        self._log_progress(f"深度分析完成，共发现 {len(vulnerabilities)} 个漏洞")

        return {
            "vulnerabilities": vulnerabilities,
            "constraints": context.parent_constraints if context else [],
            "taint_sources": context.taint_sources if context else [],
            "summary": summary,
        }

    def _format_summary_as_tool_result(
            self,
            func_sig: str,
            summary: SimpleFunctionSummary
    ) -> str:
        """
        将函数摘要格式化为 ToolMessage 的内容
        
        Args:
            func_sig: 函数签名
            summary: 函数摘要
            
        Returns:
            格式化的工具结果字符串
        """
        lines = []
        lines.append(f"函数摘要: {func_sig}")
        lines.append("")

        # 行为摘要
        behavior = getattr(summary, 'behavior_summary', 'N/A')
        lines.append(f"行为: {behavior}")

        # 参数约束
        param_constraints = getattr(summary, 'param_constraints', [])
        if param_constraints:
            lines.append("参数约束:")
            for constraint in param_constraints:
                lines.append(f"  - {constraint}")

        # 返回值
        return_val = getattr(summary, 'return_value_meaning', 'N/A')
        lines.append(f"返回值: {return_val}")

        # 全局变量操作
        global_ops = getattr(summary, 'global_var_operations', '')
        if global_ops:
            lines.append(f"全局变量操作: {global_ops}")

        return "\n".join(lines)

    async def _llm_analyze_with_messages(
            self,
            messages: List[BaseMessage],
            context: FunctionContext,
            iteration: int,
    ) -> Dict[str, Any]:
        """
        使用消息列表进行 LLM 分析 - 多轮对话模式
        
        Args:
            messages: 对话历史消息列表
            context: 函数上下文
            iteration: 当前迭代次数
        
        Returns:
            包含 tool_calls 和 analysis_complete 的字典
        """
        # 优先使用自定义系统提示词（用于 Orchestrator 动态注入）
        if self._custom_system_prompt:
            system_prompt = self._custom_system_prompt
        else:
            system_prompt = get_vuln_agent_system_prompt(self.engine_type)

        # 检查是否达到最大深度
        is_max_depth = context.depth >= context.max_depth

        try:
            # 根据深度动态调整可用工具
            if is_max_depth:
                # 达到最大深度时，只提供漏洞报告和完成分析工具
                tools = [
                    report_vulnerability_tool,
                    finalize_analysis_tool,
                ]
                self._log_progress(f"[深度限制] 当前深度 {context.depth}/{context.max_depth}，已限制子函数分析工具")
            else:
                # 正常深度时，提供所有工具
                tools = [
                    get_function_summary_tool,
                    create_sub_agent_tool,
                    report_vulnerability_tool,
                    finalize_analysis_tool,
                ]

            result = await self.tool_llm.atool_call(
                messages=messages,
                tools=tools,
                system_prompt=system_prompt,
                allow_text_response=True,
            )

            # 解析结果
            analysis_complete = False
            has_finalize = False
            reported_vulns = []

            # 检查 tool calls
            for tc in result.tool_calls:
                name = tc.get('name', '')
                args = tc.get('args', {})
                if 'finalize_analysis' in name:
                    has_finalize = True
                elif 'report_vulnerability' in name:
                    reported_vulns.append(args)

            return {
                'tool_calls': result.tool_calls,
                'content': result.content,
                'reported_vulnerabilities': reported_vulns,
            }

        except Exception as e:
            self._log_progress(f"[Tool Call] 分析失败: {e}", "error")
            return {
                'tool_calls': [],
                'content': '',
                'analysis_complete': True,
            }

    async def _execute_summary_tasks(
            self,
            calls: List[Dict[str, Any]],
            caller_identifier: Optional[str] = None,
            caller_code: Optional[str] = None,
    ) -> List[Tuple[str, Optional[SimpleFunctionSummary]]]:
        """
        并发执行摘要任务并等待结果
        
        Args:
            calls: Tool Call 参数列表（包含 callsite 信息）
            caller_identifier: 调用者函数标识符（用于解析 callsite）
            caller_code: 调用者源代码（用于 CallsiteAgent）
            
        Returns:
            [(函数签名, 摘要), ...] 的列表
        """
        semaphore = asyncio.Semaphore(self.max_concurrency)

        async def _execute_with_semaphore(call_args: Dict[str, Any]):
            async with semaphore:
                # 解析 callsite
                callsite = CallsiteInfo.from_dict(call_args)

                # 解析 callsite 为函数标识符
                func_sig = await self._resolve_callsite(callsite, caller_identifier, caller_code)
                if not func_sig:
                    func_sig = callsite.function_identifier

                result = await self._get_sub_function_summary(func_sig)
                return func_sig, result

        results = await asyncio.gather(
            *[_execute_with_semaphore(c) for c in calls],
            return_exceptions=True
        )

        # 处理结果
        processed_results = []
        for item in results:
            if isinstance(item, Exception):
                self._log_progress(f"[摘要任务] 执行失败: {item}", "warning")
                processed_results.append(("", None))
            else:
                func_sig, summary = item
                if summary:
                    self._log_progress(f"[摘要任务] 获取 {func_sig} 成功")
                else:
                    self._log_progress(f"[摘要任务] 获取 {func_sig} 无结果", "warning")
                processed_results.append(item)

        return processed_results

    async def _resolve_callsite(
            self,
            callsite: CallsiteInfo,
            caller_identifier: Optional[str],
            caller_code: Optional[str] = None,
    ) -> Optional[str]:
        """
        解析 callsite 为函数签名
        
        通过 Engine 统一处理（Engine 内部包含了静态分析和 CallsiteAgent 回退逻辑）
        
        参数:
            callsite: 调用点信息
            caller_identifier: 调用者函数标识符
            caller_code: 调用者源代码
        
        返回:
            解析后的函数签名，失败返回 None
        """
        try:
            # 委托给 Engine 处理
            signature = await self.engine.resolve_function_by_callsite(
                callsite=callsite,
                caller_identifier=caller_identifier,
                caller_code=caller_code,
            )

            if signature:
                self._log_progress(f"Resolved callsite {callsite.function_identifier} -> {signature}")
                return signature

            return callsite.function_identifier

        except Exception as e:
            self._log_progress(f"[Callsite解析] 解析失败: {e}", "warning")
            return callsite.function_identifier

    def _start_sub_agent_background(
            self,
            call_args: Dict[str, Any],
            parent_context: FunctionContext,
            caller_code: Optional[str] = None,
    ):
        """
        后台启动子 Agent（fire-and-forget）
        """
        # 获取 callsite 信息
        callsite_data = call_args
        func_name = callsite_data.get('function_identifier', 'unknown') if callsite_data else 'unknown'

        current_call_stack = parent_context.call_stack if parent_context else self.call_stack
        call_path = " -> ".join(current_call_stack + [func_name])
        call_depth = len(current_call_stack) + 1

        async def _run_sub_agent():
            try:

                result = await self._create_sub_agent(call_args, parent_context, caller_code)
                sub_vulns = result.get("vulnerabilities", [])

                if sub_vulns:
                    async with self._vuln_lock:
                        self.vulnerabilities.extend(sub_vulns)
                    self._log_progress(
                        f"[子Agent完成] {func_name} 发现 {len(sub_vulns)} 个漏洞",
                        "success"
                    )
                else:
                    self._log_progress(f"[子Agent完成] {func_name} 未发现漏洞")

            except Exception as e:
                self._log_progress(f"[子Agent失败] {func_name} | 错误: {e}", "warning")

        # 创建后台任务
        task = asyncio.create_task(_run_sub_agent())
        self._sub_agent_tasks.append(task)
        self._log_progress(f"[后台启动] 子 Agent: {func_name}")

    async def _get_sub_function_summary(
            self,
            function_identifier: str,
    ) -> Optional[SimpleFunctionSummary]:
        """获取子函数摘要（精简格式）"""
        try:
            summary = await self.summary_agent.analyze(function_identifier)
            return summary
        except Exception as e:
            self.log(f"[{self.agent_id}] Failed to get summary: {e}", "WARNING")
            return None

    async def _create_sub_agent(
            self,
            call_args: Dict[str, Any],
            parent_context: FunctionContext,
            caller_code: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        创建子 Agent 递归分析
        
        基于调用点上下文构建子函数的约束条件（纯文本格式）。
        """
        # 获取 callsite 信息并解析为函数签名
        callsite_data = call_args
        if not callsite_data:
            return {"vulnerabilities": [], "skipped": True, "reason": "missing_callsite"}

        callsite = CallsiteInfo.from_dict(callsite_data)

        # 解析 callsite 为函数标识符
        caller_identifier = parent_context.function_identifier if parent_context else None
        func_sig = await self._resolve_callsite(callsite, caller_identifier, caller_code)
        if not func_sig:
            func_sig = callsite.function_identifier

        current_call_stack = parent_context.call_stack if parent_context else self.call_stack
        current_call_stack_detailed = parent_context.call_stack_detailed if parent_context else self.call_stack_detailed

        # 获取纯文本格式的参数约束
        argument_constraints = call_args.get('argument_constraints', [])

        # 构建新的调用栈帧
        new_frame = CallStackFrame(
            function_identifier=func_sig,
            function_name=func_sig.split('(')[0] if '(' in func_sig else func_sig,
            call_line=callsite.line_number,
            call_code=callsite.call_text,
            caller_function=call_args.get('caller_function', '') or (
                current_call_stack[-1] if current_call_stack else ""),
            argument_constraints=[{"constraint": c} for c in argument_constraints],
        )

        # 构建详细的调用路径
        current_call_stack_detailed = current_call_stack_detailed.copy()
        current_call_stack_detailed.append(new_frame)

        call_path_str = " -> ".join(current_call_stack + [func_sig])

        # 检查循环调用
        call_sigs_in_stack = [frame.function_identifier for frame in current_call_stack_detailed]
        if func_sig in call_sigs_in_stack[:-1]:
            self._log_progress(f"[子Agent跳过] 检测到循环调用 | 目标: {func_sig}", "warning")
            return {"vulnerabilities": [], "skipped": True, "reason": "circular_call"}

        if len(current_call_stack_detailed) > self.max_depth:
            self._log_progress(f"[子Agent跳过] 超过递归深度 | 目标: {func_sig}", "warning")
            return {"vulnerabilities": [], "skipped": True, "reason": "max_depth"}

        # 构建子函数上下文 - 使用纯文本约束
        # 从 argument_constraints 提取污点源信息
        sub_taint_sources = []
        for constraint in argument_constraints:
            if '污点' in constraint or 'taint' in constraint.lower():
                # 尝试提取参数名
                if '参数' in constraint and ':' in constraint:
                    param_name = constraint.split(':')[0].replace('参数', '').strip()
                    if param_name:
                        sub_taint_sources.append(param_name)

        # 基于调用上下文生成 precondition
        sub_precondition = self._build_call_context_precondition(
            func_sig,
            call_args,
            argument_constraints,
            call_path_str
        )

        # 构建子函数上下文
        sub_context = FunctionContext(
            function_identifier=func_sig,
            call_stack=parent_context.call_stack + [func_sig],
            call_stack_detailed=current_call_stack_detailed,
            depth=parent_context.depth + 1,
            max_depth=self.max_depth,
            taint_sources=sub_taint_sources,
            # 使用纯文本约束 - 合并父约束和当前约束
            parent_constraints=self._merge_constraints(
                parent_context.parent_constraints,
                argument_constraints
            ),
            precondition=sub_precondition,
        )

        # 创建子 Agent
        sub_agent = DeepVulnAgent(
            engine=self.engine,
            llm_client=self.llm_client,
            max_iterations=self.max_iterations,
            verbose=self.verbose,
            max_concurrency=self.max_concurrency,
            max_depth=self.max_depth,
            parent_id=self.agent_id,
            call_stack=sub_context.call_stack,
            call_stack_detailed=current_call_stack_detailed,
            precondition=sub_precondition,
            progress_logger=self._progress_logger,
        )

        await self._update_execution_state(sub_agents_created=self.execution_state.sub_agents_created + 1)

        self._log_progress(f"[子Agent创建] 目标: {func_sig} | 深度: {sub_context.depth}/{self.max_depth}")

        # 执行子 Agent
        result = await sub_agent.run(function_identifier=func_sig, context=sub_context)

        sub_vulns = result.get("vulnerabilities", [])
        if sub_vulns:
            self._log_progress(f"[子Agent结果] {func_sig} 发现 {len(sub_vulns)} 个漏洞", "success")
        else:
            self._log_progress(f"[子Agent结果] {func_sig} 未发现漏洞")

        return result

    def _format_detailed_call_path(self, call_stack_detailed: List[CallStackFrame]) -> str:
        """
        格式化详细调用路径
        
        将调用栈帧列表转换为可读的调用路径字符串
        """
        if not call_stack_detailed:
            return ""

        parts = []
        for frame in call_stack_detailed:
            name = frame.function_name or frame.function_identifier
            if frame.call_line > 0:
                parts.append(f"{name}:{frame.call_line}")
            else:
                parts.append(name)

        return " -> ".join(parts)

    def _merge_constraints(
            self,
            parent_constraints: Any,
            current_constraints: List[str],
    ) -> List[str]:
        """
        合并父函数约束和当前约束（纯文本格式）
        """
        merged = []

        # 添加父约束
        if isinstance(parent_constraints, list):
            merged.extend(parent_constraints)
        elif isinstance(parent_constraints, dict):
            # 转换字典为文本列表
            for param, constraints in parent_constraints.items():
                if isinstance(constraints, list):
                    for c in constraints:
                        merged.append(f"{param}: {c}")
                else:
                    merged.append(f"{param}: {constraints}")

        # 添加当前约束
        merged.extend(current_constraints)

        return merged

    def _build_call_context_precondition(
            self,
            function_identifier: str,
            call_args: Dict[str, Any],
            argument_constraints: List[str],
            call_path_str: str,
    ) -> Optional[Any]:
        """
        基于调用上下文构建子函数的 precondition 文本（纯文本格式）
        """
        if not argument_constraints and not call_args.get('call_code'):
            return None

        return Precondition(
            name=f"CallContext_{function_identifier}",
            description=f"基于调用点生成的上下文 - {call_path_str}",
            target=function_identifier,
            text_content="",
            taint_sources=[],
        )

    def _filter_duplicate_function_summary_calls(
            self,
            tool_calls: List[Dict[str, Any]],
            sub_summaries: Dict[str, SimpleFunctionSummary]
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        过滤重复的函数摘要请求，避免 LLM 重复请求已经提供的函数摘要
        
        Args:
            tool_calls: 原始的 tool calls 列表
            sub_summaries: 已有的函数摘要字典
            
        Returns:
            (过滤后的 tool calls 列表, 被过滤的重复请求列表)
        """
        filtered_calls = []
        duplicate_calls = []

        for tc in tool_calls:
            name = tc.get('name', '')
            args = tc.get('args', {})

            # 检查是否是获取函数摘要的工具调用
            if name == 'get_function_summary_tool' or 'get_function_summary' in name:
                # 解析 callsite 信息
                callsite_data = args
                if not callsite_data:
                    filtered_calls.append(tc)
                    continue

                # 尝试解析函数标识符
                func_identifier = callsite_data.get('function_identifier', '')
                line_number = callsite_data.get('line_number', 0)

                # 构建去重键
                dedup_key = f"{func_identifier}:{line_number}"

                # 检查是否已经存在该函数的摘要
                if func_identifier in sub_summaries:
                    duplicate_calls.append({
                        'function_identifier': func_identifier,
                        'line_number': line_number,
                        'call_text': callsite_data.get('call_text', ''),
                        'reason': 'already_provided'
                    })
                    self._log_progress(
                        f"[去重过滤] 跳过重复的函数摘要请求: {func_identifier} (行 {line_number})",
                        "info"
                    )
                else:
                    filtered_calls.append(tc)
            else:
                # 非函数摘要工具调用，直接保留
                filtered_calls.append(tc)

        # 如果有过滤掉的重复调用，记录日志
        if duplicate_calls:
            self._log_progress(
                f"[去重统计] 过滤了 {len(duplicate_calls)} 个重复的函数摘要请求",
                "info"
            )

        return filtered_calls, duplicate_calls

    def _convert_to_vulnerabilities(
            self,
            results: List[VulnerabilityResult],
            function_identifier: str,
    ) -> List[Vulnerability]:
        """将 LLM 输出转换为 Vulnerability 对象，包含完整的调用路径和代码行信息"""
        vulnerabilities = []

        for result in results:
            # 映射漏洞类型
            vuln_type = VulnerabilityType.UNKNOWN
            try:
                vuln_type = VulnerabilityType(result.type)
            except ValueError:
                pass

            # 映射危害等级到 severity
            severity_map = {"LOW": 0.3, "MEDIUM": 0.6, "HIGH": 0.9}
            severity = severity_map.get(result.severity, 0.5)

            # 置信度 1-10 映射到 0-1
            confidence = result.confidence / 10.0

            # 构建详细的数据流路径描述
            path_nodes = []

            # 添加源节点
            if result.data_flow.source_node:
                src = result.data_flow.source_node
                code_info = f"[{src.line_number}] {src.code_line[:80]}..." if len(
                    src.code_line) > 80 else f"[{src.line_number}] {src.code_line}"
                path_nodes.append(f"源({src.variable}): {code_info}")
            else:
                path_nodes.append(f"源: {result.data_flow.source}")

            # 添加中间节点
            if result.data_flow.intermediate_nodes:
                for node in result.data_flow.intermediate_nodes:
                    code_info = f"[{node.line_number}] {node.code_line[:80]}..." if len(
                        node.code_line) > 80 else f"[{node.line_number}] {node.code_line}"
                    path_nodes.append(f"-> {node.variable}: {code_info}")
            elif result.data_flow.intermediate:
                for var in result.data_flow.intermediate:
                    path_nodes.append(f"-> {var}")

            # 添加汇聚点
            if result.data_flow.sink_node:
                sink = result.data_flow.sink_node
                code_info = f"[{sink.line_number}] {sink.code_line[:80]}..." if len(
                    sink.code_line) > 80 else f"[{sink.line_number}] {sink.code_line}"
                path_nodes.append(f"汇聚点({sink.variable}): {code_info}")
            else:
                path_nodes.append(f"汇聚点: {result.data_flow.sink}")

            path_description = "\n  ".join(path_nodes)

            # 构建调用路径信息 - 使用 Agent 维护的详细调用栈
            call_stack_info = []

            # 使用 Agent 的详细调用栈（包含调用点信息）
            if self.call_stack_detailed:
                for idx, frame in enumerate(self.call_stack_detailed, 1):
                    func = frame.function_name or frame.function_identifier
                    if frame.call_line > 0:
                        if frame.call_code:
                            code_preview = frame.call_code[:60] + "..." if len(
                                frame.call_code) > 60 else frame.call_code
                            call_stack_info.append(f"  [{idx}] {func}:{frame.call_line} - {code_preview}")
                        else:
                            call_stack_info.append(f"  [{idx}] {func}:{frame.call_line}")
                    else:
                        call_stack_info.append(f"  [{idx}] {func}")
                # 添加当前函数
                call_stack_info.append(f"  [{len(self.call_stack_detailed) + 1}] {function_identifier}")
            # 使用简单调用栈作为回退
            else:
                for idx, func in enumerate(self.call_stack + [function_identifier], 1):
                    call_stack_info.append(f"  [{idx}] {func}")

            call_stack_str = "\n".join(call_stack_info) if call_stack_info else "  (无调用栈信息)"

            # 构建证据代码行信息
            evidence_lines = []
            if result.evidence_code_lines:
                for ev in result.evidence_code_lines:
                    line_num = ev.get('line_number', 0)
                    code = ev.get('code', '')
                    if code:
                        evidence_lines.append(f"    Line {line_num}: {code}")
            if result.evidence:
                for ev in result.evidence:
                    if ev not in evidence_lines:
                        evidence_lines.append(f"    {ev}")

            evidence_str = "\n".join(evidence_lines) if evidence_lines else "    (无详细证据)"

            # 构建完整描述，包含调用路径和数据流
            full_description = f"""{result.description}

【调用路径】
{call_stack_str}

【数据传播路径】
  {path_description}

【关键代码证据】
{evidence_str}
"""

            # 构建详细的调用栈数据（包含 Agent 的调用栈和当前函数）
            final_call_stack = self.call_stack + [function_identifier]
            final_call_stack_detailed = [
                                            frame.to_dict() for frame in self.call_stack_detailed
                                        ] + [{
                "function": function_identifier,
                "function_name": function_identifier.split('(')[
                    0] if '(' in function_identifier else function_identifier,
                "line_number": 0,
                "code_snippet": "",
                "caller": self.call_stack_detailed[-1].function_identifier if self.call_stack_detailed else "",
            }]

            # 构建带行号的调用路径
            call_path_with_lines = []
            for frame in self.call_stack_detailed:
                call_path_with_lines.append({
                    "function": frame.function_identifier,
                    "function_name": frame.function_name,
                    "line_number": frame.call_line,
                    "code_snippet": frame.call_code,
                    "caller": frame.caller_function,
                })
            call_path_with_lines.append({
                "function": function_identifier,
                "function_name": function_identifier.split('(')[
                    0] if '(' in function_identifier else function_identifier,
                "line_number": 0,
                "code_snippet": "",
                "caller": self.call_stack_detailed[-1].function_identifier if self.call_stack_detailed else "",
            })

            vuln = Vulnerability(
                type=vuln_type,
                name=result.name,
                description=full_description,
                location=f"{function_identifier}: {result.location}",
                severity=severity,
                confidence=confidence,
                data_flow=DataFlowPath(
                    source=result.data_flow.source,
                    intermediate_nodes=result.data_flow.intermediate,
                    sink=result.data_flow.sink,
                    path_description=path_description,
                ),
                remediation=result.remediation,
                metadata={
                    "evidence": result.evidence,
                    "evidence_code_lines": result.evidence_code_lines,
                    "constraints_satisfied": result.constraints_satisfied,
                    "call_stack": final_call_stack,
                    "call_stack_detailed": final_call_stack_detailed,
                    "data_flow_nodes": {
                        "source": result.data_flow.source_node.model_dump() if result.data_flow.source_node else None,
                        "intermediate": [n.model_dump() for n in
                                         result.data_flow.intermediate_nodes] if result.data_flow.intermediate_nodes else [],
                        "sink": result.data_flow.sink_node.model_dump() if result.data_flow.sink_node else None,
                    },
                    "call_path_with_lines": call_path_with_lines,
                },
            )
            vulnerabilities.append(vuln)

        return vulnerabilities

    def _format_call_path_for_vulnerability(self, function_identifier: str) -> str:
        """
        格式化调用路径信息（用于漏洞保存）
        
        按照用户指定的格式生成调用路径描述，包含：
        - 调用深度
        - 每层调用的调用点和参数约束
        
        Returns:
            格式化后的调用路径字符串
        """
        current_depth = len(self.call_stack_detailed) + 1
        max_depth = self.max_depth

        lines = []
        lines.append("### 当前上下文")
        lines.append(f"- 调用深度: {current_depth}/{max_depth}")
        lines.append("- 父函数传递的约束:")
        lines.append("")

        if not self.call_stack_detailed:
            lines.append("  (无)")
            return "\n".join(lines)

        # 遍历调用栈，格式化每一层调用
        for idx, frame in enumerate(self.call_stack_detailed):
            # 获取调用者信息
            caller = frame.caller_function if frame.caller_function else "入口函数"
            callee = frame.function_name or frame.function_identifier

            # 提取函数名（去除签名部分）
            if '(' in callee:
                callee_name = callee[:callee.index('(')].strip()
            else:
                callee_name = callee

            if '(' in caller and 'sub_' in caller:
                caller_name = caller[:caller.index('(')].strip()
            else:
                caller_name = caller

            # 添加调用关系标题
            lines.append(f"{caller_name} 调用 {callee_name} 传递的调用约束：")

            # 调用点的代码
            call_code = frame.call_code if frame.call_code else f"{callee_name}(...);"
            lines.append(f"调用点的代码: {call_code}")
            lines.append("")

            # 参数约束
            constraints = frame.argument_constraints if frame.argument_constraints else []
            if constraints:
                lines.append("参数约束")
                for constraint in constraints:
                    # 处理字典格式（如果 constraint 是 dict）
                    if isinstance(constraint, dict):
                        constraint_text = constraint.get('constraint', '')
                        if constraint_text:
                            lines.append(f"- {constraint_text}")
                    else:
                        lines.append(f"- {constraint}")
            else:
                lines.append("参数约束: (无)")

            lines.append("")

        return "\n".join(lines)

    def _convert_single_vulnerability(
            self,
            result: VulnerabilityResult,
            function_identifier: str,
    ) -> Optional[Vulnerability]:
        """将单个 VulnerabilityResult 转换为 Vulnerability 对象"""
        try:
            # 映射漏洞类型
            vuln_type = VulnerabilityType.UNKNOWN
            try:
                vuln_type = VulnerabilityType(result.type)
            except ValueError:
                pass

            # 映射危害等级到 severity
            severity_map = {"LOW": 0.3, "MEDIUM": 0.6, "HIGH": 0.9}
            severity = severity_map.get(result.severity, 0.5)

            # 置信度 1-10 映射到 0-1
            confidence = result.confidence / 10.0

            # 构建简单数据流路径描述
            path_nodes = []
            if result.data_flow.source_node:
                src = result.data_flow.source_node
                path_nodes.append(f"源({src.variable}): [{src.line_number}] {src.code_line[:60]}")
            else:
                path_nodes.append(f"源: {result.data_flow.source}")

            if result.data_flow.sink_node:
                sink = result.data_flow.sink_node
                path_nodes.append(f"汇聚点({sink.variable}): [{sink.line_number}] {sink.code_line[:60]}")
            else:
                path_nodes.append(f"汇聚点: {result.data_flow.sink}")

            path_description = "\n  ".join(path_nodes)

            # 构建调用路径信息（使用新的格式）
            call_path_str = self._format_call_path_for_vulnerability(function_identifier)

            # 构建简洁的调用栈列表（用于快速查看）
            call_stack_list = []
            if self.call_stack_detailed:
                for idx, frame in enumerate(self.call_stack_detailed, 1):
                    func = frame.function_name or frame.function_identifier
                    call_stack_list.append(
                        f"  [{idx}] {func}:{frame.call_line}" if frame.call_line > 0 else f"  [{idx}] {func}")
                call_stack_list.append(f"  [{len(self.call_stack_detailed) + 1}] {function_identifier}")
            else:
                for idx, func in enumerate(self.call_stack + [function_identifier], 1):
                    call_stack_list.append(f"  [{idx}] {func}")

            # 构建调用栈数据 (字符串列表格式，用于前端展示)
            call_stack_display = []
            if self.call_stack_detailed:
                for idx, frame in enumerate(self.call_stack_detailed, 1):
                    func = frame.function_name or frame.function_identifier
                    if frame.call_line > 0:
                        call_stack_display.append(f"[{idx}] {func}:{frame.call_line}")
                    else:
                        call_stack_display.append(f"[{idx}] {func}")
                call_stack_display.append(f"[{len(self.call_stack_detailed) + 1}] {function_identifier}")
            else:
                for idx, func in enumerate(self.call_stack + [function_identifier], 1):
                    call_stack_display.append(f"[{idx}] {func}")

            # 构建调用栈数据 (原始列表格式)
            final_call_stack = self.call_stack + [function_identifier]

            # description 只包含纯漏洞描述
            # 调用路径、调用栈、数据流信息分别存储到对应字段
            return Vulnerability(
                type=vuln_type,
                name=result.name,
                description=result.description,
                location=f"{function_identifier}: {result.location}",
                severity=severity,
                confidence=confidence,
                data_flow=DataFlowPath(
                    source=result.data_flow.source,
                    intermediate_nodes=result.data_flow.intermediate,
                    sink=result.data_flow.sink,
                    path_description=path_description,
                ),
                remediation=result.remediation,
                metadata={
                    "evidence": result.evidence,
                    "call_stack": final_call_stack,
                    "call_path": call_path_str,
                    "call_stack_display": call_stack_display,
                },
            )
        except Exception as e:
            self._log_progress(f"[漏洞转换] 转换失败: {e}", "warning")
            return None

    @classmethod
    def get_execution_states(cls) -> Dict[str, AgentExecutionState]:
        """获取所有执行状态（用于可视化）"""
        return cls._execution_states.copy()

    @classmethod
    def clear_execution_states(cls):
        """清除执行状态"""
        cls._execution_states.clear()
