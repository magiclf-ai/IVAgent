#!/usr/bin/env python3
"""
ProgramAnalyzer - 程序分析 Agent

基于 LangGraph 和异步协程构建的高性能程序分析 Agent
支持高并发函数分析

特性:
    1. 全异步工作流执行
    2. 支持批量并发函数分析
    3. 异步缓存管理
    4. 并发控制与资源管理
"""

from typing import Dict, List, Optional, Any, TypedDict, Annotated, Set, Tuple
from dataclasses import dataclass, field
import json
import time
import asyncio
from enum import Enum
import re

from langgraph.graph import StateGraph, END
from langgraph.graph.message import add_messages
from langchain_core.messages import BaseMessage, HumanMessage, AIMessage, SystemMessage, ToolMessage
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI

from ..engines.base_langgraph_engine import LangGraphEngine, EngineConfig, AgentState
from ..models.function import SimpleFunctionSummary
from ..models.constraints import FunctionContext
from ..core.cli_logger import CLILogger
from .function_summary_agent import FunctionSummaryAgent


# ============================================================================
# 状态定义
# ============================================================================

class AnalysisPhase(str, Enum):
    """分析阶段"""
    INIT = "init"
    GET_INFO = "get_info"
    ANALYZE_CODE = "analyze_code"
    EXTRACT_PARAMS = "extract_params"
    IDENTIFY_CONSTRAINTS = "identify_constraints"
    PROPAGATE = "propagate"
    GENERATE_SUMMARY = "generate_summary"
    COMPLETED = "completed"
    ERROR = "error"


class AnalysisState(TypedDict):
    """
    程序分析状态
    
    扩展基础 AgentState，添加程序分析特有的字段
    """
    # 继承自 AgentState
    messages: Annotated[List[BaseMessage], add_messages]
    metadata: Dict[str, Any]
    iteration: int
    max_iterations: int
    status: str
    error: Optional[str]
    result: Optional[Any]

    # 程序分析特有字段
    function_identifier: str
    function_context: Optional[FunctionContext]
    phase: str

    # 中间结果
    func_def: Optional[Dict[str, Any]]
    callees: List[Dict[str, Any]]
    analysis_result: Optional[Dict[str, Any]]

    # 最终结果
    summary: Optional[SimpleFunctionSummary]

    # 递归分析
    pending_callees: List[str]
    analyzed_callees: Dict[str, SimpleFunctionSummary]


class ProgramAnalyzer:
    """
    程序分析器
    
    支持高并发函数分析，利用 asyncio 实现并行分析多个函数
    """

    def __init__(
            self,
            engine,
            llm_client,
            max_iterations: int = 10,
            verbose: bool = False,
            max_concurrency: int = 5,
            max_llm_retries: int = 3,
    ):
        self.engine = engine

        # 配置
        config = EngineConfig(
            max_iterations=max_iterations,
            verbose=verbose,
            max_concurrency=max_concurrency,
        )

        # 配置
        self.llm_client: ChatOpenAI = llm_client
        self.max_llm_retries = max_llm_retries
        self.verbose = verbose
        self._logger = CLILogger(component=self.__class__.__name__, verbose=verbose)

        # 异步缓存
        self._summary_cache: Dict[str, SimpleFunctionSummary] = {}
        self._cache_lock = asyncio.Lock()

        # 并发控制
        self._analysis_semaphore = asyncio.Semaphore(max_concurrency)

    def log(self, message: str, level: str = "INFO"):
        """打印日志"""
        if not self.verbose:
            return
        self._logger.log(level=level, event="program_analyzer.event", message=message)

    def build_workflow(self):
        pass

    async def get_function_summary(
            self,
            function_identifier: str,
            cache_type: str = "redis",
            cache_config: Optional[Dict[str, Any]] = None,
    ) -> SimpleFunctionSummary:
        agent = FunctionSummaryAgent(
            self.engine,
            self.llm_client,
            verbose=self.verbose,
            cache_type=cache_type,
            cache_config=cache_config,
        )
        summary = await agent.analyze(function_identifier)
        return summary
