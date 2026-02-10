#!/usr/bin/env python3
"""
IVAgent - 异步智能程序分析框架

基于 LangGraph 和异步协程构建的高性能 Agent 框架
支持高并发程序分析和漏洞挖掘
"""

__version__ = "3.0.0"
__author__ = "IVAgent Team"

# 引擎层
from .engines import (
    BaseStaticAnalysisEngine,
    LangGraphEngine,
    EngineConfig,
    AgentState,
    WorkflowStatus,
    ExecutionResult,
    IDAClient,
    IDAStaticAnalysisEngine,
    create_engine,
    create_ida_engine,
)

# Agent 层
from .agents import (
    BaseAgent,
    ProgramAnalyzer,
    DeepVulnAgent,
)

# 数据模型
from .models import (
    SimpleFunctionSummary,
    FunctionContext,
    Vulnerability,
    VulnerabilityType,
)

# 核心工具
from .core import (
    ToolBasedLLMClient,
    SimpleJSONLLMClient,
)

__all__ = [
    # 版本信息
    "__version__",
    "__author__",
    # 引擎层
    "BaseStaticAnalysisEngine",
    "LangGraphEngine",
    "EngineConfig",
    "AgentState",
    "WorkflowStatus",
    "ExecutionResult",
    "IDAClient",
    "IDAStaticAnalysisEngine",
    "create_engine",
    "create_ida_engine",
    # Agent 层
    "BaseAgent",
    "ProgramAnalyzer",
    "DeepVulnAgent",
    # 数据模型
    "SimpleFunctionSummary",
    "FunctionContext",
    "Vulnerability",
    "VulnerabilityType",
    # 核心工具
    "ToolBasedLLMClient",
    "SimpleJSONLLMClient",
]
