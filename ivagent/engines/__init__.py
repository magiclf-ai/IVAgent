#!/usr/bin/env python3
"""
Engines 模块 - 异步分析引擎

定义异步分析引擎的统一接口和 LangGraph 驱动的智能分析引擎
所有操作均为异步，支持高并发分析场景
"""

# 数据模型
from .base_static_analysis_engine import (
    FunctionDef,
    CallSite,
    CrossReference,
    VariableConstraint,
    TargetType,
)

# 引擎基类
from .base_static_analysis_engine import BaseStaticAnalysisEngine
from .base_langgraph_engine import LangGraphEngine, EngineConfig, AgentState, WorkflowStatus, ExecutionResult

# IDA MCP 引擎
from .ida_engine import IDAClient, IDAStaticAnalysisEngine

# JEB 引擎
try:
    from .jeb_engine import JEBClient, JEBStaticAnalysisEngine
except ImportError:
    JEBClient = None
    JEBStaticAnalysisEngine = None

# ABC 引擎
try:
    from .abc_engine import AbcStaticAnalysisEngine
except ImportError:
    AbcStaticAnalysisEngine = None

# 源码分析引擎
from .source_code_engine import SourceCodeEngine

# 工厂函数
from .factory import (
    create_engine, 
    create_ida_engine, 
    create_jeb_engine, 
    create_abc_engine,
    create_source_engine,
)

__all__ = [
    # 数据模型
    "FunctionDef",
    "CallSite",
    "CrossReference",
    "VariableConstraint",
    "TargetType",
    # 引擎基类
    "BaseStaticAnalysisEngine",
    "LangGraphEngine",
    "EngineConfig",
    "AgentState",
    "WorkflowStatus",
    "ExecutionResult",
    # IDA MCP 引擎
    "IDAClient",
    "IDAStaticAnalysisEngine",
    # JEB 引擎
    "JEBClient",
    "JEBStaticAnalysisEngine",
    # ABC 引擎
    "AbcStaticAnalysisEngine",
    # 源码引擎
    "SourceCodeEngine",
    # 工厂函数
    "create_engine",
    "create_ida_engine",
    "create_jeb_engine",
    "create_abc_engine",
    "create_source_engine",
]
