#!/usr/bin/env python3
"""
数据模型层

核心数据结构定义
"""

from .constraints import FunctionContext, CallStackFrame

from .function import SimpleFunctionSummary

from .vulnerability import (
    VulnerabilityType,
    TaintSource,
    DataFlowPath,
    Vulnerability,
)

from .callsite import (
    CallsiteInfo,
    ResolvedCallsite,
)

from .skill import ScopeInfo, SkillContext, StrategyHints
from .skill_parser import SkillParser

from .semantic_analysis import (
    CodeFinding,
)

from .task import (
    TaskStatus,
    TaskStatusTransitionError,
    Task,
)

__all__ = [
    # 约束模型（纯文本格式）
    "FunctionContext",
    "CallStackFrame",
    # 函数模型（精简纯文本格式）
    "SimpleFunctionSummary",
    # 漏洞模型
    "VulnerabilityType",
    "TaintSource",
    "DataFlowPath",
    "Vulnerability",
    # 调用点模型
    "CallsiteInfo",
    "ResolvedCallsite",
    # Skill 模型
    "SkillContext",
    "ScopeInfo",
    "StrategyHints",
    "SkillParser",
    # 语义分析模型
    "CodeFinding",
    # 任务管理模型
    "TaskStatus",
    "TaskStatusTransitionError",
    "Task",
]
