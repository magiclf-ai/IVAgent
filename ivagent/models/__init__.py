#!/usr/bin/env python3
"""
数据模型层

核心数据结构定义
"""

from .constraints import (
    FunctionContext,
    Precondition,
    CallStackFrame,
)

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

__all__ = [
    # 约束模型（纯文本格式）
    "FunctionContext",
    "Precondition",
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
]
