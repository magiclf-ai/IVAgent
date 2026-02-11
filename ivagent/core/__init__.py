#!/usr/bin/env python3
"""
核心模块

包含 LLM 客户端和日志管理功能
"""

from .tool_llm_client import (
    ToolBasedLLMClient,
    ToolCallResult,
    SimpleJSONLLMClient,
)

from .llm_logger import (
    get_log_manager,
    LLMLogManager,
    LogStorageType,
    LLMLogEntry,
    SQLiteLogStorage,
    JSONLogStorage,
    MemoryLogStorage,
)

from .agent_logger import (
    get_agent_log_manager,
    AgentLogManager,
    AgentExecutionLog,
    AgentTaskLog,
    AgentStatus,
    AgentLogStorage,
)

__all__ = [
    # Tool Call LLM 客户端
    'ToolBasedLLMClient',
    'ToolCallResult',
    'SimpleJSONLLMClient',
    # LLM 日志管理
    'get_log_manager',
    'LLMLogManager',
    'LogStorageType',
    'LLMLogEntry',
    'SQLiteLogStorage',
    'JSONLogStorage',
    'MemoryLogStorage',
    # Agent 日志管理
    'get_agent_log_manager',
    'AgentLogManager',
    'AgentExecutionLog',
    'AgentTaskLog',
    'AgentStatus',
    'AgentLogStorage',
]
