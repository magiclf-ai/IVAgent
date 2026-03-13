#!/usr/bin/env python3
"""
Orchestrator Module

TaskOrchestratorAgent - LLM 驱动的任务规划 Agent
TaskExecutorAgent - 任务执行 Agent
MasterOrchestrator - 多 Skill 协调器

负责消费 SkillContext，通过 Tools 暴露能力，由 LLM 自主决策执行流程。
"""

from .orchestrator_agent import (
    TaskOrchestratorAgent,
    OrchestratorResult,
)
from .task_executor_agent import (
    TaskExecutorAgent,
    TaskExecutorResult,
)
from .master_orchestrator import (
    MasterOrchestrator,
    MasterOrchestratorResult,
)

__all__ = [
    # Single Orchestrator
    'TaskOrchestratorAgent',
    'OrchestratorResult',
    # Task Executor Agent
    'TaskExecutorAgent',
    'TaskExecutorResult',
    # Master Orchestrator (Multi-Skill)
    'MasterOrchestrator',
    'MasterOrchestratorResult',
]

