#!/usr/bin/env python3
"""
Orchestrator Module

TaskOrchestratorAgent - LLM 驱动的任务规划 Agent
WorkflowAgent - 自主的 Workflow 执行 Agent
MasterOrchestrator - 多 Workflow 协调器

负责解析 Workflow 文档，通过 Tools 暴露能力，由 LLM 自主决策执行流程。
"""

from .workflow_parser import WorkflowParser, WorkflowContext
from .orchestrator_agent import (
    TaskOrchestratorAgent,
    OrchestratorResult,
    run_workflow,
)
from .workflow_agent import (
    WorkflowAgent,
    WorkflowResult,
)
from .master_orchestrator import (
    MasterOrchestrator,
    MasterOrchestratorResult,
    SubWorkflowInfo,
    run_master_workflow,
)

__all__ = [
    # Workflow
    'WorkflowParser',
    'WorkflowContext',
    # Single Orchestrator
    'TaskOrchestratorAgent',
    'OrchestratorResult',
    'run_workflow',
    # Workflow Agent (New)
    'WorkflowAgent',
    'WorkflowResult',
    # Master Orchestrator (Multi-Workflow)
    'MasterOrchestrator',
    'MasterOrchestratorResult',
    'SubWorkflowInfo',
    'run_master_workflow',
]

