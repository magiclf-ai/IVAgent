#!/usr/bin/env python3
"""
Workflow Parser Module

Workflow Markdown 文档解析器，将 Workflow 解析为描述性上下文。

此模块是 ivagent.models.workflow 的包装，提供 Orchestrator 特定的解析功能。
"""

from typing import Optional
from pathlib import Path

from ..models.workflow import (
    WorkflowContext,
    WorkflowParser as BaseWorkflowParser,
    TargetInfo,
    ScopeInfo,
    StrategyHints,
    VulnerabilityFocus,
)


class WorkflowParser(BaseWorkflowParser):
    """
    Orchestrator 专用的 Workflow 解析器
    
    继承基础解析器，提供额外的便利方法和验证。
    """
    
    def validate(self, context: WorkflowContext) -> tuple[bool, Optional[str]]:
        """
        验证 Workflow 上下文的基本完整性

        注意：这不是配置验证，只是检查必要信息是否存在。
        目标路径可以在运行时提供，因此 target.path 不是必需的。

        Args:
            context: Workflow 上下文

        Returns:
            (是否有效, 错误信息)
        """
        if not context.name:
            return False, "Workflow name is empty"

        # target.path 不是必需的，可以在运行时提供
        # if context.target and context.target.path:
        #     if not Path(context.target.path).exists():
        #         return False, f"Target path does not exist: {context.target.path}"

        return True, None
    
    def parse_and_validate(self, file_path: str) -> WorkflowContext:
        """
        解析并验证 Workflow 文件
        
        Args:
            file_path: Workflow 文件路径
            
        Returns:
            WorkflowContext 对象
            
        Raises:
            ValueError: 验证失败
        """
        context = self.parse(file_path)
        is_valid, error_msg = self.validate(context)
        
        if not is_valid:
            raise ValueError(f"Invalid workflow: {error_msg}")
        
        return context


# 重新导出模型类，方便导入
__all__ = [
    'WorkflowParser',
    'WorkflowContext',
    'TargetInfo',
    'ScopeInfo',
    'StrategyHints',
    'VulnerabilityFocus',
]
