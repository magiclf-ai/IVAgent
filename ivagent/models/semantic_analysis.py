#!/usr/bin/env python3
"""
代码分析模型

定义代码探索和语义分析使用的数据模型
（原 SemanticAnalysisAgent 已合并到 CodeExplorerAgent）
"""

from dataclasses import dataclass


@dataclass
class CodeFinding:
    """代码发现项 - 简化结构，核心信息用文本承载
    
    注意：此模型目前未被使用，保留用于向后兼容。
    CodeExplorerAgent 直接返回 markdown 格式的文本结果。
    """
    description: str                    # 发现描述（文本形式承载所有信息）
    location: str = ""                  # 位置 (file:line 或 address)，可选
