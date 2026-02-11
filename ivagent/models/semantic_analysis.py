#!/usr/bin/env python3
"""
语义分析模型

定义 SemanticAnalysisAgent 使用的数据模型
"""

from dataclasses import dataclass


@dataclass
class CodeFinding:
    """代码发现项 - 简化结构，核心信息用文本承载"""
    description: str                    # 发现描述（文本形式承载所有信息）
    location: str = ""                  # 位置 (file:line 或 address)，可选
