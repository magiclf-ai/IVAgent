#!/usr/bin/env python3
"""
Workflow 数据模型

定义 Workflow 文档的数据结构，用于描述用户意图和分析上下文。
注意：这是描述性上下文，供 LLM 理解，而非机器配置。
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from pathlib import Path
import re
import yaml


@dataclass
class TargetInfo:
    """
    目标信息 - 描述性（可选）
    
    Attributes:
        path: 目标程序路径（可选，可通过运行时参数提供）
        description: 用户提供的额外描述（可选）
    """
    path: Optional[str] = None
    description: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        result = {}
        if self.path:
            result["path"] = self.path
        if self.description:
            result["description"] = self.description
        return result


@dataclass
class ScopeInfo:
    """
    分析范围 - 描述性
    
    Attributes:
        description: 自然语言描述分析范围
        exclude_hints: 排除建议（可选）
    """
    description: str
    exclude_hints: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "description": self.description,
            "exclude_hints": self.exclude_hints,
        }


@dataclass
class StrategyHints:
    """
    策略提示 - 建议性描述
    
    Attributes:
        max_depth: 建议调用链深度
        concurrency: 建议并发度
        other_hints: 其他策略建议
    """
    max_depth: Optional[str] = None
    concurrency: Optional[str] = None
    other_hints: Optional[str] = None
    
    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> "StrategyHints":
        if not data:
            return cls()
        return cls(
            max_depth=data.get("max_depth"),
            concurrency=data.get("concurrency"),
            other_hints=data.get("other_hints") or data.get("description"),
        )
    
    def to_dict(self) -> Dict[str, Any]:
        result = {}
        if self.max_depth:
            result["max_depth"] = self.max_depth
        if self.concurrency:
            result["concurrency"] = self.concurrency
        if self.other_hints:
            result["other_hints"] = self.other_hints
        return result


@dataclass
class VulnerabilityFocus:
    """
    漏洞关注点 - 自然语言描述
    
    Attributes:
        description: 漏洞关注点描述文本
    """
    description: str
    
    def to_dict(self) -> Dict[str, Any]:
        return {"description": self.description}


@dataclass
class WorkflowContext:
    """
    Workflow 上下文数据类
    
    注意: 这不是配置，而是提供给 LLM 的上下文信息。
    LLM 理解这些描述性内容，而非解析配置字段。
    
    Attributes:
        name: Workflow 名称
        description: Workflow 描述
        version: 版本号
        target: 目标信息（可选，可通过运行时参数提供）
        scope: 分析范围
        strategy_hints: 策略建议（非强制）
        vulnerability_focus: 漏洞关注点描述
        background_knowledge: 背景知识 Markdown
        raw_markdown: 原始 Markdown 正文（Frontmatter 之后的内容）
    """
    name: str
    description: str
    version: str
    target: Optional[TargetInfo] = None
    scope: ScopeInfo = None
    strategy_hints: StrategyHints = None
    vulnerability_focus: str = ""
    background_knowledge: str = ""
    raw_markdown: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        result = {
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "strategy_hints": self.strategy_hints.to_dict(),
            "vulnerability_focus": self.vulnerability_focus,
            "background_knowledge": self.background_knowledge,
        }
        if self.target:
            result["target"] = self.target.to_dict()
        if self.scope:
            result["scope"] = self.scope.to_dict()
        return result
    
    def get_full_context_text(self, target_path: Optional[str] = None) -> str:
        """
        获取完整的上下文文本，用于注入 LLM Prompt
        
        Args:
            target_path: 运行时提供的目标路径（可选）
        
        Returns:
            格式化的上下文文本
        """
        lines = [
            f"## Workflow: {self.name}",
            f"",
            f"### 描述",
            f"{self.description}",
            f"",
        ]
        
        # 使用运行时传入的 target_path 或 workflow 中的 target
        if target_path:
            lines.extend([
                f"### 目标程序",
                f"- 路径: {target_path}",
            ])
        elif self.target and self.target.path:
            lines.extend([
                f"### 目标程序",
                f"- 路径: {self.target.path}",
            ])
            if self.target.description:
                lines.extend([f"- 额外描述: {self.target.description}"])
        else:
            lines.extend([
                f"### 目标程序",
                f"- 路径: （待运行时指定）",
            ])

        # 添加分析范围（可选）
        if self.scope:
            lines.extend([
                f"",
                f"### 分析范围",
                f"{self.scope.description}",
            ])

            if self.scope.exclude_hints:
                lines.extend([
                    f"",
                    f"### 排除建议",
                    f"{self.scope.exclude_hints}",
                ])
        
        # 添加漏洞关注点
        if self.vulnerability_focus:
            lines.extend([
                f"",
                f"### 漏洞关注点",
                f"{self.vulnerability_focus}",
            ])
        
        # 添加背景知识
        if self.background_knowledge:
            lines.extend([
                f"",
                f"### 背景知识",
                f"{self.background_knowledge}",
            ])
        
        hints_dict = self.strategy_hints.to_dict()
        if hints_dict:
            lines.extend([
                f"",
                f"### 策略提示",
            ])
            if self.strategy_hints.max_depth:
                lines.append(f"- 建议调用深度: {self.strategy_hints.max_depth}")
            if self.strategy_hints.concurrency:
                lines.append(f"- 建议并发度: {self.strategy_hints.concurrency}")
            if self.strategy_hints.other_hints:
                lines.append(f"- 其他建议: {self.strategy_hints.other_hints}")
        
        # 添加原始 Markdown 内容（--- 后面的 workflow 流程）
        if self.raw_markdown:
            lines.extend([
                f"",
                f"{self.raw_markdown}",
            ])
        
        return "\n".join(lines)


class WorkflowParser:
    """
    Workflow Markdown 文档解析器
    
    将 Workflow 解析为描述性上下文，供 LLM 理解。
    不做任何配置验证或默认值填充。
    """
    
    def __init__(self):
        self._frontmatter_pattern = re.compile(r'^---\s*\n(.*?)\n---\s*\n', re.DOTALL)
    
    def parse(self, file_path: str) -> WorkflowContext:
        """
        解析 Workflow 文档为上下文
        
        Args:
            file_path: Workflow 文件路径
            
        Returns:
            WorkflowContext 对象
            
        Raises:
            FileNotFoundError: 文件不存在
            ValueError: 文档格式错误
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Workflow file not found: {file_path}")
        
        content = path.read_text(encoding='utf-8')
        return self.parse_content(content)
    
    def parse_content(self, content: str) -> WorkflowContext:
        """
        解析 Workflow 内容字符串
        
        Args:
            content: Workflow 文档内容
            
        Returns:
            WorkflowContext 对象
        """
        # 提取 YAML Frontmatter
        frontmatter_match = self._frontmatter_pattern.match(content)
        
        if frontmatter_match:
            yaml_content = frontmatter_match.group(1)
            markdown_body = content[frontmatter_match.end():]
            metadata = yaml.safe_load(yaml_content) or {}
        else:
            # 没有 Frontmatter，尝试解析整个内容为 Markdown
            yaml_content = ""
            markdown_body = content
            metadata = {}
        
        # 解析目标信息（可选）
        target_data = metadata.get('target', {})
        if target_data and target_data.get('path'):
            target = TargetInfo(
                path=target_data.get('path', ''),
                description=target_data.get('description')
            )
        else:
            target = None
        
        # 解析范围信息（可选）
        scope_data = metadata.get('scope', {})
        if scope_data:
            scope = ScopeInfo(
                description=scope_data.get('description', ''),
                exclude_hints=scope_data.get('exclude_hints')
            )
        else:
            scope = None
        
        # 解析策略提示
        strategy_data = metadata.get('strategy_hints') or metadata.get('strategy', {})
        strategy_hints = StrategyHints.from_dict(
            strategy_data if isinstance(strategy_data, dict) else None
        )
        
        # 解析漏洞关注点
        vuln_focus_data = metadata.get('vulnerability_focus', {})
        if isinstance(vuln_focus_data, dict):
            vulnerability_focus = vuln_focus_data.get('description', '')
        else:
            vulnerability_focus = str(vuln_focus_data) if vuln_focus_data else ''
        
        # 构建 WorkflowContext
        return WorkflowContext(
            name=metadata.get('name', ''),
            description=metadata.get('description', ''),
            version=metadata.get('version', '1.0'),
            target=target,
            scope=scope,
            strategy_hints=strategy_hints,
            vulnerability_focus=vulnerability_focus,
            background_knowledge=metadata.get('background_knowledge', ''),
            raw_markdown=markdown_body
        )


# 便捷函数
def parse_workflow(file_path: str) -> WorkflowContext:
    """
    便捷函数：解析 Workflow 文件
    
    Args:
        file_path: Workflow 文件路径
        
    Returns:
        WorkflowContext 对象
    """
    parser = WorkflowParser()
    return parser.parse(file_path)


def parse_workflow_content(content: str) -> WorkflowContext:
    """
    便捷函数：解析 Workflow 内容字符串
    
    Args:
        content: Workflow 文档内容
        
    Returns:
        WorkflowContext 对象
    """
    parser = WorkflowParser()
    return parser.parse_content(content)
