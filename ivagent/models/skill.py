#!/usr/bin/env python3
"""
Skill 数据模型

定义统一的 SkillContext。
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class ScopeInfo:
    """分析范围"""

    description: str
    exclude_hints: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "description": self.description,
            "exclude_hints": self.exclude_hints,
        }


@dataclass
class StrategyHints:
    """策略提示"""

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
        result: Dict[str, Any] = {}
        if self.max_depth:
            result["max_depth"] = self.max_depth
        if self.concurrency:
            result["concurrency"] = self.concurrency
        if self.other_hints:
            result["other_hints"] = self.other_hints
        return result


@dataclass
class SkillContext:
    """
    统一的 Skill 上下文。

    由 SkillParser 从 SKILL.md 解析生成，供 MasterOrchestrator、
    IVAgentScanner、DeepVulnAgent 等组件消费。
    """

    name: str
    description: str
    skill_dir: Optional[Path] = None

    engine: Optional[str] = None
    target_type: str = "generic"

    scope: Optional[ScopeInfo] = None
    strategy_hints: StrategyHints = field(default_factory=StrategyHints)

    taint_sources: List[str] = field(default_factory=list)
    dangerous_apis: List[str] = field(default_factory=list)
    background_knowledge_files: List[str] = field(default_factory=list)

    raw_markdown: str = ""
    vulnerability_focus: str = ""
    background_knowledge: str = ""

    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    supporting_files: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "name": self.name,
            "description": self.description,
            "engine": self.engine,
            "target_type": self.target_type,
            "strategy_hints": self.strategy_hints.to_dict(),
            "vulnerability_focus": self.vulnerability_focus,
            "background_knowledge": self.background_knowledge,
            "background_knowledge_files": self.background_knowledge_files,
            "taint_sources": self.taint_sources,
            "dangerous_apis": self.dangerous_apis,
            "tags": self.tags,
        }
        if self.scope:
            result["scope"] = self.scope.to_dict()
        return result

    def _build_guidance_sections(self) -> List[str]:
        """构建供 LLM 消费的分析指导文本片段。"""

        lines: List[str] = []

        if self.scope:
            lines.extend(
                [
                    "### 分析范围",
                    f"{self.scope.description}",
                    "",
                ]
            )
            if self.scope.exclude_hints:
                lines.extend(
                    [
                        "### 排除建议",
                        f"{self.scope.exclude_hints}",
                        "",
                    ]
                )

        if self.taint_sources:
            lines.extend(["### 污点源", *[f"- {item}" for item in self.taint_sources], ""])

        if self.dangerous_apis:
            lines.extend(["### 危险 API", *[f"- {item}" for item in self.dangerous_apis], ""])

        if self.vulnerability_focus:
            lines.extend(["### 漏洞关注点", f"{self.vulnerability_focus}", ""])

        if self.background_knowledge:
            lines.extend(["### 背景知识", f"{self.background_knowledge}", ""])

        hints_dict = self.strategy_hints.to_dict()
        if hints_dict:
            lines.append("### 策略提示")
            if self.strategy_hints.max_depth:
                lines.append(f"- 建议调用深度: {self.strategy_hints.max_depth}")
            if self.strategy_hints.concurrency:
                lines.append(f"- 建议并发度: {self.strategy_hints.concurrency}")
            if self.strategy_hints.other_hints:
                lines.append(f"- 其他建议: {self.strategy_hints.other_hints}")
            lines.append("")

        if self.raw_markdown:
            lines.append(self.raw_markdown)

        return lines

    def get_full_context_text(self, target_path: Optional[str] = None) -> str:
        """
        获取完整上下文文本，用于注入 LLM Prompt。
        """

        lines = [
            f"## Skill: {self.name}",
            "",
            "### 描述",
            f"{self.description}",
            "",
        ]

        if target_path:
            lines.extend(
                [
                    "### 目标程序",
                    f"- 路径: {target_path}",
                    "",
                ]
            )

        lines.extend(self._build_guidance_sections())

        return "\n".join(lines).strip()

    def get_precondition_text(self) -> Optional[str]:
        """
        获取供 DeepVulnAgent 使用的文本化约束内容。
        """

        text = "\n".join(self._build_guidance_sections()).strip()
        return text or None

    def build_runtime_skill(self, analysis_context: Optional[str] = None) -> Optional["SkillContext"]:
        """
        构建运行时漏洞分析 Skill，将 analysis_context 与 Skill 前置知识统一合并。
        """

        merged_blocks: List[str] = []
        context_text = (analysis_context or "").strip()
        precondition_text = (self.get_precondition_text() or "").strip()

        if context_text:
            merged_blocks.append(context_text)
        if precondition_text and precondition_text != context_text:
            merged_blocks.append(precondition_text)

        merged_text = "\n\n".join(block for block in merged_blocks if block).strip()
        if not merged_text:
            return None

        return SkillContext(
            name="analysis_context",
            description="analysis context",
            target_type="vuln_analysis",
            raw_markdown=merged_text,
        )
