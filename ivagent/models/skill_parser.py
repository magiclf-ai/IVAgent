#!/usr/bin/env python3
"""
SKILL.md 解析器
"""

import re
from pathlib import Path
from typing import Any, Dict, List

import yaml

from .skill import ScopeInfo, SkillContext, StrategyHints


class SkillParser:
    """SKILL.md 解析器"""

    def __init__(self):
        self._frontmatter_pattern = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL)

    def parse(self, skill_path: str) -> SkillContext:
        """
        解析 SKILL.md 文件或 skill 目录。
        """

        path = Path(skill_path)
        if path.is_dir():
            skill_md = path / "SKILL.md"
            if not skill_md.exists():
                raise FileNotFoundError(f"SKILL.md not found in directory: {skill_path}")
            skill_dir = path
            path = skill_md
        else:
            if not path.exists():
                raise FileNotFoundError(f"Skill file not found: {skill_path}")
            skill_dir = path.parent

        content = path.read_text(encoding="utf-8")
        context = self._parse_content(content, skill_dir=skill_dir)
        context.skill_dir = skill_dir
        context.supporting_files = self._load_supporting_files(skill_dir, path.name)
        return context

    def _parse_content(self, content: str, skill_dir: Path | None = None) -> SkillContext:
        """解析 SKILL.md 字符串内容。"""

        metadata, markdown_body = self._split_frontmatter(content)
        return self._build_context(metadata, markdown_body, skill_dir=skill_dir)

    def _split_frontmatter(self, content: str) -> tuple[Dict[str, Any], str]:
        """拆分 frontmatter 与正文。"""

        frontmatter_match = self._frontmatter_pattern.match(content)
        if frontmatter_match:
            yaml_content = frontmatter_match.group(1)
            markdown_body = content[frontmatter_match.end() :]
            metadata = yaml.safe_load(yaml_content) or {}
        else:
            markdown_body = content
            metadata = {}
        return metadata, markdown_body

    def _build_context(
        self,
        metadata: Dict[str, Any],
        markdown_body: str,
        skill_dir: Path | None = None,
    ) -> SkillContext:
        """基于 frontmatter 与正文构建 SkillContext。"""

        scope_data = metadata.get("scope")
        scope = None
        if isinstance(scope_data, dict):
            scope = ScopeInfo(
                description=scope_data.get("description", ""),
                exclude_hints=scope_data.get("exclude_hints"),
            )

        strategy_data = metadata.get("strategy_hints")
        strategy_hints = StrategyHints.from_dict(strategy_data if isinstance(strategy_data, dict) else None)

        taint_sources = self._normalize_string_list(metadata.get("taint_sources", []))
        dangerous_apis = self._normalize_string_list(metadata.get("dangerous_apis", []))
        background_knowledge_files = self._normalize_string_list(metadata.get("background_knowledge_files", []))
        tags = self._normalize_string_list(metadata.get("tags", []))
        background_knowledge = self._build_background_knowledge(
            metadata=metadata,
            skill_dir=skill_dir,
        )

        return SkillContext(
            name=metadata.get("name", ""),
            description=metadata.get("description", ""),
            engine=metadata.get("engine"),
            target_type=metadata.get("target_type", "generic"),
            scope=scope,
            strategy_hints=strategy_hints,
            taint_sources=taint_sources,
            dangerous_apis=dangerous_apis,
            background_knowledge_files=background_knowledge_files,
            raw_markdown=markdown_body.strip(),
            vulnerability_focus=metadata.get("vulnerability_focus", ""),
            background_knowledge=background_knowledge,
            tags=tags,
            metadata={
                key: value
                for key, value in metadata.items()
                if key
                not in {
                    "name",
                    "description",
                    "engine",
                    "target_type",
                    "scope",
                    "strategy_hints",
                    "taint_sources",
                    "dangerous_apis",
                    "vulnerability_focus",
                    "background_knowledge",
                    "background_knowledge_files",
                    "tags",
                }
            },
        )

    def _build_background_knowledge(
        self,
        metadata: Dict[str, Any],
        skill_dir: Path | None = None,
    ) -> str:
        """按 frontmatter 声明顺序拼接背景知识。"""

        if not metadata:
            return ""

        blocks: List[str] = []
        for key, value in metadata.items():
            if key == "background_knowledge":
                text = self._normalize_text_block(value)
                if text:
                    blocks.append(text)
            elif key == "background_knowledge_files":
                for relative_path in self._normalize_string_list(value):
                    text = self._read_background_knowledge_file(
                        skill_dir=skill_dir,
                        relative_path=relative_path,
                    )
                    if text:
                        blocks.append(text)

        return "\n\n".join(blocks).strip()

    @staticmethod
    def _normalize_text_block(value: Any) -> str:
        if isinstance(value, list):
            parts = [str(item).strip() for item in value if str(item).strip()]
            return "\n".join(parts).strip()
        if value is None:
            return ""
        return str(value).strip()

    @staticmethod
    def _read_background_knowledge_file(skill_dir: Path | None, relative_path: str) -> str:
        if not skill_dir:
            raise ValueError("background_knowledge_files requires a concrete skill directory")

        candidate = Path(relative_path)
        if not candidate.is_absolute():
            candidate = (skill_dir / candidate).resolve()

        if not candidate.exists() or not candidate.is_file():
            raise FileNotFoundError(f"Background knowledge file not found: {relative_path}")

        return candidate.read_text(encoding="utf-8").strip()

    def _load_supporting_files(self, skill_dir: Path, main_file: str) -> Dict[str, str]:
        """加载 skill 目录下的其他文本支持文件。"""

        supporting: Dict[str, str] = {}
        if not skill_dir.is_dir():
            return supporting

        for file_path in skill_dir.rglob("*"):
            if not file_path.is_file() or file_path.name == main_file:
                continue
            relative_path = str(file_path.relative_to(skill_dir))
            try:
                supporting[relative_path] = file_path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, PermissionError):
                continue

        return supporting

    def discover(self, skills_root: str) -> List[SkillContext]:
        """发现根目录下全部 skill。"""

        root = Path(skills_root)
        if not root.is_dir():
            return []

        skills: List[SkillContext] = []
        for skill_dir in sorted(root.iterdir()):
            if not skill_dir.is_dir():
                continue
            if not (skill_dir / "SKILL.md").exists():
                continue
            try:
                skills.append(self.parse(str(skill_dir)))
            except (FileNotFoundError, ValueError):
                continue
        return skills

    def resolve_skill(self, skill_name: str, skills_root: str = "vuln_skills") -> SkillContext:
        """按名称或路径解析 skill。"""

        direct_path = Path(skill_name)
        if direct_path.exists():
            return self.parse(str(direct_path))

        variants = [
            skill_name,
            skill_name.replace("-", "_"),
            skill_name.replace("_", "-"),
        ]
        for variant in variants:
            candidate_dir = Path(skills_root) / variant
            if candidate_dir.is_dir() and (candidate_dir / "SKILL.md").exists():
                return self.parse(str(candidate_dir))

        raise FileNotFoundError(f"Skill not found: {skill_name} (searched in {skills_root}/)")

    @staticmethod
    def _normalize_string_list(value: Any) -> List[str]:
        if isinstance(value, str):
            stripped = value.strip()
            return [stripped] if stripped else []
        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item).strip()]
        return []
