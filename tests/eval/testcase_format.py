#!/usr/bin/env python3
"""Markdown-based test case loader for the evaluation framework."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import List


METADATA_LINE_PATTERN = r"(?m)^- \*\*{key}\*\*:\s*(.+?)\s*$"


@dataclass
class TestCase:
    """Evaluation test case loaded from a testcase directory."""

    name: str
    content: str
    testcase_dir: Path
    engine: str
    skill: str
    entry_functions: List[str]
    timeout: int
    tags: List[str]


def extract_metadata(content: str, key: str) -> str:
    """Extract `- **Key**: value` metadata from TESTCASE.md."""

    match = re.search(METADATA_LINE_PATTERN.format(key=re.escape(key)), content)
    return match.group(1).strip() if match else ""


def load_testcase(testcase_dir: Path) -> TestCase:
    """Load a single testcase directory."""

    md_path = testcase_dir / "TESTCASE.md"
    if not md_path.exists():
        raise FileNotFoundError(f"TESTCASE.md not found in {testcase_dir}")

    content = md_path.read_text(encoding="utf-8")
    entry_functions = [
        item.strip()
        for item in extract_metadata(content, "Entry Functions").split(",")
        if item.strip()
    ]
    tags = [
        item.strip()
        for item in extract_metadata(content, "Tags").split(",")
        if item.strip()
    ]

    timeout_raw = extract_metadata(content, "Timeout")
    timeout_match = re.search(r"(\d+)", timeout_raw)
    timeout = int(timeout_match.group(1)) if timeout_match else 300

    testcase = TestCase(
        name=testcase_dir.name,
        content=content,
        testcase_dir=testcase_dir,
        engine=extract_metadata(content, "Engine") or "source",
        skill=extract_metadata(content, "Skill"),
        entry_functions=entry_functions,
        timeout=timeout,
        tags=tags,
    )
    if not testcase.skill:
        raise ValueError(f"Missing Skill metadata in {md_path}")
    if not testcase.entry_functions:
        raise ValueError(f"Missing Entry Functions metadata in {md_path}")
    return testcase


def discover_testcases(root: Path) -> List[TestCase]:
    """Discover all testcases below `root`."""

    if not root.exists():
        return []

    testcases: List[TestCase] = []
    for md_path in sorted(root.rglob("TESTCASE.md")):
        testcase_dir = md_path.parent
        testcases.append(load_testcase(testcase_dir))
    return sorted(testcases, key=lambda item: item.name)
