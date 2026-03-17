#!/usr/bin/env python3
"""Markdown-based test case loader for the evaluation framework."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import List


METADATA_LINE_PATTERN = r"(?m)^- \*\*{key}\*\*:\s*(.+?)\s*$"
REPO_ROOT = Path(__file__).resolve().parents[2]
SHARED_SKILL_PATH = REPO_ROOT / "tests" / "eval" / "skills" / "autonomous_binary_pseudocode" / "SKILL.md"


@dataclass
class TestCase:
    """Evaluation test case loaded from a testcase directory."""

    name: str
    content: str
    ground_truth_markdown: str
    testcase_dir: Path
    analysis_engine: str
    input_engine: str
    task_path: Path
    shared_skill_path: Path
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
    task_path = testcase_dir / "TASK.md"
    if not task_path.exists():
        raise FileNotFoundError(f"TASK.md not found in {testcase_dir}")
    if not SHARED_SKILL_PATH.exists():
        raise FileNotFoundError(f"Shared eval skill not found: {SHARED_SKILL_PATH}")

    tags = [
        item.strip()
        for item in extract_metadata(content, "Tags").split(",")
        if item.strip()
    ]
    entry_functions = [
        item.strip()
        for item in extract_metadata(content, "Entry Functions").split(",")
        if item.strip()
    ]

    timeout_raw = extract_metadata(content, "Timeout")
    timeout_match = re.search(r"(\d+)", timeout_raw)
    timeout = int(timeout_match.group(1)) if timeout_match else 900

    ground_truth_match = re.search(
        r"(?ms)^## Expected Vulnerabilities\s*$\n(?P<body>.+)$",
        content,
    )
    ground_truth_markdown = (
        "## Expected Vulnerabilities\n\n" + ground_truth_match.group("body").strip()
        if ground_truth_match
        else content.strip()
    )

    testcase = TestCase(
        name=testcase_dir.name,
        content=content,
        ground_truth_markdown=ground_truth_markdown,
        testcase_dir=testcase_dir,
        analysis_engine=extract_metadata(content, "Engine") or "source",
        input_engine=extract_metadata(content, "Input Engine") or "ida",
        task_path=task_path,
        shared_skill_path=SHARED_SKILL_PATH,
        entry_functions=entry_functions,
        timeout=timeout,
        tags=tags,
    )
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
