#!/usr/bin/env python3
"""System-test runner built around the public ivagent_cli.py entrypoint."""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import re
import shutil
import sqlite3
import sys
import tempfile
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from ivagent.agents.deep_vuln_agent import DeepVulnAgent
from ivagent.core.agent_logger import AgentLogManager, AgentLogStorage
from ivagent.core.db_profiles import (
    ENV_AGENT_LOG_DB,
    ENV_KEY,
    ENV_LLM_LOG_DB,
    ENV_VULN_DB,
    PROFILE_PRODUCTION,
    activate_db_profile,
)
from ivagent.core.llm_logger import LLMLogManager, SQLiteLogStorage
from ivagent.core.run_context import ENV_RUN_ID, ENV_RUN_LABEL
from ivagent.core.vuln_storage import VulnerabilityManager, VulnerabilityStorage
from ivagent.engines.ida_engine import IDAClient
from ivagent.engines.service_manager import EngineServiceManager

from tests.eval.testcase_format import TestCase

BATCH_PROGRESS_JSON = "PROGRESS.json"
BATCH_PROGRESS_MD = "PROGRESS.md"
REPO_ROOT = Path(__file__).resolve().parents[2]
IDA_PSEUDOCODE_DIRNAME = "ida_pseudocode_source"
IDA_MANIFEST_NAME = ".manifest.json"
PREPARED_TARGET_METADATA = "prepared_target.json"
MAX_IDA_EXPORT_FUNCTIONS = 500
IDA_DB_SUFFIXES = {".i64", ".idb"}
PSEUDOCODE_TEXT_SUFFIXES = {".c", ".cc", ".cpp", ".h", ".hpp", ".txt"}
FATAL_TOOL_ERROR_PATTERNS: tuple[tuple[str, ...], ...] = (
    ("docstring", "not found in function signature"),
    ("bind_tools",),
    ("tool schema",),
    ("invalid tool schema",),
    ("tool registration",),
)


@dataclass
class TestRunResult:
    """Single testcase execution result."""

    testcase_name: str
    success: bool
    error: Optional[str]
    wall_time_seconds: float
    vulnerabilities: List[Dict[str, Any]]
    results_markdown: str
    output_dir: str
    llm_log_db: str
    agent_log_db: str
    vuln_db: str
    fatal_llm_errors: List[str] = field(default_factory=list)


@dataclass
class PreparedTarget:
    """Prepared analysis target for one testcase run."""

    target_path: Path
    source_root: Optional[str]
    metadata: Dict[str, Any] = field(default_factory=dict)


def format_run_summary_as_markdown(result: TestRunResult) -> str:
    """Render testcase execution metadata as markdown."""

    lines = [
        f"# Test Run Summary: {result.testcase_name}",
        "",
        f"- **Status**: {'success' if result.success else 'failed'}",
        f"- **Wall Time Seconds**: {result.wall_time_seconds:.6f}",
        f"- **Vulnerabilities Count**: {len(result.vulnerabilities)}",
        f"- **Fatal LLM Log Errors Count**: {len(result.fatal_llm_errors)}",
        f"- **Output Directory**: {result.output_dir}",
        f"- **LLM Log DB**: {result.llm_log_db}",
        f"- **Agent Log DB**: {result.agent_log_db}",
        f"- **Vulnerability DB**: {result.vuln_db}",
    ]
    if result.error:
        lines.append(f"- **Error**: {result.error}")
    lines.append(f"- **LLM Interactions**: {Path(result.output_dir) / 'llm_interactions.md'}")
    lines.append(f"- **Agent Execution**: {Path(result.output_dir) / 'agent_execution.md'}")
    lines.append("")
    if result.fatal_llm_errors:
        lines.extend(["## Fatal LLM Log Errors", ""])
        for error in result.fatal_llm_errors:
            lines.append(f"- {error}")
        lines.append("")
    return "\n".join(lines)


def _stringify_llm_payload(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (dict, list)):
        try:
            return json.dumps(value, ensure_ascii=False, indent=2)
        except TypeError:
            return str(value)
    return str(value)


def _extract_message_text(message: Any) -> str:
    if isinstance(message, str):
        return message
    if isinstance(message, list):
        parts: List[str] = []
        for item in message:
            if isinstance(item, dict):
                text = item.get("text")
                parts.append(str(text) if text else json.dumps(item, ensure_ascii=False, indent=2))
            else:
                parts.append(str(item))
        return "\n".join(parts)
    if isinstance(message, dict):
        if "content" in message:
            return _extract_message_text(message["content"])
        return json.dumps(message, ensure_ascii=False, indent=2)
    return str(message)


def format_llm_interactions_as_markdown(llm_log_db: str) -> str:
    """Export detailed LLM interactions from sqlite into readable markdown."""

    db_path = Path(llm_log_db)
    if not db_path.exists():
        return "# LLM Interactions\n\nNo `llm_logs.db` found.\n"

    storage = SQLiteLogStorage(db_path)
    entries = list(reversed(storage.query_entries(limit=1000)))
    lines = [
        "# LLM Interactions",
        "",
        f"**Total Entries**: {len(entries)}",
        "",
    ]
    if not entries:
        lines.extend(["No LLM interactions recorded.", ""])
        return "\n".join(lines)

    for index, entry in enumerate(entries, start=1):
        lines.extend(
            [
                f"## Call {index}",
                "",
                f"- **Timestamp**: {entry.timestamp}",
                f"- **Model**: {entry.model}",
                f"- **Call Type**: {entry.call_type}",
                f"- **Status**: {entry.status}",
                f"- **Success**: {entry.success}",
                f"- **Latency**: {entry.latency_ms:.0f} ms",
                f"- **Retry Count**: {entry.retry_count}",
            ]
        )
        if entry.agent_id:
            lines.append(f"- **Agent ID**: {entry.agent_id}")
        if entry.metadata:
            lines.extend(["", "**Metadata**:", "", "```json", _stringify_llm_payload(entry.metadata), "```"])
        if entry.system_prompt:
            lines.extend(["", "### System Prompt", "", "```text", entry.system_prompt, "```"])
        if entry.output_schema:
            lines.extend(["", "### Output Schema", "", "```text", str(entry.output_schema), "```"])
        lines.extend(["", "### Messages", ""])
        for msg_index, message in enumerate(entry.messages, start=1):
            role = "unknown"
            content = message
            if isinstance(message, dict):
                role = str(message.get("role") or message.get("type") or "unknown")
                content = message.get("content", message)
            lines.extend(
                [
                    f"#### Message {msg_index} ({role})",
                    "",
                    "```text",
                    _extract_message_text(content),
                    "```",
                    "",
                ]
            )
        if entry.response is not None:
            lines.extend(["### Response", "", "```json", _stringify_llm_payload(entry.response), "```", ""])
        if entry.error:
            lines.extend(["### Error", "", "```text", entry.error, "```", ""])
        lines.extend(["---", ""])

    return "\n".join(lines)


def _stringify_agent_payload(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, indent=2)
    return str(value)


def _format_agent_tree_node(node: Dict[str, Any], level: int = 0) -> str:
    indent = "  " * level
    lines = [
        f"{indent}- **{node.get('agent_type', 'Unknown')}** ({node.get('target_function', 'Unknown')})",
        f"{indent}  - Agent ID: {node.get('agent_id', 'Unknown')}",
        f"{indent}  - Status: {node.get('status', 'unknown')}",
        f"{indent}  - Depth: {node.get('depth', 0)}",
        f"{indent}  - Vulnerabilities: {node.get('vulnerabilities_found', 0)}",
        f"{indent}  - Sub-agents: {node.get('sub_agents_created', 0)}",
        f"{indent}  - LLM Calls: {node.get('llm_calls', 0)}",
    ]
    if node.get("error_message"):
        lines.append(f"{indent}  - Error: {node['error_message']}")
    if node.get("summary"):
        lines.append(f"{indent}  - Summary: {node['summary']}")
    for child in node.get("children", []):
        lines.append(_format_agent_tree_node(child, level + 1))
    return "\n".join(lines)


def format_agent_execution_as_markdown(agent_log_db: str) -> str:
    """Export agent execution and task logs into readable markdown."""

    db_path = Path(agent_log_db)
    if not db_path.exists():
        return "# Agent Execution\n\nNo `agent_logs.db` found.\n"

    storage = AgentLogStorage(db_path)
    stats = storage.get_stats()
    roots = storage.get_executions_by_parent(None)
    lines = [
        "# Agent Execution",
        "",
        "## Statistics",
        "",
        f"- **Total Agents**: {stats['total_agents']}",
        f"- **Completed**: {stats['completed']}",
        f"- **Failed**: {stats['failed']}",
        f"- **Total Vulnerabilities Found**: {stats['total_vulnerabilities']}",
        "",
        "## Execution Tree",
        "",
    ]
    if not roots:
        lines.extend(["No agent executions recorded.", ""])
        return "\n".join(lines)

    for root in roots:
        tree = storage.get_execution_tree(root.agent_id)
        if tree:
            lines.append(_format_agent_tree_node(tree))
            lines.append("")

    lines.extend(["## Execution Details", ""])
    for index, execution in enumerate(reversed(storage.query_executions(limit=1000)), start=1):
        lines.extend(
            [
                f"### Execution {index}: {execution.agent_type} ({execution.target_function})",
                "",
                f"- **Agent ID**: {execution.agent_id}",
                f"- **Parent ID**: {execution.parent_id or 'None'}",
                f"- **Status**: {execution.status}",
                f"- **Start Time**: {execution.start_time}",
                f"- **End Time**: {execution.end_time or 'N/A'}",
                f"- **Depth**: {execution.depth}",
                f"- **Vulnerabilities Found**: {execution.vulnerabilities_found}",
                f"- **Sub-agents Created**: {execution.sub_agents_created}",
                f"- **LLM Calls**: {execution.llm_calls}",
            ]
        )
        if execution.call_stack:
            lines.extend(["", "**Call Stack**:", ""])
            for item in execution.call_stack:
                lines.append(f"- {item}")
        if execution.summary:
            lines.extend(["", "**Summary**:", "", execution.summary, ""])
        if execution.error_message:
            lines.extend(["", "**Error**:", "", "```text", execution.error_message, "```", ""])
        if execution.metadata:
            lines.extend(["**Metadata**:", "", "```json", _stringify_agent_payload(execution.metadata), "```", ""])

        tasks = storage.get_tasks_by_agent(execution.agent_id)
        if tasks:
            lines.extend(["**Tasks**:", ""])
            for task in tasks:
                lines.extend(
                    [
                        f"- **{task.task_type}** -> {task.target}",
                        f"  - Status: {task.status}",
                        f"  - Start Time: {task.start_time}",
                        f"  - End Time: {task.end_time or 'N/A'}",
                    ]
                )
                if task.result_summary:
                    lines.append(f"  - Result: {task.result_summary}")
                if task.error_message:
                    lines.append(f"  - Error: {task.error_message}")
                if task.metadata:
                    lines.extend(
                        [
                            "  - Metadata:",
                            "```json",
                            _stringify_agent_payload(task.metadata),
                            "```",
                        ]
                    )
            lines.append("")
        lines.extend(["---", ""])

    return "\n".join(lines)


def write_run_artifacts(result: TestRunResult) -> None:
    """Persist testcase artifacts as markdown documents only."""

    output_dir = Path(result.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "detection_results.md").write_text(result.results_markdown, encoding="utf-8")
    (output_dir / "run_summary.md").write_text(format_run_summary_as_markdown(result), encoding="utf-8")
    (output_dir / "llm_interactions.md").write_text(
        format_llm_interactions_as_markdown(result.llm_log_db),
        encoding="utf-8",
    )
    (output_dir / "agent_execution.md").write_text(
        format_agent_execution_as_markdown(result.agent_log_db),
        encoding="utf-8",
    )


def write_run_index(results: List[TestRunResult], output_dir: str) -> None:
    """Persist a markdown index for a batch run."""

    base_dir = Path(output_dir)
    base_dir.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Evaluation Run Index",
        "",
        f"**Total Test Cases**: {len(results)}",
        "",
    ]
    for result in results:
        lines.extend(
            [
                f"## {result.testcase_name}",
                "",
                f"- **Status**: {'success' if result.success else 'failed'}",
                f"- **Wall Time Seconds**: {result.wall_time_seconds:.6f}",
                f"- **Vulnerabilities Count**: {len(result.vulnerabilities)}",
                f"- **Fatal LLM Log Errors Count**: {len(result.fatal_llm_errors)}",
                f"- **Run Directory**: {result.output_dir}",
            ]
        )
        if result.error:
            lines.append(f"- **Error**: {result.error}")
        if result.fatal_llm_errors:
            lines.append(f"- **Fatal LLM Error Summary**: {_build_fatal_llm_error_summary(result.fatal_llm_errors)}")
        lines.append("")
    (base_dir / "RUNS.md").write_text("\n".join(lines), encoding="utf-8")
    print(f"Run index saved to {base_dir / 'RUNS.md'}")


def _batch_progress_paths(output_dir: str | Path) -> tuple[Path, Path]:
    root = Path(output_dir)
    return root / BATCH_PROGRESS_JSON, root / BATCH_PROGRESS_MD


def _init_batch_progress(testcases: List[TestCase], output_dir: str | Path, parallelism: int) -> Dict[str, Any]:
    root = Path(output_dir)
    now = datetime.now().isoformat()
    return {
        "started_at": now,
        "updated_at": now,
        "parallelism": max(1, parallelism),
        "summary": {
            "total": len(testcases),
            "pending": len(testcases),
            "running": 0,
            "completed": 0,
            "success": 0,
            "failed": 0,
        },
        "testcases": {
            testcase.name: {
                "name": testcase.name,
                "engine": testcase.analysis_engine,
                "status": "pending",
                "run_id": None,
                "timeout": testcase.timeout,
                "output_dir": str(root / testcase.name),
                "console_log": str(root / testcase.name / "console.log"),
                "started_at": None,
                "finished_at": None,
                "wall_time_seconds": None,
                "vulnerabilities_count": 0,
                "error": None,
                "fatal_llm_errors": [],
            }
            for testcase in testcases
        },
    }


def _refresh_batch_progress_summary(progress: Dict[str, Any]) -> None:
    cases = list(progress.get("testcases", {}).values())
    pending = sum(1 for case in cases if case.get("status") == "pending")
    running = sum(1 for case in cases if case.get("status") == "running")
    success = sum(1 for case in cases if case.get("status") == "success")
    failed = sum(1 for case in cases if case.get("status") == "failed")
    completed = success + failed
    progress["updated_at"] = datetime.now().isoformat()
    progress["summary"] = {
        "total": len(cases),
        "pending": pending,
        "running": running,
        "completed": completed,
        "success": success,
        "failed": failed,
    }


def _format_duration(seconds: Any) -> str:
    if seconds is None:
        return "N/A"
    try:
        seconds = float(seconds)
    except (TypeError, ValueError):
        return str(seconds)
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes, remain = divmod(int(seconds), 60)
    if minutes < 60:
        return f"{minutes}m{remain:02d}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h{minutes:02d}m"


def _normalize_inline_text(text: Any, max_len: int = 240) -> str:
    compact = " ".join(str(text or "").split())
    if len(compact) <= max_len:
        return compact
    return compact[: max_len - 3] + "..."


def _read_last_nonempty_log_line(log_path: Path) -> str:
    if not log_path.exists():
        return ""
    try:
        lines = log_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    for line in reversed(lines):
        line = line.strip()
        if line:
            return line
    return ""


def _collect_runtime_metrics(case: Dict[str, Any]) -> Dict[str, Any]:
    metrics = {
        "llm_calls": 0,
        "llm_avg_latency_ms": None,
        "llm_max_latency_ms": None,
        "agent_total": 0,
        "agent_running": 0,
        "agent_failed": 0,
        "task_total": 0,
        "task_running": 0,
        "task_failed": 0,
    }

    run_id = str(case.get("run_id") or "").strip()
    output_dir = Path(case.get("output_dir", ""))
    llm_db = output_dir / "llm_logs.db"
    if llm_db.exists():
        try:
            conn = sqlite3.connect(str(llm_db))
            try:
                if run_id:
                    try:
                        row = conn.execute(
                            """
                            SELECT COUNT(*), AVG(latency_ms), MAX(latency_ms)
                            FROM llm_logs
                            WHERE COALESCE(json_extract(metadata, '$.run_id'), '') = ?
                            """,
                            (run_id,),
                        ).fetchone()
                    except sqlite3.OperationalError:
                        rows = conn.execute("SELECT latency_ms, metadata FROM llm_logs").fetchall()
                        samples = [
                            float(item[0] or 0.0)
                            for item in rows
                            if _metadata_matches_run_id(item[1], run_id)
                        ]
                        row = (
                            len(samples),
                            (sum(samples) / len(samples)) if samples else None,
                            max(samples) if samples else None,
                        )
                else:
                    row = conn.execute(
                        """
                        SELECT COUNT(*), AVG(latency_ms), MAX(latency_ms)
                        FROM llm_logs
                        """
                    ).fetchone()
                if row:
                    metrics["llm_calls"] = int(row[0] or 0)
                    metrics["llm_avg_latency_ms"] = float(row[1]) if row[1] is not None else None
                    metrics["llm_max_latency_ms"] = float(row[2]) if row[2] is not None else None
            finally:
                conn.close()
        except sqlite3.Error:
            pass

    agent_db = output_dir / "agent_logs.db"
    if agent_db.exists():
        try:
            conn = sqlite3.connect(str(agent_db))
            try:
                if run_id:
                    try:
                        row = conn.execute(
                            """
                            SELECT
                                COUNT(*),
                                SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END),
                                SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END)
                            FROM agent_executions
                            WHERE COALESCE(json_extract(metadata, '$.run_id'), '') = ?
                            """,
                            (run_id,),
                        ).fetchone()
                    except sqlite3.OperationalError:
                        rows = conn.execute("SELECT status, metadata FROM agent_executions").fetchall()
                        selected = [row[0] for row in rows if _metadata_matches_run_id(row[1], run_id)]
                        row = (
                            len(selected),
                            sum(1 for status in selected if status == "running"),
                            sum(1 for status in selected if status == "failed"),
                        )
                else:
                    row = conn.execute(
                        """
                        SELECT
                            COUNT(*),
                            SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END),
                            SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END)
                        FROM agent_executions
                        """
                    ).fetchone()
                if row:
                    metrics["agent_total"] = int(row[0] or 0)
                    metrics["agent_running"] = int(row[1] or 0)
                    metrics["agent_failed"] = int(row[2] or 0)
                if run_id:
                    try:
                        row = conn.execute(
                            """
                            SELECT
                                COUNT(*),
                                SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END),
                                SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END)
                            FROM agent_tasks
                            WHERE COALESCE(json_extract(metadata, '$.run_id'), '') = ?
                            """,
                            (run_id,),
                        ).fetchone()
                    except sqlite3.OperationalError:
                        rows = conn.execute("SELECT status, metadata FROM agent_tasks").fetchall()
                        selected = [row[0] for row in rows if _metadata_matches_run_id(row[1], run_id)]
                        row = (
                            len(selected),
                            sum(1 for status in selected if status == "running"),
                            sum(1 for status in selected if status == "failed"),
                        )
                else:
                    row = conn.execute(
                        """
                        SELECT
                            COUNT(*),
                            SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END),
                            SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END)
                        FROM agent_tasks
                        """
                    ).fetchone()
                if row:
                    metrics["task_total"] = int(row[0] or 0)
                    metrics["task_running"] = int(row[1] or 0)
                    metrics["task_failed"] = int(row[2] or 0)
            finally:
                conn.close()
        except sqlite3.Error:
            pass

    return metrics


def _format_runtime_metrics(case: Dict[str, Any]) -> str:
    metrics = case.get("runtime_metrics") or {}
    if not metrics:
        return "metrics=暂无"
    avg_latency = metrics.get("llm_avg_latency_ms")
    max_latency = metrics.get("llm_max_latency_ms")
    avg_text = f"{avg_latency:.0f}ms" if isinstance(avg_latency, (int, float)) else "N/A"
    max_text = f"{max_latency:.0f}ms" if isinstance(max_latency, (int, float)) else "N/A"
    return (
        f"llm={metrics.get('llm_calls', 0)}"
        f" avg={avg_text}"
        f" max={max_text}"
        f", agents={metrics.get('agent_total', 0)}/{metrics.get('agent_running', 0)}running"
        f", tasks={metrics.get('task_total', 0)}/{metrics.get('task_running', 0)}running"
    )


def _build_fatal_llm_error_summary(errors: List[str], limit: int = 3) -> str:
    if not errors:
        return ""
    shown = [_normalize_inline_text(item) for item in errors[:limit]]
    summary = " | ".join(shown)
    if len(errors) > limit:
        summary += f" | ... and {len(errors) - limit} more"
    return f"Fatal LLM log errors detected ({len(errors)}): {summary}"


def format_batch_progress_as_markdown(progress: Dict[str, Any]) -> str:
    summary = progress.get("summary", {})
    cases = list(progress.get("testcases", {}).values())
    running_cases = [case for case in cases if case.get("status") == "running"]
    failed_cases = [case for case in cases if case.get("status") == "failed"]
    completed_cases = [case for case in cases if case.get("status") in {"success", "failed"}]
    pending_cases = [case for case in cases if case.get("status") == "pending"]
    completed_cases.sort(key=lambda item: item.get("finished_at") or "", reverse=True)

    lines = [
        "# Batch Progress",
        "",
        f"- **Updated At**: {progress.get('updated_at', '')}",
        f"- **Parallelism**: {progress.get('parallelism', 1)}",
        f"- **Total**: {summary.get('total', 0)}",
        f"- **Completed**: {summary.get('completed', 0)}",
        f"- **Running**: {summary.get('running', 0)}",
        f"- **Pending**: {summary.get('pending', 0)}",
        f"- **Success**: {summary.get('success', 0)}",
        f"- **Failed**: {summary.get('failed', 0)}",
        "",
    ]
    if running_cases:
        lines.extend(["## Running", ""])
        for case in sorted(running_cases, key=lambda item: item["name"]):
            last_log = _read_last_nonempty_log_line(Path(case["console_log"]))
            lines.append(
                f"- **{case['name']}**: started={case.get('started_at') or 'N/A'}, "
                f"{_format_runtime_metrics(case)}, log={last_log or 'No logs yet'}"
            )
        lines.append("")
    if completed_cases:
        lines.extend(["## Recently Completed", ""])
        for case in completed_cases[:10]:
            fatal_count = len(case.get("fatal_llm_errors") or [])
            lines.append(
                f"- **{case['name']}**: {case['status']}, "
                f"vulns={case.get('vulnerabilities_count', 0)}, "
                f"duration={_format_duration(case.get('wall_time_seconds'))}, "
                f"fatal_llm={fatal_count}, "
                f"{_format_runtime_metrics(case)}"
            )
        lines.append("")
    if failed_cases:
        lines.extend(["## Failed", ""])
        for case in sorted(failed_cases, key=lambda item: item["name"]):
            fatal_errors = case.get("fatal_llm_errors") or []
            if fatal_errors:
                lines.append(
                    f"- **{case['name']}**: {_build_fatal_llm_error_summary(fatal_errors, limit=1)}"
                )
            else:
                lines.append(f"- **{case['name']}**: {case.get('error') or 'Unknown error'}")
        lines.append("")
    if pending_cases:
        lines.extend(["## Pending", ""])
        for case in sorted(pending_cases, key=lambda item: item["name"]):
            lines.append(f"- **{case['name']}**")
        lines.append("")
    return "\n".join(lines)


def write_batch_progress(output_dir: str | Path, progress: Dict[str, Any]) -> None:
    for case in progress.get("testcases", {}).values():
        case["runtime_metrics"] = _collect_runtime_metrics(case)
    _refresh_batch_progress_summary(progress)
    json_path, md_path = _batch_progress_paths(output_dir)
    json_path.write_text(json.dumps(progress, ensure_ascii=False, indent=2), encoding="utf-8")
    md_path.write_text(format_batch_progress_as_markdown(progress), encoding="utf-8")


def load_batch_progress(output_dir: str | Path) -> Dict[str, Any]:
    root = Path(output_dir)
    json_path, _ = _batch_progress_paths(root)
    if json_path.exists():
        return json.loads(json_path.read_text(encoding="utf-8"))

    results = discover_run_results(root)
    if not results:
        return {}

    now = datetime.now().isoformat()
    progress = {
        "started_at": now,
        "updated_at": now,
        "parallelism": 1,
        "summary": {},
        "testcases": {},
    }
    for result in results:
        progress["testcases"][result.testcase_name] = {
            "name": result.testcase_name,
            "engine": "",
            "status": "success" if result.success else "failed",
            "timeout": None,
            "output_dir": result.output_dir,
            "console_log": str(Path(result.output_dir) / "console.log"),
            "started_at": None,
            "finished_at": None,
            "wall_time_seconds": result.wall_time_seconds,
            "vulnerabilities_count": len(result.vulnerabilities),
            "error": result.error,
            "fatal_llm_errors": result.fatal_llm_errors,
        }
    _refresh_batch_progress_summary(progress)
    return progress


def _severity_to_text(value: Any) -> str:
    if isinstance(value, (int, float)):
        score = float(value)
        if score >= 0.9:
            return "CRITICAL"
        if score >= 0.7:
            return "HIGH"
        if score >= 0.4:
            return "MEDIUM"
        if score >= 0.2:
            return "LOW"
        return "INFO"
    return str(value or "Unknown")


def vulnerability_to_dict(vulnerability: Any) -> Dict[str, Any]:
    if isinstance(vulnerability, dict):
        data = dict(vulnerability)
    elif hasattr(vulnerability, "to_dict"):
        data = vulnerability.to_dict()
    else:
        data = dict(getattr(vulnerability, "__dict__", {}))

    data_flow = data.get("data_flow") or {}
    if hasattr(data_flow, "to_dict"):
        data_flow = data_flow.to_dict()
    if not isinstance(data_flow, dict):
        data_flow = {}

    metadata = data.get("metadata") or {}
    if not isinstance(metadata, dict):
        metadata = {}

    return {
        "name": data.get("name", "Unnamed Vulnerability"),
        "type": data.get("type", "UNKNOWN"),
        "description": data.get("description", ""),
        "function_identifier": data.get("function_identifier", metadata.get("function_identifier", "")),
        "location": data.get("location", ""),
        "severity": _severity_to_text(data.get("severity")),
        "confidence": data.get("confidence", 0),
        "data_flow_source": data_flow.get("source"),
        "data_flow_sink": data_flow.get("sink"),
        "data_flow_path": data_flow.get("path"),
        "evidence": data.get("evidence", metadata.get("evidence", [])),
        "remediation": data.get("remediation", ""),
        "code_snippet": data.get("code_snippet"),
        "metadata": metadata,
    }


def format_detection_results_as_markdown(results: Dict[str, Any]) -> str:
    vulnerabilities = [vulnerability_to_dict(item) for item in results.get("vulnerabilities", []) or []]
    lines = ["# Detection Results", ""]
    if not vulnerabilities:
        lines.append("No vulnerabilities detected.")
        return "\n".join(lines) + "\n"

    lines.extend([f"**Total Vulnerabilities Found**: {len(vulnerabilities)}", ""])
    for index, vuln in enumerate(vulnerabilities, start=1):
        lines.extend(
            [
                f"## Vulnerability {index}: {vuln['name']}",
                "",
                f"- **Type**: {vuln['type']}",
                f"- **Function**: {vuln.get('function_identifier') or 'Unknown'}",
                f"- **Location**: {vuln.get('location') or 'Unknown'}",
                f"- **Severity**: {vuln.get('severity') or 'Unknown'}",
                f"- **Confidence**: {vuln.get('confidence', 0)}",
                "",
            ]
        )
        if vuln.get("description"):
            lines.extend(["**Description**:", "", vuln["description"], ""])
        if vuln.get("data_flow_source") or vuln.get("data_flow_sink") or vuln.get("data_flow_path"):
            lines.extend(["**Data Flow**:", ""])
            if vuln.get("data_flow_source"):
                lines.append(f"- **Source**: {vuln['data_flow_source']}")
            if vuln.get("data_flow_sink"):
                lines.append(f"- **Sink**: {vuln['data_flow_sink']}")
            if vuln.get("data_flow_path"):
                lines.append(f"- **Path**: {vuln['data_flow_path']}")
            lines.append("")
        evidence = vuln.get("evidence") or []
        if evidence:
            lines.extend(["**Evidence**:", ""])
            for item in evidence:
                lines.append(f"- {item}")
            lines.append("")
        if vuln.get("remediation"):
            lines.extend(["**Remediation**:", "", vuln["remediation"], ""])
        if vuln.get("code_snippet"):
            lines.extend(["**Code Snippet**:", "", "```c", str(vuln["code_snippet"]), "```", ""])
        lines.extend(["---", ""])
    return "\n".join(lines)


def _extract_summary_value(content: str, key: str) -> str:
    pattern = rf"^- \*\*{re.escape(key)}\*\*:\s*(.+)$"
    match = re.search(pattern, content, flags=re.MULTILINE)
    return match.group(1).strip() if match else ""


def _extract_vulnerability_count(summary: str, results_markdown: str) -> int:
    count_raw = _extract_summary_value(summary, "Vulnerabilities Count")
    if count_raw:
        try:
            return int(float(count_raw))
        except ValueError:
            pass
    total_raw = _extract_summary_value(results_markdown, "Total Vulnerabilities Found")
    if total_raw:
        try:
            return int(float(total_raw))
        except ValueError:
            pass
    if "## Vulnerability " in results_markdown:
        return results_markdown.count("## Vulnerability ")
    return 0


def _extract_summary_section_items(content: str, header: str) -> List[str]:
    lines = content.splitlines()
    target_header = f"## {header}".strip()
    in_section = False
    items: List[str] = []
    for raw_line in lines:
        line = raw_line.rstrip()
        if line.strip() == target_header:
            in_section = True
            continue
        if in_section and line.startswith("## "):
            break
        if in_section and line.startswith("- "):
            items.append(line[2:].strip())
    return items


def load_result_from_dir(run_dir: str | Path) -> TestRunResult:
    run_path = Path(run_dir)
    summary_path = run_path / "run_summary.md"
    detection_path = run_path / "detection_results.md"
    if not summary_path.exists():
        raise FileNotFoundError(f"run_summary.md not found in {run_path}")
    if not detection_path.exists():
        raise FileNotFoundError(f"detection_results.md not found in {run_path}")

    summary = summary_path.read_text(encoding="utf-8")
    results_markdown = detection_path.read_text(encoding="utf-8")
    testcase_name = summary.removeprefix("# Test Run Summary:").splitlines()[0].strip()
    status = _extract_summary_value(summary, "Status").lower()
    wall_time_raw = _extract_summary_value(summary, "Wall Time Seconds") or "0"
    error = _extract_summary_value(summary, "Error") or None
    vulnerability_count = _extract_vulnerability_count(summary, results_markdown)
    fatal_llm_errors = _extract_summary_section_items(summary, "Fatal LLM Log Errors")
    return TestRunResult(
        testcase_name=testcase_name or run_path.name,
        success=status == "success",
        error=error,
        wall_time_seconds=float(wall_time_raw),
        vulnerabilities=[{} for _ in range(vulnerability_count)],
        results_markdown=results_markdown,
        output_dir=_extract_summary_value(summary, "Output Directory") or str(run_path),
        llm_log_db=_extract_summary_value(summary, "LLM Log DB"),
        agent_log_db=_extract_summary_value(summary, "Agent Log DB"),
        vuln_db=_extract_summary_value(summary, "Vulnerability DB"),
        fatal_llm_errors=fatal_llm_errors,
    )


def discover_run_results(results_dir: str | Path) -> List[TestRunResult]:
    root = Path(results_dir)
    if not root.exists():
        return []
    if (root / "run_summary.md").exists():
        return [load_result_from_dir(root)]

    results: List[TestRunResult] = []
    for summary_path in sorted(root.glob("*/run_summary.md")):
        try:
            results.append(load_result_from_dir(summary_path.parent))
        except Exception as exc:
            print(f"Warning: failed to load run directory {summary_path.parent}: {exc}")
    return results


def reset_singletons() -> None:
    """Reset singleton managers and per-process analysis state."""

    VulnerabilityManager._instance = None
    VulnerabilityManager._lock = threading.Lock()
    LLMLogManager._instance = None
    LLMLogManager._lock = threading.Lock()
    AgentLogManager._instance = None
    AgentLogManager._lock = threading.Lock()
    DeepVulnAgent.clear_execution_states()
    DeepVulnAgent.clear_analysis_task_cache()


def _sanitize_filename_component(text: str) -> str:
    normalized = re.sub(r"[^0-9A-Za-z_.-]+", "_", (text or "").strip())
    return normalized.strip("._") or "unknown"


def _write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _find_bins_payload_files(testcase: TestCase) -> List[Path]:
    bins_dir = testcase.testcase_dir / "bins"
    if not bins_dir.is_dir():
        return []
    return sorted(
        path for path in bins_dir.rglob("*")
        if path.is_file() and path.name.lower() != "readme.md"
    )


def _resolve_ida_database_path(testcase: TestCase) -> Optional[Path]:
    candidates = [path for path in _find_bins_payload_files(testcase) if path.suffix.lower() in IDA_DB_SUFFIXES]
    if len(candidates) == 1:
        return candidates[0]
    return None


def _resolve_source_authoring_dir(testcase: TestCase) -> Optional[Path]:
    for rel_path in ("authoring/source", "source"):
        candidate = testcase.testcase_dir / rel_path
        if candidate.is_dir():
            return candidate
    return None


def _copy_tree(src: Path, dst: Path, *, include_suffixes: Optional[set[str]] = None) -> int:
    copied = 0
    for path in sorted(src.rglob("*")):
        if path.is_dir():
            continue
        if include_suffixes and path.suffix.lower() not in include_suffixes:
            continue
        rel_path = path.relative_to(src)
        target = dst / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
        copied += 1
    return copied


def _write_exported_pseudocode(
    export_dir: Path,
    *,
    index: int,
    identifier: str,
    name: str,
    address: str,
    signature: str,
    pseudocode: str,
) -> str:
    safe_name = _sanitize_filename_component(name)
    safe_addr = _sanitize_filename_component(address or identifier)
    filename = f"{index:03d}_{safe_name}_{safe_addr}.c"
    file_path = export_dir / filename
    header = [
        f"/* source: ida_live_export */",
        f"/* identifier: {identifier} */",
        f"/* address: {address or 'unknown'} */",
        f"/* signature: {signature or name} */",
        "",
    ]
    file_path.write_text("\n".join(header) + (pseudocode or ""), encoding="utf-8")
    return filename


async def _prepare_pseudocode_snapshot_target(testcase: TestCase, export_dir: Path) -> Optional[PreparedTarget]:
    payload_files = [
        path for path in _find_bins_payload_files(testcase)
        if path.suffix.lower() in PSEUDOCODE_TEXT_SUFFIXES
    ]
    if not payload_files:
        return None

    bins_dir = testcase.testcase_dir / "bins"
    copied = _copy_tree(bins_dir, export_dir, include_suffixes=PSEUDOCODE_TEXT_SUFFIXES)
    manifest = {
        "mode": "prebuilt_pseudocode_snapshot",
        "input_engine": testcase.input_engine,
        "entry_functions": testcase.entry_functions,
        "copied_files": copied,
        "source_dir": str(bins_dir),
    }
    _write_json(export_dir / IDA_MANIFEST_NAME, manifest)
    return PreparedTarget(target_path=export_dir, source_root=str(export_dir), metadata=manifest)


async def _prepare_synthetic_source_target(testcase: TestCase, export_dir: Path) -> PreparedTarget:
    source_dir = _resolve_source_authoring_dir(testcase)
    if source_dir is None:
        raise FileNotFoundError(f"Missing authoring source for testcase: {testcase.testcase_dir}")

    copied = _copy_tree(source_dir, export_dir)
    manifest = {
        "mode": "synthetic_source_snapshot",
        "input_engine": testcase.input_engine,
        "entry_functions": testcase.entry_functions,
        "copied_files": copied,
        "source_dir": str(source_dir),
        "warning": "IDA 资产缺失，当前运行使用源码快照模拟伪代码输入。",
    }
    _write_json(export_dir / IDA_MANIFEST_NAME, manifest)
    return PreparedTarget(target_path=export_dir, source_root=str(export_dir), metadata=manifest)


async def _prepare_live_ida_target(testcase: TestCase, export_dir: Path) -> PreparedTarget:
    idb_path = _resolve_ida_database_path(testcase)
    if idb_path is None:
        raise FileNotFoundError(f"Missing unique IDA database under {testcase.testcase_dir / 'bins'}")

    service_manager = EngineServiceManager()
    client: Optional[IDAClient] = None
    exported_records: List[Dict[str, Any]] = []
    missing_entries: List[str] = []
    warnings: List[str] = []
    entry_queue: deque[str] = deque()
    visited: set[str] = set()

    try:
        service_info = await service_manager.ensure_service("ida", target_path=str(idb_path))
        client = IDAClient(
            host=service_info["host"],
            port=service_info["port"],
        )
        if not await client.connect():
            raise RuntimeError(f"无法连接 IDA RPC: {service_info['host']}:{service_info['port']}")

        for entry in testcase.entry_functions:
            entry_queue.append(entry)

        while entry_queue and len(exported_records) < MAX_IDA_EXPORT_FUNCTIONS:
            identifier = entry_queue.popleft()
            if identifier in visited:
                continue
            visited.add(identifier)

            info = await client.get_function_info(identifier)
            if not isinstance(info, dict) or info.get("error"):
                if identifier in testcase.entry_functions and identifier not in missing_entries:
                    missing_entries.append(identifier)
                warnings.append(f"get_function_info failed: {identifier}")
                continue

            pseudocode = str(info.get("pseudocode") or "").strip()
            if not pseudocode:
                warnings.append(f"missing pseudocode: {identifier}")
                continue

            name = str(info.get("name") or identifier).strip()
            address = str(info.get("address") or "").strip()
            signature = str(info.get("signature") or name).strip()
            filename = _write_exported_pseudocode(
                export_dir,
                index=len(exported_records) + 1,
                identifier=identifier,
                name=name,
                address=address,
                signature=signature,
                pseudocode=pseudocode,
            )

            callees = await client.get_callee(identifier)
            callee_ids: List[str] = []
            if isinstance(callees, list):
                for callee in callees:
                    callee_id = str(callee.get("callee") or "").strip()
                    if callee_id:
                        callee_ids.append(callee_id)
                        if callee_id not in visited:
                            entry_queue.append(callee_id)

            exported_records.append(
                {
                    "identifier": identifier,
                    "name": name,
                    "address": address,
                    "signature": signature,
                    "file": filename,
                    "callees": callee_ids,
                }
            )

        if entry_queue:
            raise RuntimeError(f"IDA 导出超过函数上限 {MAX_IDA_EXPORT_FUNCTIONS}，已中止本次准备")

        if not exported_records:
            raise RuntimeError("IDA 导出未产出任何伪代码函数")

        manifest = {
            "mode": "ida_live_export",
            "input_engine": testcase.input_engine,
            "idb_path": str(idb_path),
            "entry_functions": testcase.entry_functions,
            "missing_entries": missing_entries,
            "warnings": warnings,
            "exported_functions": exported_records,
        }
        _write_json(export_dir / IDA_MANIFEST_NAME, manifest)
        return PreparedTarget(target_path=export_dir, source_root=str(export_dir), metadata=manifest)
    finally:
        if client is not None:
            with contextlib.suppress(Exception):
                await client.disconnect()
        await service_manager.shutdown_all()


async def _prepare_analysis_target(testcase: TestCase, output_dir: Path) -> PreparedTarget:
    export_dir = output_dir / IDA_PSEUDOCODE_DIRNAME
    if export_dir.exists():
        shutil.rmtree(export_dir)
    export_dir.mkdir(parents=True, exist_ok=True)

    if testcase.input_engine == "ida":
        snapshot_target = await _prepare_pseudocode_snapshot_target(testcase, export_dir)
        if snapshot_target is not None:
            return snapshot_target

        idb_path = _resolve_ida_database_path(testcase)
        if idb_path is not None:
            return await _prepare_live_ida_target(testcase, export_dir)

        return await _prepare_synthetic_source_target(testcase, export_dir)

    if testcase.analysis_engine == "source":
        return await _prepare_synthetic_source_target(testcase, export_dir)

    raise ValueError(
        f"Unsupported testcase combination: engine={testcase.analysis_engine}, input_engine={testcase.input_engine}"
    )


def _check_llm_connectivity() -> None:
    base_url = (os.environ.get("OPENAI_BASE_URL") or "").strip()
    if not base_url:
        raise RuntimeError("未配置 OPENAI_BASE_URL")

    api_key = (os.environ.get("OPENAI_API_KEY") or "").strip()
    models_url = f"{base_url.rstrip('/')}/models"
    headers = {}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    request = Request(models_url, headers=headers, method="GET")
    try:
        with urlopen(request, timeout=5) as response:
            status = getattr(response, "status", 200)
            if status >= 400:
                raise RuntimeError(f"LLM API 健康检查失败: HTTP {status}")
    except HTTPError as exc:
        raise RuntimeError(f"LLM API 健康检查失败: HTTP {exc.code}") from exc
    except URLError as exc:
        reason = getattr(exc, "reason", exc)
        raise RuntimeError(f"LLM API 不可达: {reason}") from exc
    except TimeoutError as exc:
        raise RuntimeError("LLM API 不可达: 连接超时") from exc


def _is_fatal_tool_error(error_text: str) -> bool:
    lowered = (error_text or "").lower()
    return any(all(token in lowered for token in pattern) for pattern in FATAL_TOOL_ERROR_PATTERNS)


def _collect_fatal_llm_errors(llm_log_db: Path) -> List[str]:
    if not llm_log_db.exists():
        return []

    try:
        storage = SQLiteLogStorage(llm_log_db)
        failed_tool_calls = storage.query_entries(
            call_type="tool_call",
            success=False,
            limit=10000,
        )
    except Exception:
        return []

    fatal_errors: List[str] = []
    seen: set[str] = set()
    for entry in reversed(failed_tool_calls):
        error_text = str(entry.error or "").strip()
        if not error_text or not _is_fatal_tool_error(error_text):
            continue
        if error_text in seen:
            continue
        seen.add(error_text)
        fatal_errors.append(error_text)
    return fatal_errors


def _db_paths_for_run(output_dir: Path) -> Dict[str, Path]:
    return {
        "llm": output_dir / "llm_logs.db",
        "agent": output_dir / "agent_logs.db",
        "vuln": output_dir / "vulnerabilities.db",
    }


def _shared_runtime_db_paths() -> Dict[str, Path]:
    """Return the shared live runtime databases used by eval and Web."""

    db_paths = activate_db_profile(PROFILE_PRODUCTION, clear_path_overrides=True)
    return {
        "llm": db_paths.llm_log_db,
        "agent": db_paths.agent_log_db,
        "vuln": db_paths.vuln_db,
    }


def _new_run_id(testcase_name: str) -> str:
    safe_name = re.sub(r"[^a-zA-Z0-9_]+", "_", testcase_name).strip("_") or "testcase"
    return f"eval_{safe_name}_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}_{uuid.uuid4().hex[:8]}"


def _build_run_env(run_id: str, run_label: str, runtime_db_paths: Dict[str, Path]) -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    env[ENV_KEY] = PROFILE_PRODUCTION
    env[ENV_RUN_ID] = run_id
    env[ENV_RUN_LABEL] = run_label
    env[ENV_LLM_LOG_DB] = str(runtime_db_paths["llm"])
    env[ENV_AGENT_LOG_DB] = str(runtime_db_paths["agent"])
    env[ENV_VULN_DB] = str(runtime_db_paths["vuln"])
    return env


def _metadata_matches_run_id(raw_metadata: Any, run_id: str) -> bool:
    if not raw_metadata:
        return False
    if isinstance(raw_metadata, dict):
        return raw_metadata.get("run_id") == run_id
    try:
        metadata = json.loads(str(raw_metadata))
    except (TypeError, ValueError, json.JSONDecodeError):
        return False
    return metadata.get("run_id") == run_id


def _delete_rows_not_in_run(conn: sqlite3.Connection, table: str, run_id: str) -> None:
    try:
        conn.execute(
            f"DELETE FROM {table} WHERE COALESCE(json_extract(metadata, '$.run_id'), '') != ?",
            (run_id,),
        )
        return
    except sqlite3.OperationalError:
        pass

    rows = conn.execute(f"SELECT rowid, metadata FROM {table}").fetchall()
    stale_ids = [(row[0],) for row in rows if not _metadata_matches_run_id(row[1], run_id)]
    if stale_ids:
        conn.executemany(f"DELETE FROM {table} WHERE rowid = ?", stale_ids)


def _copy_database_snapshot(source: Path, destination: Path) -> None:
    if not source.exists():
        return
    if source.resolve() == destination.resolve():
        return

    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        destination.unlink()

    src_conn = sqlite3.connect(f"file:{source}?mode=ro", uri=True)
    dst_conn = sqlite3.connect(str(destination))
    try:
        src_conn.backup(dst_conn)
    finally:
        dst_conn.close()
        src_conn.close()


def _archive_run_databases(shared_db_paths: Dict[str, Path], run_db_paths: Dict[str, Path], run_id: str) -> None:
    table_map = {
        "llm": ("llm_logs",),
        "agent": ("agent_executions", "agent_tasks"),
        "vuln": ("vulnerabilities",),
    }
    for kind, tables in table_map.items():
        source = shared_db_paths[kind]
        target = run_db_paths[kind]
        if not source.exists():
            continue
        _copy_database_snapshot(source, target)
        conn = sqlite3.connect(str(target))
        try:
            for table in tables:
                _delete_rows_not_in_run(conn, table, run_id)
            if kind == "vuln":
                conn.execute("DELETE FROM scan_sessions")
            conn.commit()
        finally:
            conn.close()


def _mark_incomplete_logs_failed(shared_db_paths: Dict[str, Path], run_id: str, error_message: str) -> None:
    now = datetime.now().isoformat()
    llm_log_db = shared_db_paths["llm"]
    if llm_log_db.exists():
        conn = sqlite3.connect(str(llm_log_db))
        try:
            try:
                conn.execute(
                    """
                    UPDATE llm_logs
                    SET status = 'failed',
                        success = 0,
                        error = COALESCE(NULLIF(error, ''), ?),
                        latency_ms = CASE WHEN latency_ms IS NULL OR latency_ms = 0 THEN 1 ELSE latency_ms END
                    WHERE status IN ('pending', 'running')
                      AND COALESCE(json_extract(metadata, '$.run_id'), '') = ?
                    """,
                    (error_message, run_id),
                )
            except sqlite3.OperationalError:
                rows = conn.execute(
                    "SELECT id, metadata FROM llm_logs WHERE status IN ('pending', 'running')"
                ).fetchall()
                matching_ids = [
                    (error_message, row[0])
                    for row in rows
                    if _metadata_matches_run_id(row[1], run_id)
                ]
                if matching_ids:
                    conn.executemany(
                        """
                        UPDATE llm_logs
                        SET status = 'failed',
                            success = 0,
                            error = COALESCE(NULLIF(error, ''), ?),
                            latency_ms = CASE WHEN latency_ms IS NULL OR latency_ms = 0 THEN 1 ELSE latency_ms END
                        WHERE id = ?
                        """,
                        matching_ids,
                    )
            conn.commit()
        finally:
            conn.close()

    agent_log_db = shared_db_paths["agent"]
    if agent_log_db.exists():
        conn = sqlite3.connect(str(agent_log_db))
        try:
            for table in ("agent_executions", "agent_tasks"):
                try:
                    conn.execute(
                        f"""
                        UPDATE {table}
                        SET status = 'failed',
                            end_time = COALESCE(end_time, ?),
                            error_message = COALESCE(NULLIF(error_message, ''), ?)
                        WHERE status IN ('pending', 'running')
                          AND COALESCE(json_extract(metadata, '$.run_id'), '') = ?
                        """,
                        (now, error_message, run_id),
                    )
                except sqlite3.OperationalError:
                    rows = conn.execute(
                        f"SELECT id, metadata FROM {table} WHERE status IN ('pending', 'running')"
                    ).fetchall()
                    matching_ids = [
                        (now, error_message, row[0])
                        for row in rows
                        if _metadata_matches_run_id(row[1], run_id)
                    ]
                    if matching_ids:
                        conn.executemany(
                            f"""
                            UPDATE {table}
                            SET status = 'failed',
                                end_time = COALESCE(end_time, ?),
                                error_message = COALESCE(NULLIF(error_message, ''), ?)
                            WHERE id = ?
                            """,
                            matching_ids,
                        )
            conn.commit()
        finally:
            conn.close()


def _load_vulns_from_db(vuln_db: Path) -> List[Dict[str, Any]]:
    if not vuln_db.exists():
        return []
    try:
        storage = VulnerabilityStorage(vuln_db)
        return [record.to_dict() for record in storage.query_vulnerabilities(limit=1000, order_desc=False)]
    except Exception:
        return []


async def _capture_subprocess_output(stream: asyncio.StreamReader | None, log_path: Path) -> None:
    if stream is None:
        return
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as handle:
        while True:
            line = await stream.readline()
            if not line:
                break
            handle.write(line.decode("utf-8", errors="replace"))
            handle.flush()


async def _run_ivagent_cli(
    testcase: TestCase,
    prepared_target: PreparedTarget,
    output_dir: Path,
    result_json: Path,
    console_log: Path,
    run_id: str,
    timeout_seconds: int,
    runtime_db_paths: Dict[str, Path],
) -> tuple[int, float]:
    command = [
        sys.executable,
        "ivagent_cli.py",
        "--skill",
        str(testcase.shared_skill_path),
        "--engine",
        testcase.analysis_engine,
        "--target",
        str(prepared_target.target_path),
        "--task-file",
        str(testcase.task_path),
        "--db-profile",
        PROFILE_PRODUCTION,
        "--json-output",
        str(result_json),
        "--session-root-dir",
        str(output_dir / ".ivagent" / "sessions"),
    ]
    if prepared_target.source_root:
        command.extend(["--source-root", prepared_target.source_root])

    process = await asyncio.create_subprocess_exec(
        *command,
        cwd=str(REPO_ROOT),
        env=_build_run_env(run_id, testcase.name, runtime_db_paths),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    capture_task = asyncio.create_task(_capture_subprocess_output(process.stdout, console_log))
    started = time.perf_counter()
    try:
        return_code = await asyncio.wait_for(process.wait(), timeout=timeout_seconds)
    except asyncio.TimeoutError:
        process.kill()
        await process.wait()
        await capture_task
        raise
    await capture_task
    return return_code, time.perf_counter() - started


def _result_from_payload(
    testcase: TestCase,
    output_dir: Path,
    payload: Dict[str, Any],
    wall_time_seconds: float,
) -> TestRunResult:
    db_paths = _db_paths_for_run(output_dir)
    vulnerabilities = [vulnerability_to_dict(item) for item in _load_vulns_from_db(db_paths["vuln"])]
    summary = str(payload.get("summary") or "").strip()
    success = bool(payload.get("success")) or bool(vulnerabilities)
    error = None if success and payload.get("success") else summary or None
    results_markdown = format_detection_results_as_markdown(
        {
            "testcase_name": testcase.name,
            "summary": summary,
            "vulnerabilities": vulnerabilities,
        }
    )
    return TestRunResult(
        testcase_name=testcase.name,
        success=success,
        error=error,
        wall_time_seconds=wall_time_seconds,
        vulnerabilities=vulnerabilities,
        results_markdown=results_markdown,
        output_dir=str(output_dir),
        llm_log_db=str(db_paths["llm"]),
        agent_log_db=str(db_paths["agent"]),
        vuln_db=str(db_paths["vuln"]),
        fatal_llm_errors=[],
    )


def _apply_fatal_llm_gate(result: TestRunResult) -> TestRunResult:
    result.fatal_llm_errors = _collect_fatal_llm_errors(Path(result.llm_log_db))
    if not result.fatal_llm_errors:
        return result

    result.success = False
    fatal_summary = _build_fatal_llm_error_summary(result.fatal_llm_errors)
    if result.error:
        if fatal_summary not in result.error:
            result.error = f"{result.error}; {fatal_summary}"
    else:
        result.error = fatal_summary
    return result


async def run_testcase(
    testcase: TestCase,
    output_base_dir: Optional[str] = None,
    run_id: Optional[str] = None,
    timeout_override: Optional[int] = None,
) -> TestRunResult:
    """Run one testcase by invoking the public ivagent_cli.py entrypoint."""

    if output_base_dir:
        output_dir = Path(output_base_dir) / testcase.name
        output_dir.mkdir(parents=True, exist_ok=True)
    else:
        output_dir = Path(tempfile.mkdtemp(prefix=f"ivagent_eval_{testcase.name}_"))

    run_id = run_id or _new_run_id(testcase.name)
    timeout_seconds = timeout_override or testcase.timeout
    db_paths = _db_paths_for_run(output_dir)
    shared_db_paths = _shared_runtime_db_paths()
    console_log = output_dir / "console.log"
    result_json = output_dir / "run_result.json"
    if result_json.exists():
        result_json.unlink()

    _check_llm_connectivity()

    try:
        prepared_target = await _prepare_analysis_target(testcase, output_dir)
        _write_json(output_dir / PREPARED_TARGET_METADATA, prepared_target.metadata)
        return_code, wall_time = await _run_ivagent_cli(
            testcase,
            prepared_target,
            output_dir,
            result_json,
            console_log,
            run_id,
            timeout_seconds,
            shared_db_paths,
        )
        _archive_run_databases(shared_db_paths, db_paths, run_id)
        if result_json.exists():
            payload = json.loads(result_json.read_text(encoding="utf-8"))
            run_result = _result_from_payload(testcase, output_dir, payload, wall_time)
        else:
            error_message = f"ivagent_cli.py exited with code {return_code}"
            last_log = _read_last_nonempty_log_line(console_log)
            if last_log:
                error_message = f"{error_message}: {last_log}"
            payload = {"success": False, "summary": error_message}
            run_result = _result_from_payload(testcase, output_dir, payload, wall_time)

        if return_code != 0 and not run_result.error:
            run_result.error = f"ivagent_cli.py exited with code {return_code}"
            run_result.success = False

        run_result = _apply_fatal_llm_gate(run_result)
        write_run_artifacts(run_result)
        return run_result
    except asyncio.TimeoutError:
        error_message = f"Timeout after {timeout_seconds}s"
        _mark_incomplete_logs_failed(shared_db_paths, run_id, error_message)
        _archive_run_databases(shared_db_paths, db_paths, run_id)
        run_result = _result_from_payload(
            testcase,
            output_dir,
            {"success": False, "summary": error_message},
            float(timeout_seconds),
        )
        run_result.error = error_message
        run_result.success = bool(run_result.vulnerabilities)
        if not run_result.vulnerabilities:
            run_result.results_markdown = "# Detection Results\n\nTimeout occurred.\n"
        run_result = _apply_fatal_llm_gate(run_result)
        write_run_artifacts(run_result)
        return run_result
    except Exception as exc:
        error_message = str(exc)
        _mark_incomplete_logs_failed(shared_db_paths, run_id, error_message)
        _archive_run_databases(shared_db_paths, db_paths, run_id)
        run_result = _result_from_payload(
            testcase,
            output_dir,
            {"success": False, "summary": error_message},
            0.0,
        )
        run_result.error = error_message
        run_result.success = bool(run_result.vulnerabilities)
        if not run_result.vulnerabilities:
            run_result.results_markdown = f"# Detection Results\n\nError: {error_message}\n"
        run_result = _apply_fatal_llm_gate(run_result)
        write_run_artifacts(run_result)
        return run_result
    finally:
        reset_singletons()


async def run_testcases(
    testcases: List[TestCase],
    output_base_dir: Optional[str] = None,
    engine_filter: Optional[str] = None,
    parallelism: int = 1,
    timeout_override: Optional[int] = None,
    testcases_dir: str | Path = "tests/testcases",
) -> List[TestRunResult]:
    """Run testcase list with optional parallelism."""

    del testcases_dir
    selected = testcases
    if engine_filter:
        selected = [item for item in testcases if item.analysis_engine == engine_filter]
    if not selected:
        return []

    if output_base_dir:
        base_dir = Path(output_base_dir)
        base_dir.mkdir(parents=True, exist_ok=True)
    else:
        base_dir = Path(tempfile.mkdtemp(prefix="ivagent_eval_batch_"))
        print(f"Batch output directory: {base_dir}")

    total = len(selected)
    limit = max(1, parallelism)
    progress = _init_batch_progress(selected, base_dir, limit)
    write_batch_progress(base_dir, progress)

    results_by_name: Dict[str, TestRunResult] = {}
    state_lock = asyncio.Lock()
    semaphore = asyncio.Semaphore(limit)
    started_count = 0
    completed_count = 0

    async def _run_one(testcase: TestCase) -> None:
        nonlocal started_count, completed_count
        async with semaphore:
            run_id = _new_run_id(testcase.name)
            async with state_lock:
                started_count += 1
                case_state = progress["testcases"][testcase.name]
                case_state["status"] = "running"
                case_state["run_id"] = run_id
                case_state["started_at"] = datetime.now().isoformat()
                case_state["error"] = None
                case_state["wall_time_seconds"] = None
                case_state["vulnerabilities_count"] = 0
                case_state["fatal_llm_errors"] = []
                write_batch_progress(base_dir, progress)
                print(f"[start {started_count}/{total}] {testcase.name} ({testcase.analysis_engine})")

            result = await run_testcase(
                testcase,
                output_base_dir=str(base_dir),
                run_id=run_id,
                timeout_override=timeout_override,
            )

            async with state_lock:
                completed_count += 1
                results_by_name[testcase.name] = result
                case_state = progress["testcases"][testcase.name]
                case_state["status"] = "success" if result.success else "failed"
                case_state["finished_at"] = datetime.now().isoformat()
                case_state["wall_time_seconds"] = result.wall_time_seconds
                case_state["vulnerabilities_count"] = len(result.vulnerabilities)
                case_state["error"] = result.error
                case_state["fatal_llm_errors"] = result.fatal_llm_errors
                write_batch_progress(base_dir, progress)
                if result.success:
                    print(
                        f"[done {completed_count}/{total}] {testcase.name}: "
                        f"success, vulns={len(result.vulnerabilities)}, "
                        f"duration={result.wall_time_seconds:.2f}s"
                    )
                else:
                    print(f"[done {completed_count}/{total}] {testcase.name}: failed, error={result.error}")

    await asyncio.gather(*[_run_one(testcase) for testcase in selected])
    ordered_results = [results_by_name[testcase.name] for testcase in selected if testcase.name in results_by_name]
    return ordered_results
