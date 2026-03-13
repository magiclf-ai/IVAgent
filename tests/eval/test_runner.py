#!/usr/bin/env python3
"""Test runner for the LLM-driven evaluation framework."""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.error import URLError, HTTPError
from urllib.request import Request, urlopen

from ivagent.agents.deep_vuln_agent import DeepVulnAgent
from ivagent.core.agent_logger import AgentLogManager, AgentLogStorage
from ivagent.core.llm_logger import LLMLogManager, SQLiteLogStorage
from ivagent.core.vuln_storage import VulnerabilityManager
from ivagent.core.db_profiles import (
    DBPaths,
    ENV_AGENT_LOG_DB,
    ENV_KEY,
    ENV_LLM_LOG_DB,
    ENV_VULN_DB,
    PROFILE_EVAL,
)
from ivagent.models.skill_parser import SkillParser
from ivagent.scanner import IVAgentScanner, ScanConfig

from tests.eval.testcase_format import TestCase

BATCH_PROGRESS_JSON = "PROGRESS.json"
BATCH_PROGRESS_MD = "PROGRESS.md"


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


def format_run_summary_as_markdown(result: TestRunResult) -> str:
    """Render testcase execution metadata as markdown."""

    lines = [
        f"# Test Run Summary: {result.testcase_name}",
        "",
        f"- **Status**: {'success' if result.success else 'failed'}",
        f"- **Wall Time Seconds**: {result.wall_time_seconds:.6f}",
        f"- **Vulnerabilities Count**: {len(result.vulnerabilities)}",
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
    return "\n".join(lines)


def _stringify_llm_payload(value: Any) -> str:
    """Convert logged LLM payloads into readable markdown text."""

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
    """Normalize logged message content into plain text."""

    if isinstance(message, str):
        return message
    if isinstance(message, list):
        parts: List[str] = []
        for item in message:
            if isinstance(item, dict):
                text = item.get("text")
                if text:
                    parts.append(str(text))
                else:
                    parts.append(json.dumps(item, ensure_ascii=False, indent=2))
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
        lines.append("No LLM interactions recorded.")
        lines.append("")
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
        lines.append("No agent executions recorded.")
        lines.append("")
        return "\n".join(lines)

    for root in roots:
        tree = storage.get_execution_tree(root.agent_id)
        if tree:
            lines.append(_format_agent_tree_node(tree))
            lines.append("")

    lines.extend(["## Execution Details", ""])
    executions = list(reversed(storage.query_executions(limit=1000)))
    for index, execution in enumerate(executions, start=1):
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
    (output_dir / "detection_results.md").write_text(
        result.results_markdown,
        encoding="utf-8",
    )
    (output_dir / "run_summary.md").write_text(
        format_run_summary_as_markdown(result),
        encoding="utf-8",
    )
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
        status = "success" if result.success else "failed"
        lines.extend(
            [
                f"## {result.testcase_name}",
                "",
                f"- **Status**: {status}",
                f"- **Wall Time Seconds**: {result.wall_time_seconds:.6f}",
                f"- **Vulnerabilities Count**: {len(result.vulnerabilities)}",
                f"- **Run Directory**: {result.output_dir}",
            ]
        )
        if result.error:
            lines.append(f"- **Error**: {result.error}")
        lines.append("")
    (base_dir / "RUNS.md").write_text("\n".join(lines), encoding="utf-8")
    print(f"Run index saved to {base_dir / 'RUNS.md'}")


def _batch_progress_paths(output_dir: str | Path) -> tuple[Path, Path]:
    root = Path(output_dir)
    return root / BATCH_PROGRESS_JSON, root / BATCH_PROGRESS_MD


def _init_batch_progress(
    testcases: List[TestCase],
    output_dir: str | Path,
    parallelism: int,
) -> Dict[str, Any]:
    """Create the initial batch progress document."""

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
                "engine": testcase.engine,
                "status": "pending",
                "entry_functions": testcase.entry_functions,
                "timeout": testcase.timeout,
                "output_dir": str(root / testcase.name),
                "console_log": str(root / testcase.name / "console.log"),
                "started_at": None,
                "finished_at": None,
                "wall_time_seconds": None,
                "vulnerabilities_count": 0,
                "error": None,
            }
            for testcase in testcases
        },
    }


def _refresh_batch_progress_summary(progress: Dict[str, Any]) -> None:
    """Recompute aggregate counters from testcase status."""

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
    """Format duration seconds into concise human-readable text."""

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


def _read_last_nonempty_log_line(log_path: Path) -> str:
    """Return the last non-empty line from one console log file."""

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
    """Collect lightweight runtime metrics from testcase sqlite artifacts."""

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

    llm_db = Path(case.get("output_dir", "")) / "llm_logs.db"
    if llm_db.exists():
        try:
            conn = sqlite3.connect(str(llm_db))
            try:
                row = conn.execute(
                    """
                    SELECT
                        COUNT(*) AS total_calls,
                        AVG(latency_ms) AS avg_latency_ms,
                        MAX(latency_ms) AS max_latency_ms
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

    agent_db = Path(case.get("output_dir", "")) / "agent_logs.db"
    if agent_db.exists():
        try:
            conn = sqlite3.connect(str(agent_db))
            try:
                row = conn.execute(
                    """
                    SELECT
                        COUNT(*) AS total_agents,
                        SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END) AS running_agents,
                        SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failed_agents
                    FROM agent_executions
                    """
                ).fetchone()
                if row:
                    metrics["agent_total"] = int(row[0] or 0)
                    metrics["agent_running"] = int(row[1] or 0)
                    metrics["agent_failed"] = int(row[2] or 0)

                row = conn.execute(
                    """
                    SELECT
                        COUNT(*) AS total_tasks,
                        SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END) AS running_tasks,
                        SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failed_tasks
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
    """Format per-testcase runtime metrics into one compact string."""

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


def format_batch_progress_as_markdown(progress: Dict[str, Any]) -> str:
    """Render batch progress into user-friendly markdown."""

    summary = progress.get("summary", {})
    cases = list(progress.get("testcases", {}).values())
    running_cases = [case for case in cases if case.get("status") == "running"]
    failed_cases = [case for case in cases if case.get("status") == "failed"]
    completed_cases = [
        case for case in cases if case.get("status") in {"success", "failed"}
    ]
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
            started_at = case.get("started_at") or "N/A"
            lines.append(
                f"- **{case['name']}**: started={started_at}, {_format_runtime_metrics(case)}, log={last_log or 'No logs yet'}"
            )
        lines.append("")

    if completed_cases:
        lines.extend(["## Recently Completed", ""])
        for case in completed_cases[:10]:
            lines.append(
                f"- **{case['name']}**: {case['status']}, "
                f"vulns={case.get('vulnerabilities_count', 0)}, "
                f"duration={_format_duration(case.get('wall_time_seconds'))}, "
                f"{_format_runtime_metrics(case)}"
            )
        lines.append("")

    if failed_cases:
        lines.extend(["## Failed", ""])
        for case in sorted(failed_cases, key=lambda item: item["name"]):
            lines.append(
                f"- **{case['name']}**: {case.get('error') or 'Unknown error'}"
            )
        lines.append("")

    if pending_cases:
        lines.extend(["## Pending", ""])
        for case in sorted(pending_cases, key=lambda item: item["name"]):
            lines.append(f"- **{case['name']}**")
        lines.append("")

    return "\n".join(lines)


def write_batch_progress(output_dir: str | Path, progress: Dict[str, Any]) -> None:
    """Persist batch progress as JSON and Markdown."""

    for case in progress.get("testcases", {}).values():
        case["runtime_metrics"] = _collect_runtime_metrics(case)
    _refresh_batch_progress_summary(progress)
    json_path, md_path = _batch_progress_paths(output_dir)
    json_path.write_text(
        json.dumps(progress, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    md_path.write_text(
        format_batch_progress_as_markdown(progress),
        encoding="utf-8",
    )


def load_batch_progress(output_dir: str | Path) -> Dict[str, Any]:
    """Load one batch progress document, with a fallback from finished runs."""

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
            "entry_functions": [],
            "timeout": None,
            "output_dir": result.output_dir,
            "console_log": str(Path(result.output_dir) / "console.log"),
            "started_at": None,
            "finished_at": None,
            "wall_time_seconds": result.wall_time_seconds,
            "vulnerabilities_count": len(result.vulnerabilities),
            "error": result.error,
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
    """Serialize IVAgent vulnerability objects into plain dictionaries."""

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
    """Render detection results as markdown for LLM consumption."""

    vulnerabilities = [
        vulnerability_to_dict(item)
        for item in results.get("vulnerabilities", []) or []
    ]

    lines = ["# Detection Results", ""]
    if not vulnerabilities:
        lines.append("No vulnerabilities detected.")
        return "\n".join(lines) + "\n"

    lines.extend(
        [
            f"**Total Vulnerabilities Found**: {len(vulnerabilities)}",
            "",
        ]
    )

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

        call_path = vuln.get("metadata", {}).get("call_path")
        if call_path:
            lines.extend(["**Call Path**:", "", call_path, ""])

        lines.extend(["---", ""])

    return "\n".join(lines)


def _extract_summary_value(content: str, key: str) -> str:
    import re

    pattern = rf"^- \*\*{re.escape(key)}\*\*:\s*(.+)$"
    match = re.search(pattern, content, flags=re.MULTILINE)
    return match.group(1).strip() if match else ""


def _extract_vulnerability_count(summary: str, results_markdown: str) -> int:
    """Recover vulnerability count from persisted markdown artifacts."""

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


def load_result_from_dir(run_dir: str | Path) -> TestRunResult:
    """Load a testcase result from markdown artifacts."""

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

    return TestRunResult(
        testcase_name=testcase_name or run_path.name,
        success=status == "success",
        error=error,
        wall_time_seconds=float(wall_time_raw),
        # 重新加载历史结果时只需要保留数量，避免批量汇总全部显示 0。
        vulnerabilities=[{} for _ in range(vulnerability_count)],
        results_markdown=results_markdown,
        output_dir=_extract_summary_value(summary, "Output Directory") or str(run_path),
        llm_log_db=_extract_summary_value(summary, "LLM Log DB"),
        agent_log_db=_extract_summary_value(summary, "Agent Log DB"),
        vuln_db=_extract_summary_value(summary, "Vulnerability DB"),
    )


def discover_run_results(results_dir: str | Path) -> List[TestRunResult]:
    """Discover testcase run artifacts under one results directory."""

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


def _create_run_db_paths(output_dir: Path) -> DBPaths:
    """Create testcase-local sqlite paths under one run directory."""

    return DBPaths(
        llm_log_db=output_dir / "llm_logs.db",
        agent_log_db=output_dir / "agent_logs.db",
        vuln_db=output_dir / "vulnerabilities.db",
    )


def _apply_run_db_env(db_paths: DBPaths) -> Dict[str, Optional[str]]:
    """Temporarily pin all default DB lookups to one testcase directory."""

    values = {
        ENV_KEY: PROFILE_EVAL,
        ENV_LLM_LOG_DB: str(db_paths.llm_log_db),
        ENV_AGENT_LOG_DB: str(db_paths.agent_log_db),
        ENV_VULN_DB: str(db_paths.vuln_db),
    }
    previous = {key: os.environ.get(key) for key in values}
    for key, value in values.items():
        os.environ[key] = value
    return previous


def _restore_run_db_env(previous: Dict[str, Optional[str]]) -> None:
    """Restore DB environment variables after one testcase finishes."""

    for key, value in previous.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value


def _resolve_target_path(testcase: TestCase) -> Path:
    source_dir = testcase.testcase_dir / "source"
    bins_dir = testcase.testcase_dir / "bins"
    if source_dir.exists():
        return source_dir
    if bins_dir.exists():
        return bins_dir
    raise FileNotFoundError(f"No source/ or bins/ directory found in {testcase.testcase_dir}")


def _check_llm_connectivity() -> None:
    """在运行前快速检查 LLM API 是否可达，避免每个用例都耗尽超时。"""
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


def _mark_incomplete_logs_failed(llm_log_db: Path, agent_log_db: Path, error_message: str) -> None:
    """将超时或异常后遗留的 running 日志收敛为 failed，便于排障。"""
    now = datetime.now().isoformat()

    if llm_log_db.exists():
        conn = sqlite3.connect(str(llm_log_db))
        try:
            conn.execute(
                """
                UPDATE llm_logs
                SET status = 'failed',
                    success = 0,
                    error = COALESCE(NULLIF(error, ''), ?),
                    latency_ms = CASE WHEN latency_ms IS NULL OR latency_ms = 0 THEN 1 ELSE latency_ms END
                WHERE status IN ('pending', 'running')
                """,
                (error_message,),
            )
            conn.commit()
        finally:
            conn.close()

    if agent_log_db.exists():
        conn = sqlite3.connect(str(agent_log_db))
        try:
            conn.execute(
                """
                UPDATE agent_executions
                SET status = 'failed',
                    end_time = COALESCE(end_time, ?),
                    error_message = COALESCE(NULLIF(error_message, ''), ?)
                WHERE status IN ('pending', 'running')
                """,
                (now, error_message),
            )
            conn.execute(
                """
                UPDATE agent_tasks
                SET status = 'failed',
                    end_time = COALESCE(end_time, ?),
                    error_message = COALESCE(NULLIF(error_message, ''), ?)
                WHERE status IN ('pending', 'running')
                """,
                (now, error_message),
            )
            conn.commit()
        finally:
            conn.close()


def _create_scan_config(testcase: TestCase, target_path: Path) -> ScanConfig:
    source_root = str(target_path) if testcase.engine == "source" else None
    return ScanConfig(
        engine_type=testcase.engine,
        target_path=str(target_path),
        source_root=source_root,
        llm_api_key=os.environ.get("OPENAI_API_KEY", ""),
        llm_base_url=os.environ.get("OPENAI_BASE_URL", ""),
        llm_model=os.environ.get("OPENAI_MODEL", "gpt-4.1"),
        verbose=False,
    )


def _recover_vulns_from_db(vuln_db: Path) -> List[Dict[str, Any]]:
    """从 vuln DB 回收已增量保存的漏洞（超时抢救用）。"""
    if not vuln_db.exists():
        return []
    try:
        conn = sqlite3.connect(str(vuln_db))
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute("SELECT * FROM vulnerabilities").fetchall()
            vulns = []
            for row in rows:
                evidence = row["evidence"] or "[]"
                try:
                    evidence = json.loads(evidence)
                except (json.JSONDecodeError, TypeError):
                    evidence = [evidence] if evidence else []
                vulns.append({
                    "name": row["name"],
                    "type": row["type"],
                    "description": row["description"],
                    "function_identifier": row["function_identifier"],
                    "location": row["location"],
                    "severity": row["severity"],
                    "confidence": row["confidence"],
                    "data_flow_source": row["data_flow_source"],
                    "data_flow_sink": row["data_flow_sink"],
                    "data_flow_path": row["data_flow_path"],
                    "evidence": evidence,
                    "remediation": row["remediation"],
                    "code_snippet": row["code_snippet"],
                    "metadata": {},
                })
            return vulns
        finally:
            conn.close()
    except Exception:
        return []


async def run_testcase(
    testcase: TestCase,
    output_base_dir: Optional[str] = None,
) -> TestRunResult:
    """Run one testcase with isolated sqlite outputs."""

    if output_base_dir:
        output_dir = Path(output_base_dir) / testcase.name
        output_dir.mkdir(parents=True, exist_ok=True)
    else:
        output_dir = Path(tempfile.mkdtemp(prefix=f"ivagent_eval_{testcase.name}_"))

    db_paths = _create_run_db_paths(output_dir)
    vuln_db = db_paths.vuln_db
    llm_log_db = db_paths.llm_log_db
    agent_log_db = db_paths.agent_log_db
    previous_db_env = _apply_run_db_env(db_paths)
    start_time = time.perf_counter()
    try:
        reset_singletons()
        VulnerabilityManager(db_path=vuln_db)
        LLMLogManager(storage_path=llm_log_db)
        AgentLogManager(db_path=agent_log_db)

        target_path = _resolve_target_path(testcase)
        skill = SkillParser().resolve_skill(testcase.skill, skills_root="vuln_skills")
        config = _create_scan_config(testcase, target_path)
        scanner = IVAgentScanner(config)

        _check_llm_connectivity()
        combined_vulnerabilities: List[Dict[str, Any]] = []
        last_summary = ""
        for function_identifier in testcase.entry_functions:
            # 计算 deadline 供内部时间预算管理
            scan_deadline = time.monotonic() + testcase.timeout
            result = await asyncio.wait_for(
                scanner.scan_function(function_identifier, skill=skill, deadline=scan_deadline),
                timeout=testcase.timeout,
            )
            if result.get("error"):
                raise RuntimeError(str(result["error"]))

            combined_vulnerabilities.extend(
                vulnerability_to_dict(item)
                for item in result.get("vulnerabilities", [])
            )
            if result.get("summary"):
                last_summary = str(result["summary"])

        wall_time = time.perf_counter() - start_time
        result_payload = {
            "testcase_name": testcase.name,
            "entry_functions": testcase.entry_functions,
            "vulnerabilities": combined_vulnerabilities,
            "summary": last_summary,
        }
        results_markdown = format_detection_results_as_markdown(result_payload)
        run_result = TestRunResult(
            testcase_name=testcase.name,
            success=True,
            error=None,
            wall_time_seconds=wall_time,
            vulnerabilities=combined_vulnerabilities,
            results_markdown=results_markdown,
            output_dir=str(output_dir),
            llm_log_db=str(llm_log_db),
            agent_log_db=str(agent_log_db),
            vuln_db=str(vuln_db),
        )
        write_run_artifacts(run_result)
        return run_result
    except asyncio.TimeoutError:
        wall_time = time.perf_counter() - start_time
        error_message = f"Timeout after {testcase.timeout}s"
        _mark_incomplete_logs_failed(llm_log_db, agent_log_db, error_message)

        # 从 vuln DB 回收已增量保存的漏洞
        recovered_vulns = _recover_vulns_from_db(vuln_db)
        has_results = len(recovered_vulns) > 0

        if has_results:
            result_payload = {
                "testcase_name": testcase.name,
                "entry_functions": testcase.entry_functions,
                "vulnerabilities": recovered_vulns,
                "summary": f"Timeout after {testcase.timeout}s, recovered {len(recovered_vulns)} vulnerabilities from DB",
            }
            results_markdown = format_detection_results_as_markdown(result_payload)
        else:
            results_markdown = "# Detection Results\n\nTimeout occurred.\n"

        run_result = TestRunResult(
            testcase_name=testcase.name,
            success=has_results,
            error=error_message,
            wall_time_seconds=wall_time,
            vulnerabilities=recovered_vulns,
            results_markdown=results_markdown,
            output_dir=str(output_dir),
            llm_log_db=str(llm_log_db),
            agent_log_db=str(agent_log_db),
            vuln_db=str(vuln_db),
        )
        write_run_artifacts(run_result)
        return run_result
    except Exception as exc:
        wall_time = time.perf_counter() - start_time
        error_message = str(exc)
        _mark_incomplete_logs_failed(llm_log_db, agent_log_db, error_message)
        run_result = TestRunResult(
            testcase_name=testcase.name,
            success=False,
            error=error_message,
            wall_time_seconds=wall_time,
            vulnerabilities=[],
            results_markdown=f"# Detection Results\n\nError: {error_message}\n",
            output_dir=str(output_dir),
            llm_log_db=str(llm_log_db),
            agent_log_db=str(agent_log_db),
            vuln_db=str(vuln_db),
        )
        write_run_artifacts(run_result)
        return run_result
    finally:
        reset_singletons()
        _restore_run_db_env(previous_db_env)


def _test_run_result_from_payload(payload: Dict[str, Any]) -> TestRunResult:
    """Build `TestRunResult` from the JSON payload emitted by `run-one`."""

    vulnerabilities = payload.get("vulnerabilities") or []
    return TestRunResult(
        testcase_name=str(payload.get("testcase_name") or ""),
        success=bool(payload.get("success")),
        error=payload.get("error"),
        wall_time_seconds=float(payload.get("wall_time_seconds") or 0.0),
        vulnerabilities=vulnerabilities,
        results_markdown="",
        output_dir=str(payload.get("output_dir") or ""),
        llm_log_db=str(payload.get("llm_log_db") or ""),
        agent_log_db=str(payload.get("agent_log_db") or ""),
        vuln_db=str(payload.get("vuln_db") or ""),
    )


async def _capture_subprocess_output(
    stream: asyncio.StreamReader | None,
    log_path: Path,
) -> None:
    """Drain one subprocess output stream into one per-testcase console log."""

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


async def _run_testcase_in_subprocess(
    testcase: TestCase,
    output_base_dir: str,
    testcases_dir: str | Path,
) -> TestRunResult:
    """Run one testcase in a dedicated child process for full isolation."""

    run_dir = Path(output_base_dir) / testcase.name
    run_dir.mkdir(parents=True, exist_ok=True)
    result_json = run_dir / "run_result.json"
    console_log = run_dir / "console.log"
    if result_json.exists():
        result_json.unlink()

    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "tests.eval.cli",
        "--testcases-dir",
        str(testcases_dir),
        "run-one",
        testcase.name,
        "--output-dir",
        str(output_base_dir),
        "--json-output",
        str(result_json),
        cwd=str(Path.cwd()),
        env=env,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    await _capture_subprocess_output(process.stdout, console_log)
    return_code = await process.wait()

    if result_json.exists():
        payload = json.loads(result_json.read_text(encoding="utf-8"))
        result = _test_run_result_from_payload(payload)
        detection_path = Path(result.output_dir) / "detection_results.md"
        if detection_path.exists():
            result.results_markdown = detection_path.read_text(encoding="utf-8")
        return result

    run_summary_path = run_dir / "run_summary.md"
    if run_summary_path.exists():
        return load_result_from_dir(run_dir)

    last_log = _read_last_nonempty_log_line(console_log)
    error_message = (
        f"Child process exited with code {return_code}"
        if not last_log
        else f"Child process exited with code {return_code}: {last_log}"
    )
    return TestRunResult(
        testcase_name=testcase.name,
        success=False,
        error=error_message,
        wall_time_seconds=0.0,
        vulnerabilities=[],
        results_markdown=f"# Detection Results\n\nError: {error_message}\n",
        output_dir=str(run_dir),
        llm_log_db=str(run_dir / "llm_logs.db"),
        agent_log_db=str(run_dir / "agent_logs.db"),
        vuln_db=str(run_dir / "vulnerabilities.db"),
    )


async def run_testcases(
    testcases: List[TestCase],
    output_base_dir: Optional[str] = None,
    engine_filter: Optional[str] = None,
    parallelism: int = 1,
    testcases_dir: str | Path = "tests/testcases",
) -> List[TestRunResult]:
    """Run testcase list with child-process isolation and optional parallelism."""

    selected = testcases
    if engine_filter:
        selected = [item for item in testcases if item.engine == engine_filter]

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

    async def _run_one(index: int, testcase: TestCase) -> None:
        nonlocal started_count, completed_count
        async with semaphore:
            async with state_lock:
                started_count += 1
                case_state = progress["testcases"][testcase.name]
                case_state["status"] = "running"
                case_state["started_at"] = datetime.now().isoformat()
                case_state["error"] = None
                case_state["wall_time_seconds"] = None
                case_state["vulnerabilities_count"] = 0
                write_batch_progress(base_dir, progress)
                print(
                    f"[start {started_count}/{total}] {testcase.name} "
                    f"({testcase.engine})"
                )

            result = await _run_testcase_in_subprocess(
                testcase,
                str(base_dir),
                testcases_dir,
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
                write_batch_progress(base_dir, progress)
                if result.success:
                    print(
                        f"[done {completed_count}/{total}] {testcase.name}: "
                        f"success, vulns={len(result.vulnerabilities)}, "
                        f"duration={result.wall_time_seconds:.2f}s"
                    )
                else:
                    print(
                        f"[done {completed_count}/{total}] {testcase.name}: "
                        f"failed, error={result.error}"
                    )

    await asyncio.gather(
        *[
            asyncio.create_task(_run_one(index, testcase))
            for index, testcase in enumerate(selected, start=1)
        ]
    )

    results = [results_by_name[item.name] for item in selected if item.name in results_by_name]
    write_batch_progress(base_dir, progress)
    return results
