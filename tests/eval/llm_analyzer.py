#!/usr/bin/env python3
"""LLM-driven runtime and log analyzer for evaluation runs."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from ivagent.core.agent_logger import AgentLogStorage
from ivagent.core.llm_logger import SQLiteLogStorage
from ivagent.core.vuln_storage import VulnerabilityStorage


def _response_to_text(response: object) -> str:
    content = getattr(response, "content", response)
    if isinstance(content, list):
        return "\n".join(str(item) for item in content)
    return str(content)


def _safe_db_path(output_dir: str, filename: str) -> Path:
    return Path(output_dir) / filename


def format_llm_logs_as_markdown(output_dir: str) -> str:
    """Render LLM log database as a markdown summary."""

    db_path = _safe_db_path(output_dir, "llm_logs.db")
    if not db_path.exists():
        return "# LLM Logs Summary\n\nNo `llm_logs.db` found.\n"

    storage = SQLiteLogStorage(db_path)
    stats = storage.get_stats()
    lines = [
        "# LLM Logs Summary",
        "",
        "## Statistics",
        "",
        f"- **Total Calls**: {stats['total_calls']}",
        f"- **Success Calls**: {stats['success_calls']}",
        f"- **Failed Calls**: {stats['failed_calls']}",
        f"- **Success Rate**: {stats['success_rate']:.1%}",
        f"- **Average Latency**: {stats['avg_latency_ms']:.0f} ms",
        "",
        "## Model Distribution",
        "",
    ]

    for model, count in sorted(stats["model_distribution"].items()):
        lines.append(f"- {model}: {count} calls")
    if not stats["model_distribution"]:
        lines.append("- None")
    lines.extend(["", "## Call Type Distribution", ""])

    for call_type, count in sorted(stats["call_type_distribution"].items()):
        lines.append(f"- {call_type}: {count} calls")
    if not stats["call_type_distribution"]:
        lines.append("- None")

    if stats["failed_calls"] > 0:
        lines.extend(["", "## Failed Calls", ""])
        for entry in storage.query_entries(success=False, limit=10):
            lines.extend(
                [
                    f"### Failed Call at {entry.timestamp}",
                    f"- **Model**: {entry.model}",
                    f"- **Call Type**: {entry.call_type}",
                    f"- **Error**: {entry.error or 'Unknown'}",
                    f"- **Retry Count**: {entry.retry_count}",
                    "",
                ]
            )

    return "\n".join(lines) + "\n"


def format_agent_tree_node(node: Dict[str, Any], level: int = 0) -> str:
    """Recursively render an agent execution tree node."""

    indent = "  " * level
    lines = [
        f"{indent}- **{node.get('agent_type', 'Unknown')}** ({node.get('target_function', 'Unknown')})",
        f"{indent}  - Status: {node.get('status', 'unknown')}",
        f"{indent}  - Vulnerabilities: {node.get('vulnerabilities_found', 0)}",
        f"{indent}  - Sub-agents: {node.get('sub_agents_created', 0)}",
        f"{indent}  - LLM Calls: {node.get('llm_calls', 0)}",
    ]
    if node.get("error_message"):
        lines.append(f"{indent}  - Error: {node['error_message']}")
    for child in node.get("children", []):
        lines.append(format_agent_tree_node(child, level + 1))
    return "\n".join(lines)


def format_agent_logs_as_markdown(output_dir: str) -> str:
    """Render agent execution database as markdown."""

    db_path = _safe_db_path(output_dir, "agent_logs.db")
    if not db_path.exists():
        return "# Agent Execution Summary\n\nNo `agent_logs.db` found.\n"

    storage = AgentLogStorage(db_path)
    stats = storage.get_stats()
    lines = [
        "# Agent Execution Summary",
        "",
        "## Statistics",
        "",
        f"- **Total Agents**: {stats['total_agents']}",
        f"- **Completed**: {stats['completed']}",
        f"- **Failed**: {stats['failed']}",
        f"- **Total Vulnerabilities Found**: {stats['total_vulnerabilities']}",
        "",
        "## Agent Type Distribution",
        "",
    ]

    for agent_type, count in sorted(stats["agent_type_distribution"].items()):
        lines.append(f"- {agent_type}: {count} agents")
    if not stats["agent_type_distribution"]:
        lines.append("- None")

    lines.extend(["", "## Agent Execution Tree", ""])
    roots = storage.get_executions_by_parent(None)
    if not roots:
        lines.append("No agent executions recorded.")
    else:
        for root in roots:
            lines.append(format_agent_tree_node(storage.get_execution_tree(root.agent_id)))
    return "\n".join(lines) + "\n"


def format_vulnerabilities_as_markdown(output_dir: str) -> str:
    """Render stored vulnerabilities as markdown."""

    db_path = _safe_db_path(output_dir, "vulnerabilities.db")
    if not db_path.exists():
        return "# Detected Vulnerabilities\n\nNo `vulnerabilities.db` found.\n"

    storage = VulnerabilityStorage(db_path)
    vulnerabilities = storage.query_vulnerabilities(limit=100)
    lines = [
        "# Detected Vulnerabilities",
        "",
        f"**Total**: {len(vulnerabilities)}",
        "",
    ]

    for index, vuln in enumerate(vulnerabilities, start=1):
        confidence = (
            f"{vuln.confidence * 10:.1f}/10"
            if isinstance(vuln.confidence, (int, float))
            else str(vuln.confidence)
        )
        lines.extend(
            [
                f"## Vulnerability {index}: {vuln.name}",
                "",
                f"- **Type**: {vuln.type}",
                f"- **Function**: {vuln.function_identifier}",
                f"- **Location**: {vuln.location}",
                f"- **Severity**: {vuln.severity}",
                f"- **Confidence**: {confidence}",
                "",
            ]
        )
        if vuln.description:
            lines.extend(["**Description**:", "", vuln.description, ""])
    return "\n".join(lines) + "\n"


def llm_analyze_logs(output_dir: str, llm: object) -> str:
    """Ask the LLM to analyze one run directory."""

    combined_md = "\n\n---\n\n".join(
        [
            format_llm_logs_as_markdown(output_dir),
            format_agent_logs_as_markdown(output_dir),
            format_vulnerabilities_as_markdown(output_dir),
        ]
    )
    prompt = f"""You are analyzing execution logs from an automated vulnerability detection run.

{combined_md}

# Task

You MUST write the entire report in Simplified Chinese.
Return a Chinese markdown report only.

Return markdown with these sections:

## 1. Execution Quality
Assess whether the run completed cleanly and efficiently.

## 2. LLM Usage Analysis
Explain whether LLM usage, retries, and latency are reasonable.

## 3. Agent Behavior Analysis
Explain whether agent creation depth and execution tree look healthy.

## 4. Vulnerability Detection Quality
Judge whether the detected vulnerabilities look reasonable.

## 5. Anomalies and Problems
List concrete anomalies or suspicious patterns.

## 6. Recommendations
Provide concrete improvements.

## 7. Overall Assessment
Summarize the run quality.
"""
    return _response_to_text(llm.invoke(prompt))


def llm_monitor_runtime(output_dir: str, llm: object, snapshots: List[Dict[str, Any]]) -> str:
    """Ask the LLM to evaluate recent runtime snapshots."""

    lines = ["# Runtime Snapshots", ""]
    for index, snapshot in enumerate(snapshots, start=1):
        lines.extend(
            [
                f"## Snapshot {index} ({snapshot['timestamp']})",
                "",
                f"- LLM Calls: {snapshot['llm_calls']}",
                f"- Agents: {snapshot['agents']}",
                f"- Vulnerabilities: {snapshot['vulnerabilities']}",
                f"- Failed Agents: {snapshot['failed_agents']}",
                f"- Failed LLM Calls: {snapshot['failed_llm_calls']}",
                "",
            ]
        )

    prompt = f"""You are monitoring a live vulnerability detection run.

{chr(10).join(lines)}

# Task

You MUST write the entire report in Simplified Chinese.
Return a Chinese markdown report only.

Analyze recent progress and answer:

## 1. Progress Assessment
Is the run making progress?

## 2. Problem Detection
Is it stuck or failing abnormally?

## 3. Recommendation
Choose one of:
- **Continue**
- **Monitor**
- **Stop**

Explain the reasoning clearly.
"""
    return _response_to_text(llm.invoke(prompt))


def take_snapshot(output_dir: str) -> Dict[str, Any]:
    """Take a lightweight runtime snapshot from the sqlite artifacts."""

    llm_db = _safe_db_path(output_dir, "llm_logs.db")
    agent_db = _safe_db_path(output_dir, "agent_logs.db")
    vuln_db = _safe_db_path(output_dir, "vulnerabilities.db")

    llm_stats = SQLiteLogStorage(llm_db).get_stats() if llm_db.exists() else {
        "total_calls": 0,
        "failed_calls": 0,
    }
    agent_stats = AgentLogStorage(agent_db).get_stats() if agent_db.exists() else {
        "total_agents": 0,
        "failed": 0,
    }
    vuln_count = len(VulnerabilityStorage(vuln_db).query_vulnerabilities(limit=1000)) if vuln_db.exists() else 0

    return {
        "timestamp": datetime.now().isoformat(),
        "llm_calls": llm_stats["total_calls"],
        "agents": agent_stats["total_agents"],
        "vulnerabilities": vuln_count,
        "failed_agents": agent_stats["failed"],
        "failed_llm_calls": llm_stats["failed_calls"],
    }
