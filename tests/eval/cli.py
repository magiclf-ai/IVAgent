#!/usr/bin/env python3
"""CLI for IVAgent evaluation framework V2."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from pathlib import Path

from tests.eval.testcase_format import discover_testcases, load_testcase


def _emit_json(data: dict) -> None:
    """Print a dict as compact JSON to stdout."""
    print(json.dumps(data, ensure_ascii=False, indent=2))


def _emit_json_error(msg: str) -> None:
    """Print an error payload as JSON to stdout."""
    _emit_json({"error": msg})


def create_llm() -> object:
    """Create the LLM client used by evaluator/analyzer."""

    try:
        from langchain_openai import ChatOpenAI
    except ModuleNotFoundError as exc:
        raise SystemExit(
            "Missing dependency `langchain_openai`. Install project dependencies before "
            "running evaluate/analyze/monitor commands."
        ) from exc

    kwargs = {
        "model": os.environ.get("OPENAI_MODEL", "gpt-4.1"),
        "temperature": 0.1,
    }
    api_key = os.environ.get("OPENAI_API_KEY")
    base_url = os.environ.get("OPENAI_BASE_URL")
    if api_key:
        kwargs["api_key"] = api_key
    if base_url:
        kwargs["base_url"] = base_url
    return ChatOpenAI(**kwargs)


def cmd_list(args: argparse.Namespace) -> int:
    testcases = discover_testcases(Path(args.testcases_dir))

    if args.engine:
        testcases = [tc for tc in testcases if tc.engine == args.engine]
    if args.tags:
        required = {t.strip() for t in args.tags.split(",")}
        testcases = [tc for tc in testcases if required & set(tc.tags)]

    if getattr(args, "json", False):
        _emit_json({
            "total": len(testcases),
            "testcases": [
                {
                    "name": tc.name,
                    "engine": tc.engine,
                    "skill": tc.skill,
                    "entry_functions": tc.entry_functions,
                    "tags": tc.tags,
                    "timeout": tc.timeout,
                }
                for tc in testcases
            ],
        })
        return 0

    if not testcases:
        print("No test cases found.")
        return 0

    print(f"Found {len(testcases)} test cases:\n")
    for testcase in testcases:
        print(f"  {testcase.name} ({testcase.engine})")
        print(f"    Entry functions: {', '.join(testcase.entry_functions)}")
        print(f"    Tags: {', '.join(testcase.tags)}")
        print()
    return 0


async def cmd_run_async(args: argparse.Namespace) -> int:
    try:
        from tests.eval.test_runner import run_testcase, run_testcases, write_run_index
    except ModuleNotFoundError as exc:
        raise SystemExit(
            "Missing runtime dependencies for testcase execution. "
            "Install project requirements before running `python3 -m tests.eval.cli run`."
        ) from exc

    testcases_dir = Path(args.testcases_dir)
    if args.all:
        testcases = discover_testcases(testcases_dir)
        if args.engine:
            testcases = [item for item in testcases if item.engine == args.engine]
        if not testcases:
            print("No matching test cases found.")
            return 1

        results = await run_testcases(
            testcases,
            output_base_dir=args.output_dir,
            engine_filter=args.engine,
            parallelism=args.parallel,
            testcases_dir=testcases_dir,
        )
        output_dir = args.output_dir or (results[0].output_dir and str(Path(results[0].output_dir).parent))
        if output_dir:
            write_run_index(results, output_dir)
        return 0

    if args.testcase:
        testcase_dir = testcases_dir / args.testcase
        if not testcase_dir.exists():
            print(f"Test case not found: {args.testcase}")
            return 1

        testcase = load_testcase(testcase_dir)
        result = await run_testcase(testcase, output_base_dir=args.output_dir)
        if result.success:
            print(
                f"success: {len(result.vulnerabilities)} vulnerabilities "
                f"found in {result.wall_time_seconds:.2f}s"
            )
        else:
            print(f"failed: {result.error}")
        return 0

    print("Must specify --all or --testcase")
    return 1


def cmd_run(args: argparse.Namespace) -> int:
    return asyncio.run(cmd_run_async(args))


def cmd_evaluate(args: argparse.Namespace) -> int:
    from tests.eval.llm_evaluator import llm_evaluate_all, save_evaluation_report
    from tests.eval.test_runner import discover_run_results

    results_dir = Path(args.results_dir)
    if not results_dir.exists():
        print(f"Results directory not found: {results_dir}")
        return 1

    results = discover_run_results(results_dir)
    if not results:
        print(f"No run summaries found under: {results_dir}")
        return 1

    all_testcases = discover_testcases(Path(args.testcases_dir))
    testcase_names = {item.testcase_name for item in results}
    testcases = [item for item in all_testcases if item.name in testcase_names]

    llm = create_llm()
    report = llm_evaluate_all(testcases, results, llm)
    print(report)

    output_file = args.output or str(results_dir / "evaluation_report.md")
    save_evaluation_report(report, output_file)
    return 0


def cmd_analyze(args: argparse.Namespace) -> int:
    from tests.eval.llm_analyzer import llm_analyze_logs

    run_dir = Path(args.run_dir)
    if not run_dir.exists():
        print(f"Run directory not found: {run_dir}")
        return 1

    llm = create_llm()
    report = llm_analyze_logs(str(run_dir), llm)
    print(report)
    if args.output:
        Path(args.output).write_text(report, encoding="utf-8")
        print(f"Analysis saved to {args.output}")
    return 0


def cmd_monitor(args: argparse.Namespace) -> int:
    from tests.eval.llm_analyzer import llm_monitor_runtime, take_snapshot

    run_dir = Path(args.run_dir)
    if not run_dir.exists():
        print(f"Run directory not found: {run_dir}")
        return 1

    llm = create_llm()
    snapshots = []
    print(f"Monitoring {run_dir} (interval: {args.interval}s, Ctrl+C to stop)...")
    try:
        while True:
            snapshot = take_snapshot(str(run_dir))
            snapshots.append(snapshot)
            print(f"[{snapshot['timestamp']}]")
            print(f"  LLM Calls: {snapshot['llm_calls']}")
            print(f"  Agents: {snapshot['agents']}")
            print(f"  Vulnerabilities: {snapshot['vulnerabilities']}")
            print(f"  Failed Agents: {snapshot['failed_agents']}")
            print(f"  Failed LLM Calls: {snapshot['failed_llm_calls']}")
            if len(snapshots) >= 3 and len(snapshots) % 3 == 0:
                analysis = llm_monitor_runtime(str(run_dir), llm, snapshots[-3:])
                print("\nLLM Analysis:\n")
                print(analysis)
                print()
                if "Stop" in analysis or "stop" in analysis:
                    print("LLM recommends stopping.")
                    break
            print()
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("Monitoring stopped.")
    return 0


def cmd_monitor_batch(args: argparse.Namespace) -> int:
    from tests.eval.test_runner import format_batch_progress_as_markdown, load_batch_progress

    results_dir = Path(args.results_dir)
    if not results_dir.exists():
        print(f"Results directory not found: {results_dir}")
        return 1

    print(f"Monitoring batch run {results_dir} (interval: {args.interval}s, Ctrl+C to stop)...")
    try:
        while True:
            progress = load_batch_progress(results_dir)
            if not progress:
                print("No batch progress artifacts found yet.\n")
            else:
                print(format_batch_progress_as_markdown(progress))
                print()
                summary = progress.get("summary", {})
                if (
                    summary.get("total", 0) > 0
                    and summary.get("completed", 0) >= summary.get("total", 0)
                ):
                    print("Batch run completed.")
                    break
            if args.once:
                break
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("Batch monitoring stopped.")
    return 0


async def cmd_run_one_async(args: argparse.Namespace) -> int:
    """Execute a single testcase and emit JSON result."""
    try:
        from tests.eval.test_runner import run_testcase
    except ModuleNotFoundError as exc:
        _emit_json_error(f"Missing runtime dependencies: {exc}")
        return 1

    testcases_dir = Path(args.testcases_dir)
    testcase_dir = testcases_dir / args.testcase
    if not testcase_dir.exists():
        _emit_json_error(f"Test case not found: {args.testcase}")
        return 1

    try:
        testcase = load_testcase(testcase_dir)
    except Exception as exc:
        _emit_json_error(f"Failed to load testcase: {exc}")
        return 1

    result = await run_testcase(testcase, output_base_dir=args.output_dir)

    output = {
        "testcase_name": result.testcase_name,
        "success": result.success,
        "error": result.error,
        "wall_time_seconds": round(result.wall_time_seconds, 2),
        "vulnerabilities_count": len(result.vulnerabilities),
        "vulnerabilities": result.vulnerabilities,
        "output_dir": result.output_dir,
        "llm_log_db": result.llm_log_db,
        "agent_log_db": result.agent_log_db,
        "vuln_db": result.vuln_db,
        "artifacts": {},
    }
    out_path = Path(result.output_dir)
    for name in ("run_summary.md", "detection_results.md"):
        artifact = out_path / name
        if artifact.exists():
            output["artifacts"][name] = str(artifact)

    if args.json_output:
        Path(args.json_output).write_text(
            json.dumps(output, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    _emit_json(output)
    return 0 if result.success else 1


def cmd_run_one(args: argparse.Namespace) -> int:
    return asyncio.run(cmd_run_one_async(args))


def cmd_status(args: argparse.Namespace) -> int:
    """Query eval DB statistics and emit JSON."""
    from ivagent.core.db_profiles import get_db_paths, PROFILE_EVAL
    from ivagent.core.llm_logger import SQLiteLogStorage
    from ivagent.core.agent_logger import AgentLogStorage
    from ivagent.core.vuln_storage import VulnerabilityStorage

    eval_paths = get_db_paths(PROFILE_EVAL)

    llm_stats = {"total_calls": 0, "success_calls": 0, "failed_calls": 0}
    if eval_paths.llm_log_db.exists():
        try:
            storage = SQLiteLogStorage(eval_paths.llm_log_db)
            s = storage.get_stats()
            llm_stats = {
                "total_calls": s.get("total_calls", 0),
                "success_calls": s.get("success_calls", 0),
                "failed_calls": s.get("failed_calls", 0),
            }
        except Exception:
            pass

    agent_stats = {"total_agents": 0, "completed": 0, "failed": 0}
    if eval_paths.agent_log_db.exists():
        try:
            storage = AgentLogStorage(eval_paths.agent_log_db)
            s = storage.get_stats()
            agent_stats = {
                "total_agents": s.get("total_agents", 0),
                "completed": s.get("completed", 0),
                "failed": s.get("failed", 0),
            }
        except Exception:
            pass

    vuln_stats = {"total": 0, "by_severity": {}}
    if eval_paths.vuln_db.exists():
        try:
            storage = VulnerabilityStorage(eval_paths.vuln_db)
            s = storage.get_statistics()
            vuln_stats = {
                "total": s.get("total", 0),
                "by_severity": s.get("by_severity", {}),
            }
        except Exception:
            pass

    _emit_json({
        "profile": "eval",
        "llm_logs": llm_stats,
        "agents": agent_stats,
        "vulnerabilities": vuln_stats,
    })
    return 0


def cmd_reset(args: argparse.Namespace) -> int:
    """Delete eval DB files and reset singletons."""
    from ivagent.core.db_profiles import get_db_paths, PROFILE_EVAL
    from tests.eval.test_runner import reset_singletons

    eval_paths = get_db_paths(PROFILE_EVAL)
    deleted = []
    for db_path in (eval_paths.llm_log_db, eval_paths.agent_log_db, eval_paths.vuln_db):
        if db_path.exists():
            db_path.unlink()
            deleted.append(db_path.name)

    reset_singletons()

    _emit_json({
        "action": "reset",
        "deleted_databases": deleted,
    })
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="IVAgent Evaluation Framework CLI (V2 - LLM-driven)"
    )
    parser.add_argument(
        "--testcases-dir",
        default="tests/testcases",
        help="Test cases directory",
    )

    subparsers = parser.add_subparsers(dest="command")

    list_parser = subparsers.add_parser("list", help="List all test cases")
    list_parser.add_argument("--json", action="store_true", help="Output as JSON")
    list_parser.add_argument("--engine", choices=["source", "ida", "jeb", "abc"], help="Filter by engine")
    list_parser.add_argument("--tags", help="Filter by tags (comma-separated)")

    run_parser = subparsers.add_parser("run", help="Run test cases")
    run_group = run_parser.add_mutually_exclusive_group(required=True)
    run_group.add_argument("--all", action="store_true", help="Run all test cases")
    run_group.add_argument("--testcase", help="Run one testcase by name")
    run_parser.add_argument("--engine", choices=["source", "ida", "jeb", "abc"])
    run_parser.add_argument("--output-dir", help="Directory to store outputs")
    run_parser.add_argument(
        "--parallel",
        type=int,
        default=1,
        help="Maximum number of testcases to run in parallel when using --all",
    )

    evaluate_parser = subparsers.add_parser("evaluate", help="Evaluate run results")
    evaluate_parser.add_argument("--results-dir", required=True)
    evaluate_parser.add_argument("--output")

    analyze_parser = subparsers.add_parser("analyze", help="Analyze one testcase run directory")
    analyze_parser.add_argument("--run-dir", required=True)
    analyze_parser.add_argument("--output")

    monitor_parser = subparsers.add_parser("monitor", help="Monitor a live testcase run directory")
    monitor_parser.add_argument("--run-dir", required=True)
    monitor_parser.add_argument("--interval", type=int, default=10)

    monitor_batch_parser = subparsers.add_parser(
        "monitor-batch",
        help="Monitor one live batch run directory",
    )
    monitor_batch_parser.add_argument("--results-dir", required=True)
    monitor_batch_parser.add_argument("--interval", type=int, default=15)
    monitor_batch_parser.add_argument("--once", action="store_true")

    run_one_parser = subparsers.add_parser("run-one", help="Run a single testcase (JSON output)")
    run_one_parser.add_argument("testcase", help="Testcase name")
    run_one_parser.add_argument("--output-dir", help="Output directory")
    run_one_parser.add_argument("--json-output", help="Optional JSON file path for machine-readable result output")

    subparsers.add_parser("status", help="Query eval DB statistics (JSON output)")

    subparsers.add_parser("reset", help="Clear eval DB and reset state (JSON output)")

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return 1

    if args.command == "list":
        return cmd_list(args)
    if args.command == "run":
        return cmd_run(args)
    if args.command == "evaluate":
        return cmd_evaluate(args)
    if args.command == "analyze":
        return cmd_analyze(args)
    if args.command == "monitor":
        return cmd_monitor(args)
    if args.command == "monitor-batch":
        return cmd_monitor_batch(args)
    if args.command == "run-one":
        return cmd_run_one(args)
    if args.command == "status":
        return cmd_status(args)
    if args.command == "reset":
        return cmd_reset(args)
    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
