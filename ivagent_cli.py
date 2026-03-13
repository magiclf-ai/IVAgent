#!/usr/bin/env python3
"""
IVAgent 统一 CLI 入口。
"""

import argparse
import asyncio
import json
import os
import sys
import time
import warnings
from typing import Any, Optional

from ivagent.core.cli_logger import CLILogger, format_duration
from ivagent.core.db_profiles import get_db_paths
from ivagent.models.skill import SkillContext
from ivagent.models.skill_parser import SkillParser


def create_llm_client() -> Any:
    from langchain_openai import ChatOpenAI

    api_key = os.environ.get("OPENAI_API_KEY")
    base_url = os.environ.get("OPENAI_BASE_URL")
    model = os.environ.get("OPENAI_MODEL")

    kwargs: dict[str, Any] = {
        "model": model,
        "temperature": 0.3,
    }
    if api_key:
        kwargs["api_key"] = api_key
    if base_url:
        kwargs["base_url"] = base_url
    return ChatOpenAI(**kwargs)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="IVAgent - 智能漏洞挖掘系统",
    )

    parser.add_argument(
        "--skill",
        "-s",
        required=True,
        help="Skill 名称（在 vuln_skills/ 目录查找）或 SKILL.md 路径",
    )
    parser.add_argument(
        "--engine",
        "-e",
        choices=["ida", "jeb", "abc", "source"],
        help="分析引擎类型（覆盖 skill 中的 engine 字段）",
    )
    parser.add_argument(
        "--target",
        "-t",
        help="目标文件路径（IDB/APK/ABC/源码目录）",
    )
    parser.add_argument(
        "--function",
        "-f",
        help="直接扫描指定函数（跳过编排，直接调用 DeepVulnAgent）",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="引擎 RPC 地址（默认 127.0.0.1）",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=0,
        help="引擎 RPC 端口（0=使用引擎默认端口）",
    )
    parser.add_argument(
        "--no-auto-start",
        action="store_true",
        help="不自动启动引擎 RPC 服务",
    )
    parser.add_argument(
        "--source-root",
        help="源代码根目录",
    )
    parser.add_argument(
        "--mode",
        "-m",
        choices=["sequential", "parallel"],
        default="parallel",
        help="执行模式",
    )
    parser.add_argument(
        "--concurrency",
        "-c",
        type=int,
        default=10,
        help="最大并发数",
    )
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--quiet", "-q", action="store_true")
    parser.add_argument(
        "--skills-dir",
        default="vuln_skills",
        help="Skills 根目录（默认 vuln_skills/）",
    )
    return parser


def build_logger(args: argparse.Namespace) -> CLILogger:
    if args.debug:
        mode = "debug"
    elif args.quiet:
        mode = "normal"
    elif args.verbose:
        mode = "verbose"
    else:
        mode = "normal"
    return CLILogger(component="ivagent_cli", verbose=args.verbose or args.debug, mode=mode)


def resolve_source_paths(engine_type: str, target_path: Optional[str], source_root: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    if engine_type != "source":
        return target_path, source_root
    final_target = target_path or source_root
    final_source_root = source_root or target_path
    return final_target, final_source_root


async def run_direct_scan(
    *,
    skill: SkillContext,
    function_identifier: str,
    engine_type: str,
    target_path: Optional[str],
    host: str,
    port: int,
    source_root: Optional[str],
    concurrency: int,
    verbose: bool,
) -> dict[str, Any]:
    from ivagent.scanner import IVAgentScanner, ScanConfig

    config = ScanConfig(
        engine_type=engine_type,
        target_path=target_path,
        llm_api_key=os.environ.get("OPENAI_API_KEY", ""),
        llm_base_url=os.environ.get("OPENAI_BASE_URL", ""),
        llm_model=os.environ.get("OPENAI_MODEL", ""),
        engine_host=host,
        engine_port=port,
        max_concurrency=concurrency,
        verbose=verbose,
        source_root=source_root,
    )
    scanner = IVAgentScanner(config)
    return await scanner.scan_function(function_identifier, skill=skill)


async def run_orchestrator(
    *,
    skill: SkillContext,
    engine_type: str,
    target_path: Optional[str],
    source_root: Optional[str],
    execution_mode: str,
    verbose: bool,
) -> Any:
    from ivagent.orchestrator import MasterOrchestrator

    llm_client = create_llm_client()
    orchestrator = MasterOrchestrator(
        llm_client=llm_client,
        engine_type=engine_type,
        target_path=target_path,
        source_root=source_root,
        execution_mode=execution_mode,
        verbose=verbose,
    )
    try:
        return await orchestrator.execute_skill(skill, target_path=target_path)
    finally:
        engine = getattr(orchestrator, "engine", None)
        if engine and hasattr(engine, "close"):
            await engine.close()


def emit_result(result: Any) -> None:
    if hasattr(result, "workflow_results"):
        payload = {
            "success": result.success,
            "total_workflows": result.total_workflows,
            "completed_workflows": result.completed_workflows,
            "total_vulnerabilities": result.total_vulnerabilities,
            "execution_time": result.execution_time,
            "summary": result.summary,
            "errors": result.errors,
            "workflow_results": result.workflow_results,
        }
    else:
        payload = result
    print(json.dumps(payload, ensure_ascii=False, indent=2))


async def main_async(args: argparse.Namespace) -> int:
    from ivagent.engines.service_manager import EngineServiceManager
    from ivagent.core.llm_logger import get_log_manager
    from ivagent.core.agent_logger import get_agent_log_manager
    from ivagent.core.vuln_storage import get_vulnerability_manager

    # 使用 production profile 初始化数据库
    db_paths = get_db_paths()
    get_log_manager(storage_path=db_paths.llm_log_db)
    get_agent_log_manager(db_path=db_paths.agent_log_db)
    get_vulnerability_manager(db_path=db_paths.vuln_db)

    logger = build_logger(args)
    parser = SkillParser()
    skill = parser.resolve_skill(args.skill, skills_root=args.skills_dir)

    engine_type = args.engine or skill.engine
    if not engine_type:
        raise SystemExit("错误: 未指定引擎类型，请通过 --engine 指定或在 SKILL.md 中设置 engine 字段")

    target_path, source_root = resolve_source_paths(engine_type, args.target, args.source_root)
    if engine_type != "source" and not target_path and not args.no_auto_start:
        raise SystemExit("错误: 自动启动 RPC 服务时必须提供 --target")

    service_manager = EngineServiceManager(logger=logger)
    started_t0 = time.perf_counter()
    try:
        if args.no_auto_start:
            host = args.host
            port = args.port
        else:
            service_info = await service_manager.ensure_service(
                engine_type=engine_type,
                target_path=target_path,
                host=args.host,
                port=args.port,
            )
            host = service_info["host"]
            port = service_info["port"]

        if args.function:
            result = await run_direct_scan(
                skill=skill,
                function_identifier=args.function,
                engine_type=engine_type,
                target_path=target_path,
                host=host,
                port=port,
                source_root=source_root,
                concurrency=args.concurrency,
                verbose=args.verbose or args.debug,
            )
            logger.success(
                "cli.direct_scan.done",
                "直接扫描完成",
                function=args.function,
                vulnerabilities=len(result.get("vulnerabilities", [])),
                duration=format_duration(time.perf_counter() - started_t0),
            )
        else:
            result = await run_orchestrator(
                skill=skill,
                engine_type=engine_type,
                target_path=target_path,
                source_root=source_root,
                execution_mode=args.mode,
                verbose=args.verbose or args.debug,
            )
            logger.success(
                "cli.orchestrator.done",
                "编排执行完成",
                success=result.success,
                vulnerabilities=result.total_vulnerabilities,
                duration=format_duration(time.perf_counter() - started_t0),
            )

        emit_result(result)
        return 0
    finally:
        await service_manager.shutdown_all()


def main() -> int:
    warnings.filterwarnings(
        "ignore",
        message="Core Pydantic V1 functionality isn't compatible with Python 3.14 or greater.",
        category=UserWarning,
    )
    args = build_parser().parse_args()
    return asyncio.run(main_async(args))


if __name__ == "__main__":
    sys.exit(main())
