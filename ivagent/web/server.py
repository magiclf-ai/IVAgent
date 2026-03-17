#!/usr/bin/env python3
"""LLM 日志可视化服务器内部入口。"""

import argparse
import os
from typing import Sequence

from ivagent.core.cli_logger import CLILogger
from ivagent.core.db_profiles import ENV_KEY, PROFILE_PRODUCTION, activate_db_profile


def build_parser() -> argparse.ArgumentParser:
    """构建 Web 服务器命令行参数。"""

    parser = argparse.ArgumentParser(description='LLM 交互日志可视化服务器')
    parser.add_argument('--host', default='0.0.0.0', help='服务器主机地址 (默认: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=8080, help='服务器端口 (默认: 8080)')
    parser.add_argument('--reload', action='store_true', help='启用自动重载（开发模式）')
    parser.add_argument(
        '--profile', default=PROFILE_PRODUCTION,
        choices=['production', 'eval'],
        help='数据库 profile (默认: production)',
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """启动 Web 服务。"""

    logger = CLILogger(component="web.server", verbose=True)
    args = build_parser().parse_args(argv)

    # 通过环境变量传递给 uvicorn worker 进程
    os.environ[ENV_KEY] = args.profile
    db_paths = activate_db_profile(args.profile, clear_path_overrides=True)

    logger.info("startup.banner", "LLM 交互日志可视化系统")
    logger.info("startup.profile", "数据库 profile", profile=args.profile)
    logger.info("startup.llm_db", "LLM 日志", db_path=db_paths.llm_log_db)
    logger.info("startup.agent_db", "Agent 日志", db_path=db_paths.agent_log_db)
    logger.info("startup.vuln_db", "漏洞库", db_path=db_paths.vuln_db)
    logger.info("startup.addr", "服务地址", url=f"http://{args.host}:{args.port}")

    from ivagent.web.api import start_server

    start_server(host=args.host, port=args.port, reload=args.reload, profile=args.profile)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
