#!/usr/bin/env python3
"""
LLM 日志可视化服务器启动脚本

Usage:
    python server.py                        # 默认 production profile
    python server.py --profile eval         # 查看测试/评估日志
    python server.py --port 8080            # 指定端口
    python server.py --host 0.0.0.0         # 指定主机
    python server.py --reload               # 开发模式（自动重载）
"""

import argparse
import os
import sys
from pathlib import Path

# 添加父目录到路径
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.cli_logger import CLILogger
from core.db_profiles import get_db_paths, ENV_KEY, PROFILE_PRODUCTION


def main():
    logger = CLILogger(component="web.server", verbose=True)
    parser = argparse.ArgumentParser(description='LLM 交互日志可视化服务器')
    parser.add_argument('--host', default='0.0.0.0', help='服务器主机地址 (默认: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=8080, help='服务器端口 (默认: 8080)')
    parser.add_argument('--reload', action='store_true', help='启用自动重载（开发模式）')
    parser.add_argument(
        '--profile', default=PROFILE_PRODUCTION,
        choices=['production', 'eval'],
        help='数据库 profile (默认: production)',
    )

    args = parser.parse_args()

    # 通过环境变量传递给 uvicorn worker 进程
    os.environ[ENV_KEY] = args.profile
    db_paths = get_db_paths(args.profile)

    logger.info("startup.banner", "LLM 交互日志可视化系统")
    logger.info("startup.profile", "数据库 profile", profile=args.profile)
    logger.info("startup.llm_db", "LLM 日志", db_path=db_paths.llm_log_db)
    logger.info("startup.agent_db", "Agent 日志", db_path=db_paths.agent_log_db)
    logger.info("startup.vuln_db", "漏洞库", db_path=db_paths.vuln_db)
    logger.info("startup.addr", "服务地址", url=f"http://{args.host}:{args.port}")

    from web.api import start_server
    start_server(host=args.host, port=args.port, reload=args.reload)


if __name__ == '__main__':
    main()
