#!/usr/bin/env python3
"""
LLM 日志可视化服务器启动脚本

Usage:
    python server.py                    # 使用默认配置启动
    python server.py --port 8080        # 指定端口
    python server.py --host 0.0.0.0     # 指定主机
    python server.py --reload           # 开发模式（自动重载）
"""

import argparse
import sys
from pathlib import Path

# 添加父目录到路径
sys.path.insert(0, str(Path(__file__).parent.parent))

from web.api import start_server
from core.cli_logger import CLILogger


def main():
    logger = CLILogger(component="web.server", verbose=True)
    parser = argparse.ArgumentParser(description='LLM 交互日志可视化服务器')
    parser.add_argument('--host', default='0.0.0.0', help='服务器主机地址 (默认: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=8080, help='服务器端口 (默认: 8080)')
    parser.add_argument('--reload', action='store_true', help='启用自动重载（开发模式）')
    
    args = parser.parse_args()
    
    logger.info("startup.banner", "LLM 交互日志可视化系统")
    logger.info("startup.addr", "服务地址", url=f"http://{args.host}:{args.port}")
    logger.info("startup.docs", "API 文档地址", url=f"http://{args.host}:{args.port}/docs")
    
    start_server(host=args.host, port=args.port, reload=args.reload)


if __name__ == '__main__':
    main()
