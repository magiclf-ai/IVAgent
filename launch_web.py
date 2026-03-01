#!/usr/bin/env python3
"""
IVAgent 智能漏洞挖掘系统 - 快速启动器

提供简单的命令行接口来启动漏洞分析服务器
"""

import sys
import subprocess
from pathlib import Path

from ivagent.core.cli_logger import CLILogger


def check_dependencies(logger: CLILogger):
    """检查必要的依赖"""
    try:
        import fastapi
        import uvicorn
        import pydantic
        logger.success("deps.ok", "依赖检查通过")
        return True
    except ImportError as e:
        logger.error("deps.missing", "缺少依赖", error=str(e))
        logger.info("deps.install", "请安装依赖: pip install fastapi uvicorn pydantic")
        return False


def main():
    logger = CLILogger(component="launch_web", verbose=True)
    logger.info("startup.banner", "IVAgent 智能漏洞挖掘系统")
    
    # 检查依赖
    if not check_dependencies(logger):
        return 1
    
    # 获取 web 目录
    web_dir = Path(__file__).parent / "ivagent/web"
    server_script = web_dir / "server.py"
    
    if not server_script.exists():
        logger.error("startup.missing_server", "找不到服务器脚本", path=server_script)
        return 1
    
    # 启动服务器
    logger.info("startup.server", "启动服务器", script=server_script)
    args = [sys.executable, str(server_script)] + sys.argv[1:]
    return subprocess.call(args)


if __name__ == '__main__':
    sys.exit(main())
