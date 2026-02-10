#!/usr/bin/env python3
"""
LLM 交互日志系统 - 快速启动器

提供简单的命令行接口来启动日志可视化服务器
"""

import sys
import subprocess
from pathlib import Path


def check_dependencies():
    """检查必要的依赖"""
    try:
        import fastapi
        import uvicorn
        import pydantic
        print("✓ 依赖检查通过")
        return True
    except ImportError as e:
        print(f"✗ 缺少依赖: {e}")
        print("\n请安装依赖:")
        print("  pip install fastapi uvicorn pydantic")
        return False


def main():
    print("""
╔══════════════════════════════════════════════════════════════╗
║          LLM 交互日志可视化系统                              ║
╚══════════════════════════════════════════════════════════════╝
""")
    
    # 检查依赖
    if not check_dependencies():
        return 1
    
    # 获取 web 目录
    web_dir = Path(__file__).parent / "ivagent/web"
    server_script = web_dir / "server.py"
    
    if not server_script.exists():
        print(f"✗ 找不到服务器脚本: {server_script}")
        return 1
    
    # 启动服务器
    print("\n启动服务器...\n")
    args = [sys.executable, str(server_script)] + sys.argv[1:]
    return subprocess.call(args)


if __name__ == '__main__':
    sys.exit(main())
