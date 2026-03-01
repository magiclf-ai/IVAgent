#!/usr/bin/env python3
import idapro
import sys
import argparse
from pathlib import Path

# 添加 hexray_scripts 到路径
SCRIPT_DIR = Path(__file__).parent.resolve()
sys.path.insert(0, str(SCRIPT_DIR))

# 导入 server 模块
from ivagent.backends.ida.rpc.server import start_server
from ivagent.core.cli_logger import CLILogger


def main():
    logger = CLILogger(component="start_ida_rpc", verbose=True)
    parser = argparse.ArgumentParser(
        description="IDA RPC HTTP Server 启动器",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python start_ida_rpc.py --idb D:/test.i64
  python start_ida_rpc.py --idb D:/test.i64 --port 8888
  python start_ida_rpc.py --host 0.0.0.0 --port 9999
        """
    )
    parser.add_argument("--idb", help="IDB 文件路径（可选）")
    parser.add_argument("--host", default="127.0.0.1", help="监听地址（默认: 127.0.0.1）")
    parser.add_argument("--port", type=int, default=9999, help="监听端口（默认: 9999）")
    parser.add_argument("--debug", action="store_true", help="启用 Flask 调试模式")
    args = parser.parse_args()

    logger.info("startup.begin", "IDA RPC Server 启动器")
    logger.info("startup.cwd", "工作目录", cwd=Path.cwd())
    
    # 启动服务器
    server = start_server(
        idb_path=args.idb,
        host=args.host,
        port=args.port,
        debug=args.debug
    )


if __name__ == "__main__":
    main()
