#!/usr/bin/env python3

import idapro
import sys
import json
import traceback
from typing import Dict, Any, Optional, Callable
from pathlib import Path

# 添加项目路径到 sys.path (hexray_scripts)
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent.parent))

from flask import Flask, request, jsonify

from ivagent.backends.ida.rpc.protocol import Request, Response, ErrorCode
from ivagent.core.cli_logger import CLILogger

# 复用 backends/ida/api 的能力
from ivagent.backends.ida.api import (
    # IDB 信息
    get_idb_info,
    # 函数列表
    get_function_list_dict as get_function_list,
    # 函数详细信息
    get_function_info,
    # 调用关系
    get_callees,
    get_callers,
    # 汇编代码
    get_function_code_text,
    # 字符串
    get_strings_dict as get_strings,
    # 交叉引用
    get_xrefs_to_dict as get_xrefs_to,
    get_xrefs_from_dict as get_xrefs_from,
)
from ivagent.backends.ida.api.function import _parse_address


class IDARPCServer:
    """
    IDA JSON-RPC HTTP 服务器
    
    在 IDA 进程中运行，通过 Flask HTTP 服务提供分析能力
    
    参数:
        idb_path: IDB 文件路径，如果提供则自动加载
        host: 监听地址
        port: 监听端口
    """

    def __init__(self, idb_path: Optional[str] = None, host: str = "127.0.0.1", port: int = 9999):
        self.idb_path = idb_path
        self.host = host
        self.port = port
        self._app = Flask(__name__)
        self._running = False
        self._idb_loaded = False
        self._debug = False
        self._logger = CLILogger(component="IDARPCServer", verbose=True)

        # 方法注册表
        self._methods: Dict[str, Callable] = {}
        self._register_methods()

        # 注册路由
        self._setup_routes()

    def _log_exception(self, event: str, exc: Exception) -> None:
        self._logger.error(event, str(exc), error_type=type(exc).__name__)
        if self._debug:
            for line in traceback.format_exc().splitlines():
                if line.strip():
                    self._logger.debug("ida.rpc.traceback", line)

    def _setup_routes(self):
        """设置 Flask 路由"""

        @self._app.route('/')
        def index():
            """根路径 - 服务状态"""
            return jsonify({
                "status": "running",
                "service": "IDA JSON-RPC Server",
                "version": "1.0.0",
                "endpoints": ["/rpc", "/health", "/methods"]
            })

        @self._app.route('/health')
        def health():
            """健康检查"""
            try:
                import idaapi
                return jsonify({
                    "status": "healthy",
                    "ida_version": idaapi.get_kernel_version(),
                })
            except Exception as e:
                return jsonify({"status": "unhealthy", "error": str(e)}), 500

        @self._app.route('/methods')
        def list_methods():
            """列出可用方法"""
            methods_info = {}
            for name, func in self._methods.items():
                methods_info[name] = {
                    "description": func.__doc__ or "No description",
                }
            return jsonify({"methods": methods_info})

        @self._app.route('/rpc', methods=['POST'])
        def rpc_endpoint():
            """JSON-RPC 端点"""
            try:
                data = request.get_json(force=True, silent=True)
                if data is None:
                    return jsonify(Response.error(
                        None, ErrorCode.PARSE_ERROR, "Invalid JSON"
                    ).to_dict()), 400

                response = self._handle_request(data)
                return jsonify(response.to_dict())

            except Exception as e:
                self._log_exception("ida.rpc.endpoint_failed", e)
                return jsonify(Response.error(
                    None, ErrorCode.INTERNAL_ERROR, str(e)
                ).to_dict()), 500

        @self._app.route('/api/<method_name>', methods=['POST'])
        def api_endpoint(method_name: str):
            """RESTful API 端点 - 直接调用方法"""
            try:
                params = request.get_json(force=True, silent=True) or {}

                method = self._methods.get(method_name)
                if not method:
                    return jsonify({
                        "error": f"Method not found: {method_name}"
                    }), 404

                result = method(**params)
                return jsonify({"result": result})

            except Exception as e:
                self._log_exception("ida.api.endpoint_failed", e)
                return jsonify({"error": str(e)}), 500

    def _register_methods(self):
        """注册 RPC 方法"""
        self._methods = {
            # 基础
            "ping": self._ping,
            "get_idb_info": self._get_idb_info,

            # 函数分析
            "decompile_function": self._decompile_function,
            "get_function_info": self._get_function_info,
            "get_function_code": self._get_function_code,

            # 调用关系
            "get_callee": self._get_callee,
            "get_caller": self._get_caller,

            # 其他
            "get_function_list": self._get_function_list,
            "get_strings": self._get_strings,
            "get_xrefs_to": self._get_xrefs_to,
            "get_xrefs_from": self._get_xrefs_from,
        }

    def _handle_request(self, data: Dict) -> Response:
        """处理 JSON-RPC 请求"""
        try:
            req = Request.from_dict(data)
        except Exception as e:
            return Response.error(None, ErrorCode.PARSE_ERROR, str(e))

        method_name = req.method
        params = req.params
        req_id = req.id

        # 查找方法
        method = self._methods.get(method_name)
        if not method:
            return Response.error(req_id, ErrorCode.METHOD_NOT_FOUND,
                                  f"Method not found: {method_name}")

        # 执行方法
        try:
            result = method(**params)
            return Response.success(req_id, result)
        except Exception as e:
            self._log_exception("ida.rpc.handle_request_failed", e)
            return Response.error(req_id, ErrorCode.INTERNAL_ERROR, str(e))

    def _load_idb(self) -> bool:
        """
        加载 IDA 数据库
        
        返回:
            是否加载成功
        """
        if not self.idb_path:
            return True

        if self._idb_loaded:
            return True

        try:
            idb_file = Path(self.idb_path)
            if not idb_file.exists():
                self._logger.error("ida.rpc.idb_not_found", "IDB 文件不存在", path=self.idb_path)
                return False

            self._logger.info("ida.rpc.open_db", "打开数据库", path=self.idb_path)
            idapro.open_database(str(idb_file), run_auto_analysis=True)
            self._idb_loaded = True
            self._logger.success("ida.rpc.db_opened", "数据库打开成功")
            return True

        except Exception as e:
            self._log_exception("ida.rpc.open_db_failed", e)
            return False

    def start(self, debug: bool = False) -> bool:
        """
        启动服务器（在主线程中阻塞运行）
        
        参数:
            debug: 是否启用 Flask 调试模式
        
        返回:
            是否成功启动（实际阻塞直到服务器停止）
        """
        self._debug = debug
        # 先加载 IDB（如果指定了）
        if self.idb_path and not self._load_idb():
            self._logger.error("ida.rpc.start_failed", "加载 IDB 失败，服务器未启动")
            return False

        try:
            self._running = True
            self._logger.success("ida.rpc.starting", "IDA RPC Server 启动", url=f"http://{self.host}:{self.port}")
            self._logger.info("ida.rpc.endpoints", "可用端点", endpoints="/,/health,/methods,/rpc,/api/<name>")
            self._logger.info("ida.rpc.stop_hint", "使用 Ctrl+C 停止服务")

            # 在主线程中运行 Flask（阻塞）
            self._app.run(
                host=self.host,
                port=self.port,
                debug=debug,
                threaded=False,  # 禁用多线程，使用单线程模式
                use_reloader=False  # 禁用重载器，避免在 IDA 中出问题
            )

            return True

        except KeyboardInterrupt:
            self._logger.info("ida.rpc.stopped_by_user", "用户中断，服务停止")
            self._running = False
            return True
        except Exception as e:
            self._log_exception("ida.rpc.start_exception", e)
            return False

    def stop(self):
        """
        停止服务器
        
        注意: Flask 的内置服务器没有干净的停止方式，
        通常通过 Ctrl+C 在主线程中中断
        """
        self._running = False
        self._logger.info("ida.rpc.stop_requested", "收到停止请求")
        self._logger.info("ida.rpc.stop_note", "请使用 Ctrl+C 进行干净停止")

    # ============ RPC 方法实现 ============
    # 所有方法都复用 backends.ida.api 的能力

    def _ping(self) -> Dict[str, Any]:
        """测试连接"""
        import idaapi
        return {
            "status": "ok",
            "ida_version": idaapi.get_kernel_version(),
        }

    def _get_idb_info(self) -> Dict[str, Any]:
        """获取 IDB 信息"""
        return get_idb_info()

    def _decompile_function(self, address: str) -> Dict[str, Any]:
        """反编译函数"""
        ea = _parse_address(address)
        info = get_function_info(ea)

        if not info:
            raise Exception(f"Failed to decompile function at {address}")

        return {
            "address": hex(info.ea),
            "function_name": info.name,
            "pseudocode": "\n".join(info.pseudocode),
        }

    def _get_function_info(self, address: str) -> Dict[str, Any]:
        """获取函数信息"""
        ea = _parse_address(address)
        info = get_function_info(ea)

        if not info:
            raise Exception(f"Function not found at {address}")

        return {
            "address": hex(info.ea),
            "name": info.name,
            "pseudocode": "\n".join(info.pseudocode),
            "signature": info.signature,
            "return_type": info.return_type,
            "parameters": [
                {
                    "name": p.name,
                    "type": p.type_str,
                }
                for p in info.parameters
            ],
        }

    def _get_function_code(self, address: str) -> Dict[str, Any]:
        """获取函数汇编代码"""
        result = get_function_code_text(address)

        if not result:
            raise Exception(f"Function not found at {address}")

        return result

    def _get_callee(self, address: str) -> list:
        """获取函数调用的子函数"""
        callees = get_callees(address)
        return [
            {
                "caller": c.caller,
                "callee": c.callee,
                "callee_address": f"0x{c.callee_address:X}",
                "call_address": f"0x{c.call_address:X}",
                "line_index": c.line_index,
                "arg_texts": c.arg_texts or [],
            }
            for c in callees
        ]

    def _get_caller(self, address: str) -> list:
        """获取调用该函数的父函数"""
        callers = get_callers(address)
        return [
            {
                "callee": c.callee,
                "caller": c.caller,
                "caller_address": f"0x{c.caller_address:X}",
                "call_address": f"0x{c.call_address:X}",
            }
            for c in callers
        ]

    def _get_function_list(self, limit: int = 1000) -> list:
        """获取函数列表"""
        return get_function_list(limit)

    def _get_strings(self, min_length: int = 4) -> list:
        """获取字符串列表"""
        return get_strings(min_length)

    def _get_xrefs_to(self, address: str) -> list:
        """获取引用到指定地址的交叉引用"""
        return get_xrefs_to(address)

    def _get_xrefs_from(self, address: str) -> list:
        """获取从指定地址引用的交叉引用"""
        return get_xrefs_from(address)


# 全局服务器实例
_server_instance: Optional[IDARPCServer] = None


def start_server(
        idb_path: Optional[str] = None,
        host: str = "127.0.0.1",
        port: int = 9999,
        debug: bool = False
) -> IDARPCServer:
    """
    启动 IDA RPC 服务器（在主线程中阻塞运行）
    
    参数:
        idb_path: IDB 文件路径（可选，如果提供则自动加载）
        host: 监听地址（默认 127.0.0.1）
        port: 监听端口（默认 9999）
        debug: 是否启用 Flask 调试模式
    
    返回:
        IDARPCServer 实例（服务器停止后返回）
    
    示例:
        # 方式 1: 自动加载 IDB 并启动服务器
        server = start_server(idb_path="/path/to/sample.idb", port=9999)
        
        # 方式 2: 手动加载 IDB 后启动
        idapro.open_database("/path/to/sample.idb", run_auto_analysis=True)
        server = start_server(port=9999)
        
        # 服务器会在主线程阻塞，按 Ctrl+C 停止
    """
    global _server_instance

    # 停止已有的服务器
    if _server_instance:
        _server_instance.stop()

    _server_instance = IDARPCServer(idb_path=idb_path, host=host, port=port)
    _server_instance.start(debug=debug)

    return _server_instance


def stop_server():
    """停止服务器"""
    global _server_instance
    if _server_instance:
        _server_instance.stop()
        _server_instance = None


# 如果直接运行此脚本，启动服务器
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="IDA RPC HTTP Server")
    parser.add_argument("--idb", help="IDB file path to open")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind")
    parser.add_argument("--port", type=int, default=9999, help="Port to bind")
    parser.add_argument("--debug", action="store_true", help="Enable Flask debug mode")
    args = parser.parse_args()

    # 启动服务器（阻塞模式）
    server = start_server(
        idb_path=args.idb,
        host=args.host,
        port=args.port,
        debug=args.debug
    )
