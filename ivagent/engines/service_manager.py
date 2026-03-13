#!/usr/bin/env python3
"""
引擎 RPC 服务生命周期管理器
"""

import asyncio
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Optional

import aiohttp

from ..core.cli_logger import CLILogger


ENGINE_DEFAULT_PORTS = {
    "ida": 9999,
    "jeb": 16161,
    "abc": 8651,
}


class EngineServiceManager:
    """
    引擎 RPC 服务生命周期管理器。
    """

    def __init__(self, logger: Optional[CLILogger] = None):
        self._logger = logger or CLILogger(component="EngineServiceManager")
        self._managed_processes: list[subprocess.Popen] = []

    async def ensure_service(
        self,
        engine_type: str,
        target_path: Optional[str] = None,
        host: str = "127.0.0.1",
        port: int = 0,
        **_: Any,
    ) -> Dict[str, Any]:
        """
        确保引擎 RPC 服务已运行。
        """

        normalized_engine = engine_type.lower()
        if normalized_engine in {"source", "source_code", "sourcecode"}:
            return {"host": host, "port": 0, "started": False}

        if port == 0:
            port = ENGINE_DEFAULT_PORTS.get(normalized_engine, 9999)

        if await self.health_check(normalized_engine, host, port):
            self._logger.info(
                "service.already_running",
                "引擎服务已在运行",
                engine=normalized_engine,
                host=host,
                port=port,
            )
            return {"host": host, "port": port, "started": False}

        self._logger.info(
            "service.starting",
            "正在启动引擎服务",
            engine=normalized_engine,
            host=host,
            port=port,
        )

        if normalized_engine == "ida":
            await self._start_ida_service(target_path=target_path, host=host, port=port)
        elif normalized_engine == "jeb":
            await self._start_jeb_service(target_path=target_path, host=host, port=port)
        elif normalized_engine in {"abc", "abc-decompiler"}:
            await self._start_abc_service(target_path=target_path, host=host, port=port)
        else:
            raise ValueError(f"Unknown engine type: {engine_type}")

        await self._wait_for_ready(normalized_engine, host, port, timeout=60)
        return {"host": host, "port": port, "started": True}

    async def health_check(self, engine_type: str, host: str, port: int) -> bool:
        """检查引擎服务是否可用。"""

        try:
            if engine_type == "ida":
                return await self._health_check_http(host, port)
            if engine_type == "jeb":
                return await self._health_check_tcp(host, port)
            if engine_type in {"abc", "abc-decompiler"}:
                return await self._health_check_http(host, port, path="/mcp")
            return False
        except Exception:
            return False

    async def _health_check_http(self, host: str, port: int, path: str = "/") -> bool:
        url = f"http://{host}:{port}{path}"
        try:
            timeout = aiohttp.ClientTimeout(total=5)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url) as response:
                    return response.status < 500
        except Exception:
            return False

    async def _health_check_tcp(self, host: str, port: int) -> bool:
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=5)
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False

    async def _start_ida_service(self, target_path: Optional[str], host: str, port: int) -> None:
        script_path = Path(__file__).parent.parent.parent / "start_ida_rpc.py"
        command = [sys.executable, str(script_path), "--host", host, "--port", str(port)]
        if target_path:
            command.extend(["--idb", target_path])

        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self._managed_processes.append(process)

    async def _start_jeb_service(self, target_path: Optional[str], host: str, port: int) -> None:
        raise RuntimeError(
            f"JEB 服务需要手动启动。请在 JEB 中启动 MCP 服务，监听 {host}:{port}"
        )

    async def _start_abc_service(self, target_path: Optional[str], host: str, port: int) -> None:
        raise RuntimeError(
            f"ABC-Decompiler 服务需要手动启动。请启动 ABC-Decompiler MCP 服务，监听 {host}:{port}"
        )

    async def _wait_for_ready(self, engine_type: str, host: str, port: int, timeout: int = 60) -> None:
        deadline = asyncio.get_event_loop().time() + timeout
        while asyncio.get_event_loop().time() < deadline:
            if await self.health_check(engine_type, host, port):
                self._logger.success(
                    "service.ready",
                    "引擎服务已就绪",
                    engine=engine_type,
                    host=host,
                    port=port,
                )
                return
            await asyncio.sleep(2)

        raise TimeoutError(f"引擎服务启动超时 ({timeout}s): {engine_type} @ {host}:{port}")

    async def shutdown_all(self) -> None:
        """关闭所有受管理的子进程。"""

        for process in self._managed_processes:
            if process.poll() is not None:
                continue
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
        self._managed_processes.clear()
