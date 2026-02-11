#!/usr/bin/env python3
"""
IDA MCP 引擎实现

通过异步 JSON-RPC Client 连接 IDA RPC Server，实现高并发的 IDA 分析能力

架构:
    IDAEngine (当前进程)
        ↓ Async JSON-RPC over HTTP
    IDARPCServer (IDA 进程中)
        ↓ idaapi
    IDA Pro with Hex-Rays

特性:
    1. 全异步 IO 操作
    2. 支持批量并发请求
    3. 连接池管理
    4. 自动重试机制
"""

import os
import sys
import re
import time
import atexit
import asyncio
import aiohttp
from pathlib import Path
from typing import Dict, List, Optional, Any, AsyncIterator

from .base_static_analysis_engine import (
    FunctionDef,
    CallSite,
    CrossReference,
    VariableConstraint,
    BaseStaticAnalysisEngine,
    SearchOptions,
    SearchResult,
)

from ..models.callsite import CallsiteInfo


class IDAClient:
    """
    IDA RPC 客户端
    
    支持：
    - 异步 HTTP 请求
    - 连接池管理
    - 自动重试
    - 批量请求
    """

    def __init__(
            self,
            host: str = "127.0.0.1",
            port: int = 9999,
            timeout: int = 60,
            max_retries: int = 3,
            retry_delay: float = 1.0,
    ):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay

        self._session: Optional[aiohttp.ClientSession] = None
        self._url = f"http://{host}:{port}/rpc"
        self._request_id = 0
        self._lock = asyncio.Lock()

    async def connect(self) -> bool:
        """异步连接到 RPC Server"""
        if self._session is None:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            connector = aiohttp.TCPConnector(limit=100, limit_per_host=20)
            self._session = aiohttp.ClientSession(
                timeout=timeout,
                connector=connector,
            )

        # 测试连接
        try:
            result = await self.ping()
            return result is not None and result.get("status") == "ok"
        except Exception as e:
            print(f"[!] Failed to connect: {e}")
            return False

    async def disconnect(self):
        """异步断开连接"""
        if self._session:
            await self._session.close()
            self._session = None

    async def _get_request_id(self) -> int:
        """获取唯一的请求 ID"""
        async with self._lock:
            self._request_id += 1
            return self._request_id

    async def call(self, method: str, **kwargs) -> Any:
        """
        异步调用 RPC 方法
        
        参数:
            method: 方法名
            **kwargs: 方法参数
        
        返回:
            调用结果
        """
        if not self._session:
            raise RuntimeError("Client not connected")

        request_id = await self._get_request_id()
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": kwargs,
            "id": request_id,
        }

        last_error = None
        for attempt in range(self.max_retries):
            try:
                async with self._session.post(
                        self._url,
                        json=payload,
                ) as response:
                    if response.status != 200:
                        raise RuntimeError(f"HTTP {response.status}")

                    data = await response.json()

                    if "error" in data:
                        raise RuntimeError(f"RPC Error: {data['error']}")

                    return data.get("result")

            except Exception as e:
                last_error = e
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(self.retry_delay * (attempt + 1))
                continue

        raise last_error or RuntimeError("Max retries exceeded")

    async def batch_call(
            self,
            calls: List[tuple],
            max_concurrency: int = 10,
    ) -> List[Any]:
        """
        批量异步调用
        
        参数:
            calls: (method, kwargs) 元组列表
            max_concurrency: 最大并发数
        
        返回:
            结果列表
        """
        semaphore = asyncio.Semaphore(max_concurrency)

        async def _call_one(method: str, kwargs: dict) -> Any:
            async with semaphore:
                return await self.call(method, **kwargs)

        tasks = [_call_one(m, k) for m, k in calls]
        return await asyncio.gather(*tasks, return_exceptions=True)

    async def ping(self) -> Optional[Dict]:
        """测试连接"""
        try:
            return await self.call("ping")
        except:
            return None

    # ============ 便捷方法 ============

    async def get_idb_info(self) -> Dict[str, Any]:
        """获取 IDB 信息"""
        return await self.call("get_idb_info")

    async def decompile_function(self, address: str) -> Dict[str, Any]:
        """反编译函数"""
        return await self.call("decompile_function", address=address)

    async def get_function_info(self, address: str) -> Dict[str, Any]:
        """获取函数信息"""
        return await self.call("get_function_info", address=address)

    async def get_function_code(self, address: str) -> Dict[str, Any]:
        """获取函数汇编代码"""
        return await self.call("get_function_code", address=address)

    async def get_function_list(self, limit: int = 1000) -> List[Dict[str, Any]]:
        """获取函数列表"""
        return await self.call("get_function_list", limit=limit)

    async def get_callee(self, address: str) -> List[Dict[str, Any]]:
        """获取函数调用的子函数"""
        return await self.call("get_callee", address=address)

    async def get_caller(self, address: str) -> List[Dict[str, Any]]:
        """获取调用函数的父函数"""
        return await self.call("get_caller", address=address)

    async def get_xrefs_to(self, address: str) -> List[Dict[str, Any]]:
        """获取引用到指定地址的交叉引用"""
        return await self.call("get_xrefs_to", address=address)

    async def get_xrefs_from(self, address: str) -> List[Dict[str, Any]]:
        """获取从指定地址引用的交叉引用"""
        return await self.call("get_xrefs_from", address=address)

    async def get_strings(self, min_length: int = 4) -> List[Dict[str, Any]]:
        """获取字符串列表"""
        return await self.call("get_strings", min_length=min_length)

    async def __aenter__(self):
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.disconnect()


class IDAStaticAnalysisEngine(BaseStaticAnalysisEngine):
    """
    IDA MCP 引擎
    
    通过异步 JSON-RPC Client 连接 IDA RPC Server
    支持高并发分析场景
    """

    def __init__(
            self,
            target_path: Optional[str] = None,
            host: str = "127.0.0.1",
            port: int = 9999,
            timeout: int = 60,
            auto_connect: bool = True,
            max_concurrency: int = 10,
            source_root: Optional[str] = None,
            llm_client: Optional[Any] = None,
    ):
        """
        初始化异步 IDA 引擎
        
        参数:
            target_path: IDB 文件路径（用于信息展示）
            host: RPC Server 地址
            port: RPC Server 端口
            timeout: 连接超时时间
            auto_connect: 是否自动连接
            max_concurrency: 最大并发数
            source_root: 源代码根目录（用于 CallsiteAgent 源码分析）
            llm_client: LLM 客户端（用于 CallsiteAgent）
        """
        super().__init__(target_path, max_concurrency, source_root, llm_client)

        self.host = host
        self.port = port
        self.timeout = timeout
        self.auto_connect = auto_connect

        # 异步 RPC Client 实例
        self._client: Optional[IDAClient] = None

        # 异步缓存
        self._function_cache: Dict[str, FunctionDef] = {}
        self._cache_lock = asyncio.Lock()

    async def _do_initialize(self):
        """异步初始化引擎 - 连接到 IDA RPC Server"""
        if not self.auto_connect:
            return

        self._client = IDAClient(
            host=self.host,
            port=self.port,
            timeout=self.timeout,
        )

        print(f"[*] Connecting to IDA RPC Server at {self.host}:{self.port}...")
        if not await self._client.connect():
            raise RuntimeError(
                f"Failed to connect to IDA RPC Server at {self.host}:{self.port}\n"
                f"Please ensure the server is running in IDA:\n"
                f"  exec(open(r'server.py').read())\n"
                f"  server = start_server(port={self.port})"
            )

        # 获取 IDB 信息
        info = await self._client.get_idb_info()
        print(f"[*] Connected to IDA {info.get('ida_version')}")
        print(f"[*] Input file: {info.get('input_file')}")

    async def _do_close(self):
        """异步关闭引擎"""
        if self._client:
            await self._client.disconnect()
            # 给 aiohttp 一点时间完成资源清理
            await asyncio.sleep(0.1)
            print("[*] RPC Client disconnected")
            self._client = None

    async def _ensure_client(self):
        """确保 Client 已连接"""
        if self._client is None:
            raise RuntimeError("RPC Client not initialized")

    def _to_function_def(
            self,
            data: Dict[str, Any],
            callees: Optional[List[CallSite]] = None
    ) -> Optional[FunctionDef]:
        """
        将服务端返回的数据转换为 FunctionDef
        
        参数:
            data: 服务端返回的函数信息
            callees: 该函数调用的子函数列表（用于生成 callsite 元数据注释）
        """
        if not data or (isinstance(data, dict) and "error" in data):
            return None

        code: str = data.get("pseudocode", "")
        if not code:
            return None

        lines = code.splitlines()

        # 限制代码行数
        if len(lines) > 10000:
            lines = lines[:10000]

        # 构建带行号的代码
        code_with_line_comment = ""
        for line_index, line in enumerate(lines):
            code_with_line_comment += f"[{line_index:4d}] {line}\n"

        # 添加调用点元数据注释（帮助 LLM 识别反编译函数名和实际函数名的差异）
        call_comments = "// 函数中代码行与调用点签名信息如下\n"
        if callees:
            for i, callee in enumerate(callees):
                name = callee.callee_name
                signature = callee.callee_identifier
                line_number = callee.line_number
                arguments = callee.arguments if callee.arguments else []
                # 获取调用点的代码行（如果行号有效）
                callsite_code = ""
                if 0 <= line_number < len(lines):
                    callsite_code = lines[line_number].strip()

                call_comments += f"// <调用点_{i}> <name>{name}</name> <signature>{signature}</signature> <line>{line_number}</line> <callsite_code>{callsite_code}</callsite_code> <参数>{arguments}</参数> </调用点_{i}>\n"
        else:
            call_comments += "// (无调用点信息)\n"

        code = f"{call_comments}\n{code_with_line_comment}\n"

        return FunctionDef(
            signature=data.get("name", ""),
            name=data.get("name", ""),
            code=code,
            file_path=None,
            start_line=0,
            end_line=len(lines),
            parameters=[p.get("name", "") for p in data.get("parameters", [])],
            return_type=None,
            location=data.get("address"),
        )

    def _to_call_sites(self, data: List[Dict[str, Any]]) -> List[CallSite]:
        """将服务端返回的数据转换为 CallSite 列表"""
        if not isinstance(data, list):
            return []

        call_sites = []
        for item in data:
            if not item:
                continue
            try:
                call_sites.append(CallSite(
                    caller_name=item.get("caller", ""),
                    caller_identifier=item.get("caller", ""),
                    callee_name=item.get("callee", ""),
                    callee_identifier=item.get("callee", ""),
                    line_number=item.get("line_index", -1),
                    file_path=None,
                    call_context=item.get("call_address"),
                    arguments=item.get("arg_texts", []),
                ))
            except Exception as e:
                print(f"[!] Error converting call site: {e}")
                continue

        return call_sites

    # ============ AsyncBaseEngine 接口实现 ============

    async def get_function_def(
            self,
            function_name: Optional[str] = None,
            function_identifier: Optional[str] = None,
            location: Optional[str] = None,
    ) -> Optional[FunctionDef]:
        """
        异步获取函数定义
        
        直接透传给服务端的 get_function_info 或 decompile_function
        优先尝试反编译获取完整信息
        """
        await self._ensure_client()

        # 确定查询标识（地址或函数名）
        query = location or function_name or function_identifier
        if not query:
            return None

        # 检查缓存
        async with self._cache_lock:
            if query in self._function_cache:
                return self._function_cache[query]

        result = await self._client.get_function_info(query)
        if result and "error" not in result:
            # 获取 callees 信息用于生成 callsite 元数据
            callees = await self.get_callee(query)
            func_def = self._to_function_def(result, callees)
            if func_def:
                async with self._cache_lock:
                    self._function_cache[query] = func_def
                return func_def

        return None

    async def get_callee(self, function_identifier: str) -> List[CallSite]:
        """异步获取函数内调用的子函数"""
        await self._ensure_client()
        result = await self._client.get_callee(function_identifier)
        return self._to_call_sites(result) if isinstance(result, list) else []

    async def get_caller(self, function_identifier: str) -> List[CallSite]:
        """异步获取调用该函数的父函数"""
        await self._ensure_client()
        result = await self._client.get_caller(function_identifier)
        return self._to_call_sites(result) if isinstance(result, list) else []

    async def _resolve_static_callsite(
            self,
            callsite: CallsiteInfo,
            caller_identifier: Optional[str] = None,
    ) -> Optional[str]:
        """
        [实现基类方法] 静态分析：根据调用点信息解析函数签名
        
        实现策略：
        1. 如果提供了 caller_identifier，先获取调用者函数定义
        2. 从调用者的 callee 列表中查找匹配行号和函数名的调用
        3. 返回被调用函数的签名
        """
        await self._ensure_client()

        if not callsite.function_identifier:
            return None

        # 策略1: 如果有调用者标识符，从调用者上下文中解析
        if caller_identifier:
            try:
                # 获取调用者的 callee 列表
                callees = await self.get_callee(caller_identifier)

                # 在 callee 中查找匹配的行号和函数名
                for callee in callees:
                    # 匹配行号（允许一定的误差范围，因为 LLM 提供的行号可能不完全准确）
                    line_match = abs(callee.line_number - callsite.line_number) <= 2
                    # 匹配函数名
                    name_match = callee.callee_name == callsite.function_identifier

                    if line_match and name_match:
                        return callee.callee_identifier

                # 如果没有精确匹配，尝试只匹配函数名
                for callee in callees:
                    if callee.callee_name == callsite.function_identifier:
                        return callee.callee_identifier

            except Exception as e:
                print(f"[!] Error resolving callsite from caller context: {e}")

        # 策略2: 直接通过函数名搜索
        try:
            # 尝试直接获取函数信息
            func_info = await self._client.get_function_info(callsite.function_identifier)
            if func_info and "error" not in func_info:
                return func_info.get("name", callsite.function_identifier)
        except Exception:
            pass

        # 策略3: 搜索匹配函数名的函数
        try:
            matching_funcs = await self.search_symbol(callsite.function_identifier, limit=10)
            for func in matching_funcs:
                if callsite.function_identifier in func.name:
                    return func.signature
        except Exception:
            pass

        # 解析失败
        return None

    async def get_cross_reference(
            self,
            target_type: str,
            signature: str,
    ) -> Optional[CrossReference]:
        """异步获取交叉引用"""
        await self._ensure_client()

        xrefs = await self._client.get_xrefs_to(signature)
        if xrefs:
            return CrossReference(
                target_type=target_type,
                target_signature=signature,
                references=[x["from"] for x in xrefs],
            )
        return None

    async def get_variable_constraints(
            self,
            function_identifier: str,
            var_name: str,
            line_number: Optional[int] = None,
    ) -> List[VariableConstraint]:
        """异步获取变量约束条件"""
        # TODO: 服务端实现后透传
        return []

    async def search_symbol(
            self,
            query: str,
            options: Optional[SearchOptions] = None,
    ) -> List[SearchResult]:
        """
        异步搜索符号（函数）

        使用正则表达式匹配函数名
        """
        from .base_static_analysis_engine import SymbolType

        await self._ensure_client()

        if options is None:
            options = SearchOptions()

        # 获取所有函数
        all_funcs = await self._client.get_function_list(limit=100000)
        if not isinstance(all_funcs, list):
            return []

        # 准备正则表达式模式
        try:
            flags = 0 if options.case_sensitive else re.IGNORECASE
            pattern = re.compile(query, flags)
        except re.error:
            # 无效正则，返回空结果
            return []

        results = []

        for item in all_funcs:
            name = item.get("name", "")
            if not name:
                continue

            # 执行正则匹配
            if options.match_full_signature:
                match = pattern.search(name)
            else:
                # 只匹配函数名部分（去掉地址前缀等）
                match = pattern.search(name)

            if not match:
                continue

            func_def = await self.get_function_def(name)
            if func_def:
                results.append(SearchResult(
                    name=func_def.name,
                    signature=func_def.signature,
                    symbol_type=SymbolType.FUNCTION,
                    file_path=func_def.file_path,
                    line=func_def.start_line,
                    match_score=0.9,
                    match_reason=f"Name matches regex '{query}'"
                ))

        # 最后应用分页
        start_idx = options.offset
        end_idx = start_idx + options.limit

        return results[start_idx:end_idx]

    async def get_function_info(self, address: str) -> Optional[Dict[str, Any]]:
        """获取函数信息"""
        await self._ensure_client()
        return await self._client.get_function_info(address)

    async def get_function_list(self, limit: int = 1000) -> List[Dict[str, Any]]:
        """获取函数列表"""
        await self._ensure_client()
        return await self._client.get_function_list(limit=limit)

    async def get_strings(self, min_length: int = 4) -> List[Dict[str, Any]]:
        """获取字符串列表"""
        await self._ensure_client()
        return await self._client.get_strings(min_length=min_length)

    async def get_xrefs_to(self, address: str) -> List[Dict[str, Any]]:
        """获取引用到指定地址的交叉引用"""
        await self._ensure_client()
        return await self._client.get_xrefs_to(address)

    async def get_xrefs_from(self, address: str) -> List[Dict[str, Any]]:
        """获取从指定地址引用的交叉引用"""
        await self._ensure_client()
        return await self._client.get_xrefs_from(address)

    async def call(self, method: str, **kwargs) -> Any:
        """调用任意 RPC 方法"""
        await self._ensure_client()
        return await self._client.call(method, **kwargs)
