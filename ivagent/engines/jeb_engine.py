#!/usr/bin/env python3
"""
JEB 引擎实现

通过异步包装 JEB RPC Client，实现对 Android APK 的高并发静态分析能力

架构:
    JEBEngine (当前进程)
        ↓ Async JSON-RPC over HTTP
    JEB RPC Server (JEB 进程中)
        ↓ JEB API
    JEB Decompiler

特性:
    1. 全异步 IO 操作（通过线程池包装同步 JEB 调用）
    2. 支持批量并发请求
    3. 连接管理
    4. 自动重试机制
"""

import os
import sys
import asyncio
from pathlib import Path
from typing import Dict, List, Optional, Any
from concurrent.futures import ThreadPoolExecutor

from .base_static_analysis_engine import (
    FunctionDef,
    CallSite,
    CrossReference,
    VariableConstraint,
    BaseStaticAnalysisEngine,
)

from ..models.callsite import CallsiteInfo


class JEBClient:
    """
    JEB RPC 异步客户端
    
    包装同步的 JEBClient，通过线程池实现异步调用
    
    支持：
    - 异步 HTTP 请求（通过线程池）
    - 连接管理
    - 自动重试
    - 批量请求
    """

    def __init__(
            self,
            host: str = "127.0.0.1",
            port: int = 16161,
            timeout: int = 120,
            max_retries: int = 3,
            retry_delay: float = 1.0,
    ):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay

        self._sync_client = None
        self._executor = ThreadPoolExecutor(max_workers=10)
        self._connected = False

    def _get_sync_client(self):
        """获取或创建同步 JEB 客户端"""
        if self._sync_client is None:
            # 导入 JEB 客户端（放在这里避免循环导入）
            # sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "analyzers"))
            from .jeb_client import JEBClient as SyncJEBClient
            self._sync_client = SyncJEBClient(self.host, self.port, self.timeout)
        return self._sync_client

    async def connect(self) -> bool:
        """异步连接到 JEB RPC Server"""
        try:
            loop = asyncio.get_event_loop()
            client = self._get_sync_client()
            result = await loop.run_in_executor(self._executor, client.ping)
            self._connected = result == "pong"
            return self._connected
        except Exception as e:
            print(f"[!] Failed to connect to JEB: {e}")
            return False

    async def disconnect(self):
        """异步断开连接"""
        self._connected = False
        if self._executor:
            self._executor.shutdown(wait=False)

    async def _call_with_retry(self, method_name: str, *args, **kwargs) -> Any:
        """带重试机制的异步调用"""
        loop = asyncio.get_event_loop()
        client = self._get_sync_client()
        last_error = None

        for attempt in range(self.max_retries):
            try:
                method = getattr(client, method_name)
                result = await loop.run_in_executor(self._executor, method, *args, **kwargs)
                return result
            except Exception as e:
                last_error = e
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(self.retry_delay * (attempt + 1))
                continue

        raise last_error or RuntimeError(f"Max retries exceeded for {method_name}")

    async def ping(self) -> Optional[str]:
        """测试连接"""
        try:
            loop = asyncio.get_event_loop()
            client = self._get_sync_client()
            return await loop.run_in_executor(self._executor, client.ping)
        except:
            return None

    # ============ 便捷方法 ============

    async def get_method_decompiled_code(self, filepath: str, method_signature: str) -> str:
        """获取方法反编译代码"""
        return await self._call_with_retry("get_method_decompiled_code", filepath, method_signature)

    async def get_method_callees(self, filepath: str, method_signature: str) -> List[Dict[str, Any]]:
        """获取方法调用的子方法"""
        return await self._call_with_retry("get_method_callees", filepath, method_signature)

    async def get_method_callers(self, filepath: str, method_signature: str) -> List[Dict[str, Any]]:
        """获取调用该方法的父方法"""
        return await self._call_with_retry("get_method_callers", filepath, method_signature)

    async def get_field_callers(self, filepath: str, field_signature: str) -> List[Dict[str, Any]]:
        """获取访问字段的所有位置"""
        return await self._call_with_retry("get_field_callers", filepath, field_signature)

    async def get_class_methods(self, filepath: str, class_signature: str) -> List[str]:
        """获取类的所有方法"""
        return await self._call_with_retry("get_class_methods", filepath, class_signature)

    async def get_class_fields(self, filepath: str, class_signature: str) -> List[str]:
        """获取类的所有字段"""
        return await self._call_with_retry("get_class_fields", filepath, class_signature)

    async def get_superclass(self, filepath: str, class_signature: str) -> Optional[str]:
        """获取类的父类"""
        return await self._call_with_retry("get_superclass", filepath, class_signature)

    async def get_interfaces(self, filepath: str, class_signature: str) -> List[str]:
        """获取类实现的所有接口"""
        return await self._call_with_retry("get_interfaces", filepath, class_signature)

    async def get_manifest(self, filepath: str) -> str:
        """获取 APK 的 AndroidManifest.xml"""
        return await self._call_with_retry("get_manifest", filepath)

    async def get_all_exported_activities(self, filepath: str) -> List[str]:
        """获取所有导出的 Activity"""
        return await self._call_with_retry("get_all_exported_activities", filepath)

    async def check_java_identifier(self, filepath: str, identifier: str) -> List[Dict[str, Any]]:
        """检查标识符"""
        return await self._call_with_retry("check_java_identifier", filepath, identifier)

    async def __aenter__(self):
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.disconnect()


class JEBStaticAnalysisEngine(BaseStaticAnalysisEngine):
    """
    JEB 静态分析引擎
    
    通过异步包装连接 JEB RPC Server
    支持高并发 APK 分析场景
    """

    def __init__(
            self,
            target_path: Optional[str] = None,
            host: str = "127.0.0.1",
            port: int = 16161,
            timeout: int = 120,
            auto_connect: bool = True,
            max_concurrency: int = 10,
            source_root: Optional[str] = None,
            llm_client: Optional[Any] = None,
    ):
        """
        初始化异步 JEB 引擎
        
        参数:
            target_path: APK 文件路径（用于信息展示）
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
        self._client: Optional[JEBClient] = None

        # 异步缓存
        self._function_cache: Dict[str, FunctionDef] = {}
        self._cache_lock = asyncio.Lock()

    async def _do_initialize(self):
        """异步初始化引擎 - 连接到 JEB RPC Server"""
        if not self.auto_connect:
            return

        self._client = JEBClient(
            host=self.host,
            port=self.port,
            timeout=self.timeout,
        )

        print(f"[*] Connecting to JEB RPC Server at {self.host}:{self.port}...")
        if not await self._client.connect():
            raise RuntimeError(
                f"Failed to connect to JEB RPC Server at {self.host}:{self.port}\n"
                f"Please ensure JEB is running with the HTTP server enabled."
            )

        print(f"[*] Connected to JEB RPC Server")
        if self.target_path:
            print(f"[*] Target APK: {self.target_path}")

    async def _do_close(self):
        """异步关闭引擎"""
        if self._client:
            await self._client.disconnect()
            print("[*] JEB Client disconnected")
            self._client = None

    async def _ensure_client(self):
        """确保 Client 已连接"""
        if self._client is None:
            raise RuntimeError("JEB Client not initialized")

    def _to_function_def(self, signature: str, code: str, callees) -> Optional[FunctionDef]:
        """将 JEB 返回的数据转换为 FunctionDef"""
        if not code:
            return None

        lines = code.splitlines()

        # 限制代码行数
        if len(lines) > 10000:
            lines = lines[:10000]

        # 提取方法名
        name = signature
        if '->' in signature:
            name = signature.split('->')[1].split('(')[0]

        # 构建带行号的代码
        code_with_line_comment = ""
        for line_index, line in enumerate(lines):
            code_with_line_comment += f"[{line_index:4d}] {line}\n"

        call_comments = "// 函数中代码行与调用点签名信息如下\n"
        for i, callee in enumerate(callees):
            arguments = callee.get("arguments", [])
            line = callee.get("line", "")
            name = callee.get('method').get('name')
            signature = callee.get('method').get("signature", "")
            call_comments += f"// <调用点_{i}> <name>{name}</name> <signature>{signature}</signature> <callsite_code>{line}</callsite_code> <参数>{arguments}</参数> </调用点_{i}>\n"

        code = f"{call_comments}\n{code_with_line_comment}\n"

        return FunctionDef(
            signature=signature,
            name=name,
            code=code,
            file_path=self.target_path,
            start_line=0,
            end_line=len(lines),
            parameters=[],  # JEB API 不直接提供参数信息
            return_type=None,
            location=signature,  # JEB 使用签名作为位置标识
        )

    def _to_call_sites(self, data: List[Dict[str, Any]], is_callee: bool = True) -> List[CallSite]:
        """将 JEB 返回的数据转换为 CallSite 列表"""
        if not isinstance(data, list):
            return []

        call_sites = []
        for item in data:
            try:
                sig = item.get("method").get("signature", "")
                name = item.get("method").get("name", "")
                arguments = item.get("arguments", [])

                if is_callee:
                    # 当前函数调用其他函数
                    call_sites.append(CallSite(
                        caller_name="current",
                        caller_signature="current",
                        callee_name=name or sig,
                        callee_signature=sig,
                        line_number=item.get("line_index", -1),
                        file_path=self.target_path,
                        call_context=item.get("line", ""),
                        arguments=arguments,
                    ))
                else:
                    # 其他函数调用当前函数
                    call_sites.append(CallSite(
                        caller_name=name or sig,
                        caller_signature=sig,
                        callee_name="current",
                        callee_signature="current",
                        line_number=item.get("line_index", -1),
                        file_path=self.target_path,
                        call_context=item.get("line", ""),
                        arguments=arguments,
                    ))
            except Exception as e:
                print(f"[!] Error converting call site: {e}")
                continue

        return call_sites

    # ============ AsyncBaseEngine 接口实现 ============

    async def get_function_def(
            self,
            function_name: Optional[str] = None,
            function_signature: Optional[str] = None,
            location: Optional[str] = None,
    ) -> Optional[FunctionDef]:
        """
        异步获取函数定义
        
        使用 JEB 获取 Java 方法的反编译代码
        """
        await self._ensure_client()

        if not self.target_path:
            raise ValueError("APK path not set. Use set_target() first.")

        # 确定查询标识（签名优先）
        query = function_signature or location or function_name
        if not query:
            return None

        # 如果 query 是方法名，需要解析为签名
        if '->' not in query and function_name:
            # 尝试通过方法名查找签名
            results = await self._client.check_java_identifier(self.target_path, function_name)
            if results:
                for result in results:
                    if result.get("type") == "method":
                        query = result.get("signature")
                        break

        if '->' not in query:
            # 仍然无法解析为方法签名
            return None

        # 检查缓存
        async with self._cache_lock:
            if query in self._function_cache:
                return self._function_cache[query]

        # 获取反编译代码
        code = await self._client.get_method_decompiled_code(self.target_path, query)
        if code:
            callees = await self._client.get_method_callees(self.target_path, query)
            func_def = self._to_function_def(query, code, callees)
            if func_def:
                async with self._cache_lock:
                    self._function_cache[query] = func_def
                return func_def

        return None

    async def get_callee(self, function_signature: str) -> List[CallSite]:
        """异步获取函数内调用的子函数"""
        await self._ensure_client()

        if not self.target_path:
            return []

        result = await self._client.get_method_callees(self.target_path, function_signature)
        return self._to_call_sites(result, is_callee=True)

    async def get_caller(self, function_signature: str) -> List[CallSite]:
        """异步获取调用该函数的父函数"""
        await self._ensure_client()

        if not self.target_path:
            return []

        result = await self._client.get_method_callers(self.target_path, function_signature)
        return self._to_call_sites(result, is_callee=False)

    async def _resolve_static_callsite(
            self,
            callsite: CallsiteInfo,
            caller_signature: Optional[str] = None,
    ) -> Optional[str]:
        """
        [实现基类方法] 静态分析：根据调用点信息解析函数签名
        
        实现策略：
        1. 如果提供了 caller_signature，先获取调用者函数定义
        2. 从调用者的 callee 列表中查找匹配行号和函数名的调用
        3. 返回被调用函数的签名
        """
        await self._ensure_client()

        if not callsite.function_signature:
            return None

        # 策略1: 如果有调用者签名，从调用者上下文中解析
        if caller_signature:
            try:
                # 获取调用者的 callee 列表
                callees = await self.get_callee(caller_signature)

                # 在 callee 中查找匹配的行号和函数名
                for callee in callees:
                    sig_match = callee.callee_signature == callsite.function_signature
                    if sig_match:
                        return callee.callee_signature


            except Exception as e:
                print(f"[!] Error resolving callsite from caller context: {e}")

        # 策略2: 直接通过函数名搜索
        try:
            if self.target_path:
                results = await self._client.check_java_identifier(self.target_path, callsite.function_signature)
                for result in results:
                    if result.get("type") == "method":
                        return result.get("signature", callsite.function_signature)
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

        if not self.target_path:
            return None

        references = []

        if target_type == "method":
            # 获取方法调用者
            refs = await self._client.get_method_callers(self.target_path, signature)
            for ref in refs:
                references.append({
                    "from": ref.get("signature", ""),
                    "details": ref.get("details", ""),
                    "line_index": ref.get("line_index", -1),
                })

        elif target_type == "field":
            # 获取字段访问者
            refs = await self._client.get_field_callers(self.target_path, signature)
            for ref in refs:
                references.append({
                    "from": ref.get("signature", ""),
                    "details": ref.get("details", ""),
                    "address": ref.get("address", ""),
                })

        if references:
            return CrossReference(
                target_type=target_type,
                target_signature=signature,
                references=references,
            )
        return None

    async def get_variable_constraints(
            self,
            function_signature: str,
            var_name: str,
            line_number: Optional[int] = None,
    ) -> List[VariableConstraint]:
        """异步获取变量约束条件"""
        # TODO: 需要 JEB 提供更详细的变量分析能力
        return []

    async def search_functions(self, query: str, limit: int = 10) -> List[FunctionDef]:
        """异步搜索函数"""
        await self._ensure_client()

        if not self.target_path:
            return []

        try:
            results = await self._client.check_java_identifier(self.target_path, query)
            function_defs = []

            for result in results:
                if result.get("type") == "method":
                    sig = result.get("signature", "")
                    # 获取函数定义
                    func_def = await self.get_function_def(function_signature=sig)
                    if func_def:
                        function_defs.append(func_def)
                    if len(function_defs) >= limit:
                        break

            return function_defs
        except Exception:
            return []

    async def get_class_info(self, class_signature: str) -> Optional[Dict[str, Any]]:
        """获取类信息"""
        await self._ensure_client()

        if not self.target_path:
            return None

        try:
            methods = await self._client.get_class_methods(self.target_path, class_signature)
            fields = await self._client.get_class_fields(self.target_path, class_signature)
            superclass = await self._client.get_superclass(self.target_path, class_signature)
            interfaces = await self._client.get_interfaces(self.target_path, class_signature)

            return {
                "signature": class_signature,
                "methods": methods,
                "fields": fields,
                "superclass": superclass,
                "interfaces": interfaces,
            }
        except Exception:
            return None
