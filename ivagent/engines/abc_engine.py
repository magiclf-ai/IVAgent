#!/usr/bin/env python3
"""
Abc-Decompiler (Jadx-based) Engine Implementation

Provides static analysis capabilities using the Abc-Decompiler MCP Server.
"""

import logging
from typing import Optional, List, Dict, Any
import re

from .base_static_analysis_engine import (
    BaseStaticAnalysisEngine,
    FunctionDef,
    CallSite,
    CrossReference,
    VariableConstraint,
    TargetType,
    SearchOptions,
    SearchResult,
)
from ..models.callsite import CallsiteInfo
from ..backends.abc_decompiler import AbcDecompilerClient, DecompiledMethod

# Import SourceCodeEngine as fallback
from .source_code_engine import SourceCodeEngine

logger = logging.getLogger(__name__)


class AbcStaticAnalysisEngine(BaseStaticAnalysisEngine):
    """
    Abc-Decompiler Static Analysis Engine.
    
    Connects to an Abc-Decompiler MCP Server to perform static analysis on Java/Android code.
    """

    def __init__(
            self,
            target_path: Optional[str] = None,
            host: str = "http://127.0.0.1:8651/mcp",
            source_root: Optional[str] = None,
            llm_client: Optional[Any] = None,
            **kwargs
    ):
        """
        Initialize the engine.

        Args:
            target_path: Path to the target (optional, for reference)
            host: URL of the MCP server
            source_root: Source code root directory (for CallsiteAgent source analysis)
            llm_client: LLM client (for CallsiteAgent)
            **kwargs: Additional arguments
        """
        super().__init__(target_path, source_root=source_root, llm_client=llm_client, **kwargs)
        self.host = host
        self.client = AbcDecompilerClient(host)
        self._connected = False
        self._llm_client = llm_client
        self._source_root = source_root
        self._source_code_engine: Optional[SourceCodeEngine] = None

    async def _do_initialize(self):
        """Initialize the engine (connect to MCP server)."""
        try:
            await self.client.connect()
            self._connected = True
        except Exception as e:
            logger.error(f"Failed to connect to Abc-Decompiler MCP Server at {self.host}: {e}")
            logger.error("Please ensure the server is running: python jadx_mcp_server.py --http --port 3000")
            raise RuntimeError(f"Could not connect to Abc-Decompiler MCP Server: {e}") from e

    async def _do_close(self):
        """Close the engine (disconnect from MCP server)."""
        await self.client.close()
        self._connected = False
        # Close SourceCodeEngine fallback if initialized
        if self._source_code_engine:
            try:
                await self._source_code_engine._do_close()
            except Exception as e:
                logger.warning(f"Error closing SourceCodeEngine fallback: {e}")
            self._source_code_engine = None

    async def _ensure_connected(self):
        if not self._connected:
            await self.client.connect()
            self._connected = True

    async def _get_source_code_engine(self) -> Optional[SourceCodeEngine]:
        """Lazy initialization of SourceCodeEngine for fallback."""
        if self._source_code_engine is None and self._llm_client and self._source_root:
            try:
                self._source_code_engine = SourceCodeEngine(
                    source_root=self._source_root,
                    llm_client=self._llm_client
                )
                await self._source_code_engine._do_initialize()
            except Exception as e:
                logger.warning(f"Failed to initialize SourceCodeEngine fallback: {e}")
                return None
        return self._source_code_engine

    def _parse_signature(self, signature: str) -> tuple[str, str]:
        """
        Parse function signature to extract class name and method name.
        
        Supported formats:
        - com.example.Class.method
        - com.example.Class:method
        - Lcom/example/Class;->method
        """
        # Handle Smali/JNI style: Lcom/example/Class;->method
        if '->' in signature:
            parts = signature.split('->')
            class_part = parts[0]
            method_part = parts[1]
            # Remove L and ;
            if class_part.startswith('L') and class_part.endswith(';'):
                class_part = class_part[1:-1]

            class_name = class_part
            # Method might have signature like method(I)V
            if '(' in method_part:
                method_name = method_part.split('(')[0]
            else:
                method_name = method_part
            return class_name, method_name

        # Handle Dot notation: com.example.Class.method
        # This is ambiguous if we don't know where class ends and method begins.
        # We assume the last part is method name.
        if '.' in signature:
            parts = signature.rsplit('.', 1)
            return parts[0], parts[1]

        if ':' in signature:
            parts = signature.split(':')
            return parts[0], parts[1]

        # Fallback
        return "", signature

    def _extract_method_code(self, class_code: str, method_name: str) -> str:
        """
        Heuristically extract method definition from class code.
        Handles "public Object methodName(...)" format.
        """
        # Find start position
        # Pattern: public Object <method_name> (
        # We ensure it starts on a new line (ignoring whitespace) to avoid false positives
        pattern = re.compile(r'(?:^|\n)\s*public\s+Object\s+' + re.escape(method_name) + r'\s*\(', re.MULTILINE)

        match = pattern.search(class_code)
        if not match:
            return class_code

        # match.start() includes the newline/whitespace, we want the start of "public"
        # but capturing the indentation is fine for the output block.
        # Let's start from the match start, but if it starts with \n, skip it.
        start_pos = match.start()
        if class_code[start_pos] == '\n':
            start_pos += 1

        # Scan for matching brace
        idx = start_pos
        length = len(class_code)
        brace_depth = 0
        found_start = False
        in_string = False
        in_line_comment = False
        in_block_comment = False

        while idx < length:
            char = class_code[idx]

            if in_line_comment:
                if char == '\n':
                    in_line_comment = False
            elif in_block_comment:
                if char == '*' and idx + 1 < length and class_code[idx + 1] == '/':
                    in_block_comment = False
                    idx += 1
            elif in_string:
                if char == '\\':
                    idx += 1
                elif char == '"':
                    in_string = False
            else:
                if char == '"':
                    in_string = True
                elif char == '/' and idx + 1 < length:
                    if class_code[idx + 1] == '/':
                        in_line_comment = True
                        idx += 1
                    elif class_code[idx + 1] == '*':
                        in_block_comment = True
                        idx += 1
                elif char == '{':
                    brace_depth += 1
                    found_start = True
                elif char == '}':
                    brace_depth -= 1
                    if found_start and brace_depth == 0:
                        return class_code[start_pos:idx + 1]

            idx += 1

        return class_code[start_pos:]

    async def get_function_def(
            self,
            function_name: Optional[str] = None,
            function_identifier: Optional[str] = None,
            location: Optional[str] = None,
    ) -> Optional[FunctionDef]:
        """Get function definition (source code)."""
        await self._ensure_connected()

        target_class = ""
        target_method = ""

        if function_identifier:
            target_class, target_method = self._parse_signature(function_identifier)
        elif function_name:
            # This is risky without class name
            # We might need to search?
            # For now, return None if no class context
            if '.' in function_name:
                target_class, target_method = self._parse_signature(function_name)
            else:
                logger.warning(f"get_function_def: Cannot determine class for method {function_name}")

        try:
            # Fetch method source
            # Note: The server tool is get_method_by_name(class_name, method_name)
            # It returns a dict. We assume it contains 'code' or similar.
            result = await self.client.get_method_by_name(target_class, target_method)

            code = ""
            if isinstance(result, dict):
                code = result.get("code", "") or result.get("source", "") or str(result)
            elif isinstance(result, str):
                code = result

            # Heuristically extract method if we have the method name
            if code and target_method:
                code = self._extract_method_code(code, target_method)

            lines = code.splitlines()
            code_with_line_comment = ""
            for line_index, line in enumerate(lines):
                code_with_line_comment += f"[{line_index:4d}] {line}\n"

            return FunctionDef(
                signature=f"{target_class}.{target_method}",
                name=target_method,
                code=code_with_line_comment,
                file_path=f"{target_class.replace('.', '/')}.ts",  # Virtual path
                start_line=0,  # Unknown
                end_line=0  # Unknown
            )

        except Exception as e:
            logger.warning(f"AbcDecompiler failed for {target_class}.{target_method}: {e}, trying SourceCodeEngine fallback")

            # Fallback: Use SourceCodeEngine with pure text + LLM
            source_engine = await self._get_source_code_engine()
            if source_engine:
                try:
                    func_def = await source_engine.get_function_def(
                        function_identifier=f"{target_class}.{target_method}"
                    )
                    if func_def:
                        logger.info(f"SourceCodeEngine fallback succeeded for {target_class}.{target_method}")
                        return func_def
                except Exception as fallback_e:
                    logger.error(f"SourceCodeEngine fallback also failed: {fallback_e}")

            logger.error(f"Error getting function def for {target_class}.{target_method}: {e}")
            return None

    async def get_callee(
            self,
            function_identifier: str,
    ) -> List[CallSite]:
        """Get callees (calls made by this function)."""
        func_def = await self.get_function_def(function_identifier=function_identifier)
        if not func_def or not func_def.code:
            return []

        # Parse code using DecompiledMethod
        decompiled = DecompiledMethod(function_identifier, func_def.code)

        call_sites = []
        for call in decompiled.calls:
            call_sites.append(CallSite(
                caller_name=func_def.name,
                caller_identifier=function_identifier,
                callee_name=call.target_name,
                callee_identifier=call.target_signature,
                line_number=call.line_index + 1,  # 1-based
                call_context=call.call_text,
                arguments=call.arguments
            ))

        return call_sites

    async def get_caller(
            self,
            function_identifier: str,
    ) -> List[CallSite]:
        """Get callers (functions calling this function)."""
        # Current MCP server does not expose get_xrefs_to_method.
        # We cannot efficiently implement this.
        logger.warning("get_caller is not supported by current Abc-Decompiler backend (missing get_xrefs_to_method)")
        return []

    async def get_cross_reference(
            self,
            target_type: str,
            signature: str,
    ) -> Optional[CrossReference]:
        """Get cross references."""
        # Not supported
        logger.warning("get_cross_reference is not supported by current Abc-Decompiler backend")
        return None

    async def get_variable_constraints(
            self,
            function_identifier: str,
            var_name: str,
            line_number: Optional[int] = None,
    ) -> List[VariableConstraint]:
        """
        Get variable constraints.
        Not supported by current Abc-Decompiler backend.
        """
        return []

    async def _resolve_static_callsite(
            self,
            callsite: CallsiteInfo,
            caller_identifier: Optional[str] = None,
    ) -> Optional[str]:
        """
        [Implement BaseStaticAnalysisEngine] Static analysis: resolve function signature from callsite info.
        """
        # Abc-Decompiler backend currently does not support advanced callsite resolution
        return None

    async def search_symbol(
            self,
            query: str,
            options: Optional[SearchOptions] = None,
    ) -> List[SearchResult]:
        """
        异步搜索符号（类、方法、字段）

        通过 Abc-Decompiler 后端搜索匹配的类/方法/字段。
        支持子串匹配和正则表达式匹配。
        """
        from .base_static_analysis_engine import SymbolType

        await self._ensure_connected()

        if options is None:
            options = SearchOptions()

        try:
            # 获取所有类列表
            classes = await self.client.get_all_classes()
            if not isinstance(classes, list):
                return []

            results = []

            # 准备匹配模式
            if options.use_regex:
                try:
                    flags = 0 if options.case_sensitive else re.IGNORECASE
                    pattern = re.compile(query, flags)
                except re.error:
                    pattern = None
            else:
                pattern = None

            query_cmp = query if options.case_sensitive else query.lower()

            # 首先搜索匹配的类
            for class_info in classes:
                class_name = class_info.get("class_name", "") if isinstance(class_info, dict) else str(class_info)
                if not class_name:
                    continue

                # 检查类名匹配
                class_matched = False
                if options.use_regex and pattern:
                    class_matched = bool(pattern.search(class_name))
                else:
                    class_name_cmp = class_name if options.case_sensitive else class_name.lower()
                    class_matched = query_cmp in class_name_cmp

                if class_matched:
                    # 添加类作为搜索结果
                    match_score = 1.0 if class_name_cmp.startswith(query_cmp) else 0.8
                    results.append(SearchResult(
                        name=class_name,
                        signature=class_name,
                        symbol_type=SymbolType.CLASS,
                        file_path=f"{class_name.replace('.', '/')}.ts",
                        line=0,
                        match_score=match_score,
                        match_reason=f"Class name matches '{query}'"
                    ))

                # 获取类的方法
                try:
                    methods = await self.client.get_class_methods(class_name)
                    if not isinstance(methods, list):
                        continue
                except Exception:
                    continue

                for method in methods:
                    method_name = method.get("method_name", "") if isinstance(method, dict) else str(method)
                    signature = f"{class_name}.{method_name}"

                    matched = False
                    match_score = 0.5
                    match_reason = ""

                    # 检查方法名匹配
                    if options.use_regex and pattern:
                        if options.match_full_signature:
                            matched = bool(pattern.search(signature))
                        else:
                            matched = bool(pattern.search(method_name))
                        if matched:
                            match_score = 0.9
                            match_reason = f"Pattern matches method '{method_name}'"
                    else:
                        method_cmp = method_name if options.case_sensitive else method_name.lower()
                        sig_cmp = signature if options.case_sensitive else signature.lower()

                        if options.match_full_signature:
                            matched = query_cmp in sig_cmp
                            if matched:
                                match_reason = f"Signature contains '{query}'"
                        else:
                            matched = query_cmp in method_cmp
                            if matched:
                                match_reason = f"Method name contains '{query}'"

                        if matched:
                            if method_cmp.startswith(query_cmp):
                                match_score = 1.0
                            else:
                                match_score = 0.7

                    # 如果类名匹配但方法名不匹配，且 include_class_name 为 True
                    if not matched and class_matched and options.include_class_name:
                        matched = True
                        match_score = 0.6
                        match_reason = f"Class name contains '{query}'"

                    if matched:
                        results.append(SearchResult(
                            name=method_name,
                            signature=signature,
                            symbol_type=SymbolType.METHOD,
                            file_path=f"{class_name.replace('.', '/')}.ts",
                            line=0,
                            match_score=match_score,
                            match_reason=match_reason or f"Matches '{query}'"
                        ))

                # 获取类的字段
                try:
                    fields = await self.client.get_class_fields(class_name)
                    if isinstance(fields, list):
                        for field in fields:
                            field_name = field.get("field_name", "") if isinstance(field, dict) else str(field)
                            field_sig = f"{class_name}.{field_name}"

                            field_matched = False
                            if options.use_regex and pattern:
                                field_matched = bool(pattern.search(field_name))
                            else:
                                field_cmp = field_name if options.case_sensitive else field_name.lower()
                                field_matched = query_cmp in field_cmp

                            if field_matched:
                                results.append(SearchResult(
                                    name=field_name,
                                    signature=field_sig,
                                    symbol_type=SymbolType.FIELD,
                                    file_path=f"{class_name.replace('.', '/')}.ts",
                                    line=0,
                                    match_score=0.85 if field_cmp.startswith(query_cmp) else 0.65,
                                    match_reason=f"Field name matches '{query}'"
                                ))
                except Exception:
                    pass

            # 按匹配分数排序并分页
            results.sort(key=lambda x: x.match_score, reverse=True)
            start_idx = options.offset
            end_idx = start_idx + options.limit

            return results[start_idx:end_idx]

        except Exception as e:
            logger.warning(f"Search failed: {e}")
            return []
