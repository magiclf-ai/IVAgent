#!/usr/bin/env python3
"""
SourceCodeEngine - 基于 LLM Agent + Tool Call 的源码分析引擎
"""

import os
import json
import subprocess
import uuid
from typing import List, Optional, Any, Union
from pathlib import Path

from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage, AIMessage, BaseMessage
from langchain_openai import ChatOpenAI

from .base_static_analysis_engine import (
    FunctionDef,
    CallSite,
    CrossReference,
    VariableConstraint,
    BaseStaticAnalysisEngine,
)
from ..models.callsite import CallsiteInfo

# 导入 ToolBasedLLMClient
try:
    from ..core.tool_llm_client import ToolBasedLLMClient
except ImportError:
    ToolBasedLLMClient = None

# 导入 Agent 日志系统
try:
    from ..core.agent_logger import get_agent_log_manager, AgentStatus
except ImportError:
    get_agent_log_manager = None
    AgentStatus = None


class SourceCodeEngine(BaseStaticAnalysisEngine):
    """
    基于 LLM Agent 的源码分析引擎
    
    所有分析通过 ToolBasedLLMClient + Tool Call 循环实现：
    - 工具函数: search_code, read_file, list_directory (docstring 定义描述)
    - LLM 驱动: ToolBasedLLMClient 处理 bind_tools 和调用循环
    - 智能分析: LLM 自主决定如何搜索、读取、分析代码
    """

    def __init__(
            self,
            target_path: Optional[str] = None,
            max_concurrency: int = 10,
            source_root: Optional[str] = None,
            llm_client: Optional[Any] = None,
            max_iterations: int = 30,
    ):
        """
        初始化源码分析引擎
        
        参数:
            target_path: 分析目标路径
            max_concurrency: 最大并发数
            source_root: 源代码根目录
            llm_client: LLM 客户端 (ChatOpenAI 或 ToolBasedLLMClient)
            max_iterations: Tool Call 最大迭代次数
        """
        super().__init__(target_path, max_concurrency, source_root, llm_client)

        if llm_client is None:
            raise ValueError("llm_client is required for SourceCodeEngine")

        self.source_root = Path(source_root or target_path or ".").resolve()
        self.max_iterations = max_iterations
        
        # Agent 日志系统
        self.agent_id = str(uuid.uuid4())
        self._agent_logger = get_agent_log_manager() if get_agent_log_manager else None

        # 包装 LLM 客户端
        if ToolBasedLLMClient and isinstance(llm_client, ChatOpenAI):
            self._tool_client = ToolBasedLLMClient(
                llm_client, 
                verbose=False,
                agent_id=self.agent_id,
                log_metadata={"agent_type": "SourceCodeEngine"}
            )
        elif ToolBasedLLMClient and isinstance(llm_client, ToolBasedLLMClient):
            self._tool_client = llm_client
            # 更新 agent_id
            self._tool_client.agent_id = self.agent_id
            if not self._tool_client.log_metadata:
                self._tool_client.log_metadata = {}
            self._tool_client.log_metadata["agent_type"] = "SourceCodeEngine"
        else:
            self._tool_client = llm_client

    # ==========================================================================
    # 工具函数 (docstring 定义工具描述，自动被 bind_tools 识别)
    # 注意: 不使用 Returns: 部分，因为 LangChain 可能无法正确解析
    # ==========================================================================

    def search_code(self, query: str, path_filter: Optional[str] = None) -> str:
        """
        Search for text in source files using ripgrep (rg).

        Args:
            query: The text string to search for (treated as literal string, not regex).
            path_filter: Optional glob pattern to filter files (e.g., "*.c", "src/*.java").

        Returns:
            Formatted search results with file paths, line numbers, and matching content.
        """
        try:
            cmd = [
                "rg", "-n", "--no-heading", "--fixed-strings",
                "-C", "3",  # 3 lines of context
                str(query), str(self.source_root)
            ]

            if path_filter:
                cmd.extend(["-g", path_filter])

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=30
            )

            if result.returncode not in [0, 1]:  # 0=found, 1=not found
                return f"Search error: {result.stderr}"

            lines = result.stdout.strip().split('\n') if result.stdout else []
            if not lines or not lines[0]:
                return f"No matches found for: '{query}'"

            # Format results
            formatted = [f"Search results for: '{query}'", "=" * 60]

            for line in lines[:50]:  # Limit to 50 results
                if not line:
                    continue
                parts = line.split(':', 2)
                if len(parts) >= 3:
                    file_path, line_num, content = parts[0], parts[1], parts[2]
                    formatted.append(f"{file_path}:{line_num} | {content}")

            if len(lines) > 50:
                formatted.append(f"\n... and {len(lines) - 50} more matches")

            return "\n".join(formatted)

        except subprocess.TimeoutExpired:
            return f"Error: Search timed out for: '{query}'"
        except FileNotFoundError:
            return "Error: ripgrep (rg) not found. Please install ripgrep."
        except Exception as e:
            return f"Error searching code: {str(e)}"

    def read_file(self, file_path: str, start_line: int, end_line: int) -> str:
        """
        Read a specific range of lines from a file.

        Args:
            file_path: Path to the file (relative to source_root or absolute).
            start_line: Start line number (1-based, inclusive).
            end_line: End line number (1-based, inclusive).

        Returns:
            File content with line numbers and context header.
        """
        try:
            # Resolve path
            if os.path.isabs(file_path):
                full_path = Path(file_path)
            else:
                full_path = self.source_root / file_path

            full_path = full_path.resolve()

            # Security check
            try:
                full_path.relative_to(self.source_root)
            except ValueError:
                return f"Error: Access denied. Path outside source root."

            if not full_path.exists():
                return f"Error: File not found: {file_path}"

            with open(full_path, 'r', encoding='utf-8', errors='replace') as f:
                lines = f.readlines()

            total_lines = len(lines)
            start_idx = max(0, start_line - 1)
            end_idx = min(total_lines, end_line)

            if start_idx >= end_idx:
                return f"File: {file_path}\nInvalid range [{start_line}:{end_line}], total lines: {total_lines}"

            output = [
                f"File: {file_path}",
                f"Lines: {start_idx + 1} - {end_idx} (of {total_lines})",
                "=" * 60
            ]

            for i in range(start_idx, end_idx):
                output.append(f"{i + 1:4d} | {lines[i].rstrip()}")

            return "\n".join(output)

        except Exception as e:
            return f"Error reading file: {str(e)}"

    def list_directory(self, dir_path: str = ".") -> str:
        """
        List contents of a directory (files and subdirectories).

        Args:
            dir_path: Directory path (relative to source_root or absolute). Defaults to current directory.

        Returns:
            List of subdirectories and files with sizes.
        """
        try:
            if os.path.isabs(dir_path):
                full_path = Path(dir_path)
            else:
                full_path = self.source_root / dir_path

            full_path = full_path.resolve()

            # Security check
            try:
                full_path.relative_to(self.source_root)
            except ValueError:
                return f"Error: Access denied. Path outside source root."

            if not full_path.exists():
                return f"Error: Directory not found: {dir_path}"

            if not full_path.is_dir():
                return f"Error: Not a directory: {dir_path}"

            entries = list(full_path.iterdir())
            dirs = sorted([e for e in entries if e.is_dir()], key=lambda x: x.name)
            files = sorted([e for e in entries if e.is_file()], key=lambda x: x.name)

            output = [f"Directory: {dir_path}", "=" * 60]

            if dirs:
                output.append(f"\nSubdirectories ({len(dirs)}):")
                for d in dirs:
                    output.append(f"  [DIR]  {d.name}")

            if files:
                output.append(f"\nFiles ({len(files)}):")
                for f in files:
                    size = f.stat().st_size
                    size_str = f"{size:,} bytes" if size < 1024 * 1024 else f"{size / 1024 / 1024:.2f} MB"
                    output.append(f"  [FILE] {f.name:<50} ({size_str})")

            return "\n".join(output)

        except Exception as e:
            return f"Error listing directory: {str(e)}"

    # ==========================================================================
    # LLM Agent 核心 - 使用 ToolBasedLLMClient
    # ==========================================================================

    async def _run_analysis(
            self,
            system_prompt: str,
            user_prompt: str,
            finish_tool: Optional[Any] = None,
            target: str = ""
    ) -> dict:
        """
        运行 LLM 分析循环
        
        使用 ToolBasedLLMClient.atool_call 处理 Tool Call 循环
        """
        tools = [self.search_code, self.read_file, self.list_directory]
        if finish_tool:
            tools.append(finish_tool)

        messages = [HumanMessage(content=user_prompt)]
        
        # 记录执行开始
        llm_calls = 0
        if self._agent_logger and AgentStatus:
            self._agent_logger.log_execution_start(
                agent_id=self.agent_id,
                agent_type="SourceCodeEngine",
                target_function=target or "source_analysis",
                parent_id=None,
                call_stack=[],
                metadata={
                    "system_prompt": system_prompt[:500],
                    "user_prompt": user_prompt[:500],
                    "tools": [t.__name__ for t in tools]
                }
            )

        try:
            # 使用 ToolBasedLLMClient
            if hasattr(self._tool_client, 'atool_call'):
                result = await self._tool_client.atool_call(
                    messages=messages,
                    tools=tools,
                    system_prompt=system_prompt
                )

                if not result.success:
                    error_msg = result.error or "LLM call failed"
                    self._log_execution_end(False, error_msg, llm_calls)
                    return {"error": error_msg}

                # 处理 Tool Call 循环
                all_tool_calls = []
                for _ in range(self.max_iterations):
                    llm_calls += 1
                    if result.tool_calls:
                        all_tool_calls.extend(result.tool_calls)

                        # 添加 AI message
                        tool_calls_data = [{
                            "name": tc["name"],
                            "args": tc["args"],
                            "id": tc.get("id", f"call_{i}")
                        } for i, tc in enumerate(result.tool_calls)]
                        messages.append(AIMessage(content=result.content or "", tool_calls=tool_calls_data))

                        # 执行工具
                        for tc in result.tool_calls:
                            tool_name = tc["name"]
                            args = tc["args"]
                            tool_id = tc.get("id", "unknown")

                            # 检查是否是 finish 工具
                            if finish_tool and tool_name == finish_tool.__name__:
                                self._log_execution_end(True, "Analysis completed", llm_calls)
                                return {
                                    "success": True,
                                    "result": args,
                                    "tool_calls": all_tool_calls
                                }

                            # 执行工具
                            output = ""
                            if tool_name == "search_code":
                                output = self.search_code(**args)
                            elif tool_name == "read_file":
                                output = self.read_file(**args)
                            elif tool_name == "list_directory":
                                output = self.list_directory(**args)
                            else:
                                output = f"Unknown tool: {tool_name}"

                            messages.append(ToolMessage(content=str(output), tool_call_id=tool_id))

                        # 继续下一轮
                        result = await self._tool_client.atool_call(
                            messages=messages,
                            tools=tools,
                            system_prompt=system_prompt
                        )
                    else:
                        # 没有 tool call，返回文本结果
                        self._log_execution_end(True, "Analysis completed (text response)", llm_calls)
                        return {
                            "success": True,
                            "content": result.content,
                            "tool_calls": all_tool_calls
                        }

                error_msg = f"Max iterations ({self.max_iterations}) reached"
                self._log_execution_end(False, error_msg, llm_calls)
                return {"error": error_msg}

            else:
                # 直接使用 LLM bind_tools 模式
                llm = self._tool_client
                llm_with_tools = llm.bind_tools(tools)

                messages_with_system: List[BaseMessage] = [SystemMessage(content=system_prompt)] + messages

                for _ in range(self.max_iterations):
                    llm_calls += 1
                    response = await llm_with_tools.ainvoke(messages_with_system)

                    tool_calls = getattr(response, 'tool_calls', None)

                    if tool_calls:
                        messages_with_system.append(response)

                        for tc in tool_calls:
                            tool_name = tc.get('name', '')
                            args = tc.get('args', {})
                            tool_id = tc.get('id', 'unknown')

                            if finish_tool and tool_name == finish_tool.__name__:
                                self._log_execution_end(True, "Analysis completed", llm_calls)
                                return {
                                    "success": True,
                                    "result": args
                                }

                            output = ""
                            if tool_name == "search_code":
                                output = self.search_code(**args)
                            elif tool_name == "read_file":
                                output = self.read_file(**args)
                            elif tool_name == "list_directory":
                                output = self.list_directory(**args)
                            else:
                                output = f"Unknown tool: {tool_name}"

                            messages_with_system.append(ToolMessage(content=str(output), tool_call_id=tool_id))
                    else:
                        self._log_execution_end(True, "Analysis completed (text response)", llm_calls)
                        return {
                            "success": True,
                            "content": response.content
                        }

                error_msg = f"Max iterations ({self.max_iterations}) reached"
                self._log_execution_end(False, error_msg, llm_calls)
                return {"error": error_msg}
                
        except Exception as e:
            error_msg = str(e)
            self._log_execution_end(False, error_msg, llm_calls)
            return {"error": error_msg}
    
    def _log_execution_end(self, success: bool, summary: str, llm_calls: int):
        """记录执行结束日志"""
        if self._agent_logger and AgentStatus:
            status = AgentStatus.COMPLETED if success else AgentStatus.FAILED
            self._agent_logger.log_execution_end(
                agent_id=self.agent_id,
                status=status,
                llm_calls=llm_calls,
                summary=summary,
                error_message=None if success else summary
            )

    # ==========================================================================
    # BaseStaticAnalysisEngine 接口实现
    # ==========================================================================

    async def _do_initialize(self):
        """异步初始化引擎"""
        if not self.source_root.exists():
            raise ValueError(f"Source root does not exist: {self.source_root}")
        print(f"[*] SourceCodeEngine initialized: {self.source_root}")
        print(f"[*] Agent ID: {self.agent_id}")

    async def _do_close(self):
        """异步关闭引擎"""
        print("[*] SourceCodeEngine closed")

    async def get_function_def(
            self,
            function_name: Optional[str] = None,
            function_signature: Optional[str] = None,
            location: Optional[str] = None,
    ) -> Optional[FunctionDef]:
        """通过 LLM Agent 获取函数定义"""
        query = function_signature or function_name or location
        if not query:
            return None

        def finish_analysis(
                found: bool,
                name: str = "",
                signature: str = "",
                file_path: str = "",
                start_line: int = 0,
                end_line: int = 0,
                code: str = "",
                parameters: list = None,
                return_type: str = "",
                reason: str = ""
        ):
            """
            Complete the analysis and report the function definition result.
            
            Args:
                found: Whether the function definition was found.
                name: Function name.
                signature: Full function signature (return type, name, parameters).
                file_path: Relative path to the file containing the function.
                start_line: Start line number (1-based).
                end_line: End line number (1-based).
                code: Complete function code with line numbers.
                parameters: List of parameter dicts with 'name' and 'type' keys.
                return_type: Return type of the function.
                reason: Explanation if not found.
            """
            pass

        system_prompt = """You are an expert code analyst. Find and extract a complete function definition.

Your workflow:
1. Use search_code to find the function definition
2. Use read_file to examine the file content
3. Identify the complete function boundaries
4. Call finish_analysis with the complete function information

Guidelines:
- Read enough context to identify the complete function (from definition to closing brace)
- Extract accurate line numbers
- Include complete function code with original line numbers
- Parse parameters with their types"""

        user_prompt = f"Find the complete function definition for: {query}\n\nSource root: {self.source_root}"

        result = await self._run_analysis(system_prompt, user_prompt, finish_analysis, target=f"get_function_def:{query}")

        if result.get("success") and result.get("result"):
            data = result["result"]
            if data.get("found"):
                return FunctionDef(
                    signature=data.get("signature", query),
                    name=data.get("name", query),
                    code=data.get("code", ""),
                    file_path=data.get("file_path", ""),
                    start_line=data.get("start_line", 0),
                    end_line=data.get("end_line", 0),
                    parameters=data.get("parameters", []),
                    return_type=data.get("return_type") or None,
                    location=f"{data.get('file_path', '')}:{data.get('start_line', 0)}",
                )

        return None

    async def get_callee(
            self,
            function_signature: str,
    ) -> List[CallSite]:
        """通过 LLM Agent 获取函数内调用的子函数"""

        def finish_analysis(calls: list = None):
            """
            Report all function calls found within the target function.
            
            Args:
                calls: List of call dicts, each containing:
                    - callee_name: Name of the called function
                    - line_number: Line number where the call occurs
                    - context: The actual code line containing the call
                    - arguments: List of argument strings (optional)
            """
            pass

        system_prompt = """You are an expert code analyst. Analyze a function and find all function calls within it.

Your workflow:
1. Use search_code to find the target function
2. Use read_file to read the complete function code
3. Identify ALL function calls (exclude control flow keywords: if, while, for, switch, return, sizeof)
4. Call finish_analysis with the list of calls

Guidelines:
- Include the line number for each call
- Include the actual code line as context
- List the arguments if they can be determined"""

        user_prompt = f"Find all function calls within: {function_signature}\n\nSource root: {self.source_root}"

        result = await self._run_analysis(system_prompt, user_prompt, finish_analysis, target=f"get_callee:{function_signature}")

        if result.get("success") and result.get("result"):
            calls = result["result"].get("calls", [])
            caller_name = function_signature.split('(')[0].split()[-1].strip()

            return [
                CallSite(
                    caller_name=caller_name,
                    caller_signature=function_signature,
                    callee_name=c.get("callee_name", ""),
                    callee_signature=c.get("callee_name", ""),
                    line_number=c.get("line_number", 0),
                    file_path="",
                    call_context=c.get("context", ""),
                    arguments=c.get("arguments", []),
                )
                for c in calls
            ]

        return []

    async def get_caller(
            self,
            function_signature: str,
    ) -> List[CallSite]:
        """通过 LLM Agent 获取调用该函数的父函数"""
        func_name = function_signature.split('(')[0].split()[-1].strip()

        def finish_analysis(callers: list = None):
            """
            Report all functions that call the target function.
            
            Args:
                callers: List of caller dicts, each containing:
                    - caller_name: Name of the calling function
                    - caller_signature: Full signature of caller (optional)
                    - file_path: Path to the file
                    - line_number: Line number of the call
                    - context: The actual code line containing the call
            """
            pass

        system_prompt = """You are an expert code analyst. Find all functions that call a specific target function.

Your workflow:
1. Use search_code to find all occurrences of the target function name
2. For each occurrence, use read_file to examine context
3. Determine if it's an actual call (not definition, comment, or string)
4. Identify the containing function (caller)
5. Call finish_analysis with all callers

Exclude:
- The function's own definition
- Comments mentioning the function
- String literals containing the function name"""

        user_prompt = f"Find all functions that call: {func_name}\n\nSource root: {self.source_root}"

        result = await self._run_analysis(system_prompt, user_prompt, finish_analysis, target=f"get_caller:{func_name}")

        if result.get("success") and result.get("result"):
            callers = result["result"].get("callers", [])

            return [
                CallSite(
                    caller_name=c.get("caller_name", ""),
                    caller_signature=c.get("caller_signature", c.get("caller_name", "")),
                    callee_name=func_name,
                    callee_signature=function_signature,
                    line_number=c.get("line_number", 0),
                    file_path=c.get("file_path", ""),
                    call_context=c.get("context", ""),
                    arguments=[],
                )
                for c in callers
            ]

        return []

    async def get_cross_reference(
            self,
            target_type: str,
            signature: str,
    ) -> Optional[CrossReference]:
        """通过 LLM Agent 获取交叉引用"""

        def finish_analysis(references: list = None):
            """
            Report all references to the target symbol.
            
            Args:
                references: List of reference dicts, each containing:
                    - file_path: Path to the file
                    - line: Line number
                    - content: The line content
                    - type: Type of reference (definition|call|reference|comment)
            """
            pass

        system_prompt = """You are an expert code analyst. Find all references to a specific symbol.

Your workflow:
1. Use search_code to find all occurrences
2. Classify each occurrence by type
3. Call finish_analysis with all references

Reference types:
- definition: Where the symbol is defined
- call: Where the symbol is called/invoked
- reference: Where the symbol is referenced but not called
- comment: Where the symbol appears in comments"""

        user_prompt = f"Find all cross-references for {target_type}: {signature}\n\nSource root: {self.source_root}"

        result = await self._run_analysis(system_prompt, user_prompt, finish_analysis, target=f"get_cross_reference:{signature}")

        if result.get("success") and result.get("result"):
            refs = result["result"].get("references", [])

            return CrossReference(
                target_type=target_type,
                target_signature=signature,
                references=[
                    {
                        "file": r.get("file_path", ""),
                        "line": r.get("line", 0),
                        "content": r.get("content", ""),
                        "type": r.get("type", "reference")
                    }
                    for r in refs
                ]
            )

        return None

    async def get_variable_constraints(
            self,
            function_signature: str,
            var_name: str,
            line_number: Optional[int] = None,
    ) -> List[VariableConstraint]:
        """通过 LLM Agent 获取变量约束"""

        def finish_analysis(constraints: list = None):
            """
            Report all constraints for the target variable.
            
            Args:
                constraints: List of constraint dicts, each containing:
                    - line_number: Line where constraint appears
                    - constraint: Description of the constraint
                    - type: Type of constraint (null_check|range_check|type_check|other)
            """
            pass

        system_prompt = """You are an expert code analyst. Analyze variable constraints in a function.

Your workflow:
1. Use search_code to find the target function
2. Use read_file to read the function code
3. Find all places where the variable is used
4. Identify constraints (conditions, checks, validations)
5. Call finish_analysis with all constraints

Constraint types:
- null_check: Checks if variable is null/not null
- range_check: Checks if variable is within a range
- type_check: Checks variable type
- other: Other types of constraints"""

        user_prompt = f"Analyze variable '{var_name}' in function '{function_signature}'"
        if line_number:
            user_prompt += f" (focus around line {line_number})"
        user_prompt += f"\n\nSource root: {self.source_root}"

        result = await self._run_analysis(system_prompt, user_prompt, finish_analysis, target=f"get_variable_constraints:{var_name}")

        if result.get("success") and result.get("result"):
            constraints = result["result"].get("constraints", [])

            return [
                VariableConstraint(
                    var_name=var_name,
                    var_type=None,
                    constraints=[c.get("constraint", "")],
                    source=c.get("type", "analysis"),
                    line_number=c.get("line_number", 0)
                )
                for c in constraints
            ]

        return []

    async def _resolve_static_callsite(
            self,
            callsite: CallsiteInfo,
            caller_signature: Optional[str] = None,
    ) -> Optional[str]:
        """通过 LLM Agent 解析调用点"""
        if not callsite.function_signature:
            return None

        func_name = callsite.function_signature.split('(')[0].strip()

        def finish_analysis(resolved: bool, signature: str = "", reason: str = ""):
            """
            Report the resolved function signature.
            
            Args:
                resolved: Whether the signature was successfully resolved.
                signature: The resolved full signature.
                reason: Explanation if not resolved.
            """
            pass

        system_prompt = """You are an expert code analyst. Resolve a function call to its complete signature.

Your workflow:
1. If caller is provided, examine the call context
2. Otherwise, search for the function definition
3. Call finish_analysis with the resolved signature"""

        user_prompt = f"Resolve function call: {callsite.function_signature}\nLocation: {callsite.file_path}:{callsite.line_number}"
        if caller_signature:
            user_prompt += f"\nCalled from: {caller_signature}"
        user_prompt += f"\n\nSource root: {self.source_root}"

        result = await self._run_analysis(system_prompt, user_prompt, finish_analysis, target=f"_resolve_static_callsite:{func_name}")

        if result.get("success") and result.get("result"):
            data = result["result"]
            if data.get("resolved"):
                return data.get("signature")

        return None

    async def search_functions(
            self,
            query: str,
            limit: int = 10,
    ) -> List[FunctionDef]:
        """通过 LLM Agent 搜索函数"""

        def finish_analysis(functions: list = None):
            """
            Report matching functions.
            
            Args:
                functions: List of function dicts, each containing:
                    - name: Function name
                    - signature: Full signature
                    - file_path: Path to file
                    - line: Line number
            """
            pass

        system_prompt = """You are an expert code analyst. Search for functions matching a query.

Your workflow:
1. Use search_code to find potential matches
2. Examine each match to confirm it's a function definition
3. Call finish_analysis with all matching functions"""

        user_prompt = f"Search for functions matching: {query}\nReturn up to {limit} results\n\nSource root: {self.source_root}"

        result = await self._run_analysis(system_prompt, user_prompt, finish_analysis, target=f"search_functions:{query}")

        if result.get("success") and result.get("result"):
            funcs = result["result"].get("functions", [])[:limit]

            results = []
            for f in funcs:
                func_def = await self.get_function_def(function_name=f.get("name"))
                if func_def:
                    results.append(func_def)

            return results

        return []
