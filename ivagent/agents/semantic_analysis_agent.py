#!/usr/bin/env python3
"""
SemanticAnalysisAgent - 语义理解分析 Agent

接收自然语言描述的代码分析需求，通过 Tool Call 循环自主探索和分析代码，
结合基础代码探索（grep/read_file）和高级静态分析能力完成深度语义分析。
"""

import os
import subprocess
import uuid
from typing import Dict, List, Optional, Any
from pathlib import Path

from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage, AIMessage

from .base import BaseAgent
from .prompts import SEMANTIC_ANALYSIS_SYSTEM_PROMPT
from ..engines.base_static_analysis_engine import BaseStaticAnalysisEngine, SearchOptions
# 导入 ToolBasedLLMClient
try:
    from ..core.tool_llm_client import ToolBasedLLMClient
except ImportError:
    ToolBasedLLMClient = None

# 导入日志系统
try:
    from ..core.agent_logger import get_agent_log_manager, AgentStatus
except ImportError:
    get_agent_log_manager = None
    AgentStatus = None


class SemanticAnalysisAgent(BaseAgent):
    """
    语义理解分析 Agent
    
    接收自然语言描述的代码分析需求，通过 Tool Call 循环自主探索代码，
    利用基础代码探索工具和高级静态分析能力完成深度分析。
    
    Attributes:
        engine: 静态分析引擎，提供高级分析能力
        llm_client: LLM 客户端
        source_root: 源码根目录（用于基础工具）
        max_iterations: 最大迭代次数
        agent_id: Agent 唯一标识
        enable_logging: 是否启用日志记录
    """

    def __init__(
        self,
        engine: BaseStaticAnalysisEngine,
        llm_client: Any,
        source_root: Optional[Path] = None,
        max_iterations: int = 20,
        verbose: bool = False,
        enable_logging: bool = True,
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None,
    ):
        """
        初始化语义分析 Agent
        
        Args:
            engine: 静态分析引擎实例
            llm_client: LLM 客户端
            source_root: 源码根目录（可选，用于基础代码探索）
            max_iterations: Tool Call 最大迭代次数
            verbose: 是否打印详细日志
            enable_logging: 是否启用日志记录
            session_id: 会话 ID
            agent_id: Agent ID（可选，自动生成）
        """
        super().__init__(
            engine=engine,
            llm_client=llm_client,
            max_iterations=max_iterations,
            verbose=verbose,
        )
        
        # 确定源码根目录
        self.source_root = source_root
        if self.source_root is None:
            # 尝试从引擎获取
            self.source_root = getattr(engine, 'source_root', None)
        if self.source_root is None:
            self.source_root = getattr(engine, '_source_root', None)
        if self.source_root is None:
            self.source_root = Path(".")
        
        # 日志配置
        self.enable_logging = enable_logging
        self.session_id = session_id
        self.agent_id = agent_id or f"semantic_analysis_{uuid.uuid4().hex[:8]}"
        self._agent_log_manager = get_agent_log_manager() if (enable_logging and get_agent_log_manager) else None
        
        # 初始化 ToolBasedLLMClient（启用 LLM 日志）
        if ToolBasedLLMClient:
            if not isinstance(llm_client, ToolBasedLLMClient):
                self._tool_client = ToolBasedLLMClient(
                    llm=llm_client,
                    max_retries=3,
                    retry_delay=1.0,
                    verbose=verbose,
                    enable_logging=enable_logging,
                    session_id=session_id,
                    agent_id=self.agent_id,
                    log_metadata={
                        "agent_type": "SemanticAnalysisAgent",
                    },
                )
            else:
                self._tool_client = llm_client
        else:
            raise RuntimeError("ToolBasedLLMClient is required")
        
        self.log(f"SemanticAnalysisAgent initialized (agent_id={self.agent_id})")

    # ==========================================================================
    # 基础代码探索工具（类似 SourceCodeEngine）
    # ==========================================================================

    def search_code(self, query: str, path_filter: Optional[str] = None) -> str:
        """Search for text in source files using ripgrep (rg).

        Parameters:
            query: The text string to search for (treated as literal string, not regex).
            path_filter: Optional glob pattern to filter files (e.g., "*.c", "src/*.java").
        """
        # Returns: Formatted search results with file paths, line numbers, and matching content.
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
        """Read a specific range of lines from a file.

        Parameters:
            file_path: Path to the file (relative to source_root or absolute).
            start_line: Start line number (1-based, inclusive).
            end_line: End line number (1-based, inclusive).
        """
        # Returns: File content with line numbers and context header.
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
                return "Error: Access denied. Path outside source root."

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
        """List contents of a directory (files and subdirectories).

        Parameters:
            dir_path: Directory path (relative to source_root or absolute). Defaults to current directory.
        """
        # Returns: List of subdirectories and files with sizes.
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
                return "Error: Access denied. Path outside source root."

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
    # 高级静态分析工具（来自 Engine 接口）
    # ==========================================================================

    async def get_function_def(self, function_identifier: str) -> str:
        """获取函数的完整定义（签名、参数、代码）。

        Parameters:
            function_identifier: 函数标识符或函数名
        """
        # Returns: 函数定义信息，包含签名、参数、代码等
        try:
            func_def = await self.engine.get_function_def(function_identifier=function_identifier)
            if func_def is None:
                return f"Function not found: {function_identifier}"
            
            result = [
                f"Function: {func_def.name}",
                f"Signature: {func_def.signature}",
                f"Location: {func_def.location or 'N/A'}",
                f"Parameters: {func_def.parameters}",
                f"Return Type: {func_def.return_type or 'N/A'}",
                "=" * 60,
                func_def.code if func_def.code else "(No code available)",
            ]
            return "\n".join(result)
        except Exception as e:
            return f"Error getting function definition: {str(e)}"

    async def get_callee(self, function_identifier: str) -> str:
        """获取函数内调用的所有子函数。

        Parameters:
            function_identifier: 函数标识符
        """
        # Returns: 子函数调用列表
        try:
            call_sites = await self.engine.get_callee(function_identifier)
            if not call_sites:
                return f"No callees found for: {function_identifier}"
            
            result = [f"Callees of {function_identifier}:", "=" * 60]
            for cs in call_sites:
                result.append(f"  Line {cs.line_number}: {cs.callee_name}")
                result.append(f"    Context: {cs.call_context or 'N/A'}")
            return "\n".join(result)
        except Exception as e:
            return f"Error getting callees: {str(e)}"

    async def get_caller(self, function_identifier: str) -> str:
        """获取调用该函数的所有父函数。

        Parameters:
            function_identifier: 函数标识符
        """
        # Returns: 父函数调用列表
        try:
            call_sites = await self.engine.get_caller(function_identifier)
            if not call_sites:
                return f"No callers found for: {function_identifier}"
            
            result = [f"Callers of {function_identifier}:", "=" * 60]
            for cs in call_sites:
                result.append(f"  From {cs.caller_name} at line {cs.line_number}")
                result.append(f"    Context: {cs.call_context or 'N/A'}")
            return "\n".join(result)
        except Exception as e:
            return f"Error getting callers: {str(e)}"

    async def get_xref(self, target: str, target_type: str = "function") -> str:
        """获取目标（函数/变量）的交叉引用。

        Parameters:
            target: 目标名称或签名
            target_type: 目标类型 (function, variable)
        """
        # Returns: 交叉引用列表
        try:
            xref = await self.engine.get_cross_reference(target_type, target)
            if xref is None or not xref.references:
                return f"No cross-references found for: {target}"
            
            result = [f"Cross-references for {target}:", "=" * 60]
            for ref in xref.references[:20]:  # Limit to 20
                result.append(f"  [{ref.get('type', 'ref')}] {ref.get('file', 'N/A')}:{ref.get('line', 0)}")
                result.append(f"    {ref.get('content', 'N/A')}")
            return "\n".join(result)
        except Exception as e:
            return f"Error getting cross-references: {str(e)}"

    async def search_symbol(
            self,
            pattern: str,
            limit: int = 10,
            offset: int = 0,
            case_sensitive: bool = False,
    ) -> str:
        """根据模式搜索符号（函数、类、变量等）。

        Parameters:
            pattern: 搜索模式（Python 正则表达式）
            limit: 返回结果数量限制
            offset: 结果起始偏移量，返回 [offset, offset + limit) 范围内的结果
            case_sensitive: 是否区分大小写，默认为 False（忽略大小写）
        """
        # Returns: 匹配的符号列表
        try:
            # 验证正则表达式有效性
            import re
            flags = 0 if case_sensitive else re.IGNORECASE
            try:
                re.compile(pattern, flags)
            except re.error as e:
                return f"Invalid regex pattern: {str(e)}"

            search_results = await self.engine.search_symbol(
                query=pattern,
                options=SearchOptions(
                    limit=limit,
                    offset=offset,
                    case_sensitive=case_sensitive,
                    use_regex=True,
                )
            )
            if not search_results:
                return f"No symbols found matching: {pattern}"

            result = [f"Symbols matching '{pattern}':", "=" * 60]
            for i, sr in enumerate(search_results, offset + 1):
                result.append(f"  #{i} [{sr.symbol_type.value}] {sr.name}")
                result.append(f"    Signature: {sr.signature}")
                result.append(f"    File: {sr.file_path or 'N/A'}:{sr.line or 0}")
            return "\n".join(result)
        except Exception as e:
            return f"Error searching symbols: {str(e)}"

    # ==========================================================================
    # 完成工具
    # ==========================================================================

    def finish_analysis(self, result: str) -> str:
        """完成分析并返回文本化结果。

        Parameters:
            result: 分析结果描述，包含核心发现、关键证据和相关代码位置

        Returns:
            格式化后的分析结果文本
        """
        return f"=== 分析结果 ===\n\n{result}"

    # ==========================================================================
    # 核心分析方法
    # ==========================================================================

    async def analyze(
        self,
        query: str,
        context: Optional[str] = None,
    ) -> str:
        """
        执行语义分析

        Args:
            query: 自然语言分析需求
            context: 可选上下文

        Returns:
            分析结果字符串
        """
        self.log(f"Starting analysis for query: {query[:100]}...")
        
        # 更新 ToolBasedLLMClient 的元数据以包含 target_function (query 的前50字符)
        target_function = query[:50] if len(query) <= 50 else query[:50] + "..."
        if isinstance(self._tool_client, ToolBasedLLMClient):
            self._tool_client.log_metadata["target_function"] = target_function
        
        # 记录 Agent 执行日志开始
        agent_log = None
        if self._agent_log_manager:
            agent_log = self._agent_log_manager.log_execution_start(
                agent_id=self.agent_id,
                agent_type="SemanticAnalysisAgent",
                target_function=target_function,
                metadata={
                    "query": query[:200],
                    "has_context": bool(context),
                    "max_iterations": self.max_iterations,
                }
            )
        
        # 构建消息
        system_prompt = SEMANTIC_ANALYSIS_SYSTEM_PROMPT

        user_prompt = f"""
## 分析需求

{query}

"""
        if context:
            user_prompt += f"""## 上下文信息

{context}

"""

        messages = [HumanMessage(content=user_prompt)]
        
        # 准备工具列表
        tools = [
            self.search_code,
            self.read_file,
            self.list_directory,
            self.get_function_def,
            self.get_callee,
            self.get_caller,
            self.get_xref,
            self.search_symbol,
            self.finish_analysis,
        ]

        # 执行 Tool Call 循环
        all_tool_calls = []
        final_result = None
        
        try:
            for iteration in range(self.max_iterations):
                self.log(f"Iteration {iteration + 1}/{self.max_iterations}")
                
                # 如果是最后一次迭代，注入提示词要求总结
                is_last_iteration = (iteration == self.max_iterations - 1)
                if is_last_iteration:
                    finalize_prompt = """\n\n[系统通知] 已达到最大迭代次数限制。请基于已收集的所有信息，立即调用 finish_analysis 工具提交总结分析结果。

要求：
1. 根据已有信息给出最佳分析结果
2. 必须调用 finish_analysis 工具提交结果
3. 在摘要中说明分析因迭代限制而终止"""
                    messages.append(HumanMessage(content=finalize_prompt))
                
                # 调用 LLM
                result = await self._call_llm_with_tools(
                    messages=messages,
                    tools=tools,
                    system_prompt=system_prompt,
                )
                
                if result is None:
                    final_result = f"[分析失败] LLM call failed: 返回值为 None"
                    break
                
                # 处理 tool calls
                tool_calls = result.get("tool_calls", [])
                if not tool_calls:
                    # 没有 tool call，可能是文本响应
                    content = result.get("content", "")
                    if content:
                        messages.append(AIMessage(content=content))
                        # 继续下一轮
                        continue
                    else:
                        # 没有内容和 tool call，结束
                        final_result = "[分析失败] No analysis result generated: LLM did not produce any output"
                        break
                
                # 记录 tool calls
                all_tool_calls.extend(tool_calls)
                
                # 添加 AI message with tool calls
                tool_calls_data = [{
                    "name": tc["name"],
                    "args": tc["args"],
                    "id": tc.get("id", f"call_{i}")
                } for i, tc in enumerate(tool_calls)]
                messages.append(AIMessage(content=result.get("content", ""), tool_calls=tool_calls_data))
                
                # 执行工具
                for tc in tool_calls:
                    tool_name = tc["name"]
                    args = tc["args"]
                    tool_id = tc.get("id", "unknown")
                    
                    self.log(f"Executing tool: {tool_name}")
                    
                    # 执行工具
                    try:
                        if tool_name == "search_code":
                            output = self.search_code(**args)
                        elif tool_name == "read_file":
                            output = self.read_file(**args)
                        elif tool_name == "list_directory":
                            output = self.list_directory(**args)
                        elif tool_name == "get_function_def":
                            output = await self.get_function_def(**args)
                        elif tool_name == "get_callee":
                            output = await self.get_callee(**args)
                        elif tool_name == "get_caller":
                            output = await self.get_caller(**args)
                        elif tool_name == "get_xref":
                            output = await self.get_xref(**args)
                        elif tool_name == "search_symbol":
                            output = await self.search_symbol(**args)
                        elif tool_name == "finish_analysis":
                            # 直接返回 finish_analysis 生成的文本结果
                            final_result = self.finish_analysis(args.get("result", ""))
                            break
                        else:
                            output = f"Unknown tool: {tool_name}"
                    except Exception as e:
                        output = f"Error executing {tool_name}: {str(e)}"
                    
                    messages.append(ToolMessage(content=str(output), tool_call_id=tool_id))
                
                # 如果已经得到结果，跳出外层循环
                if final_result:
                    break
            
            # 循环结束但未得到结果（正常情况下最后一次迭代应该已返回）
            if final_result is None:
                final_result = f"[分析失败] 达到最大迭代次数({self.max_iterations})但未获得有效结果"
            
        except Exception as e:
            final_result = f"[分析失败] Analysis failed with exception: {str(e)}"
        
        # 记录 Agent 执行日志结束
        if self._agent_log_manager and agent_log:
            # 根据结果判断状态
            is_failed = final_result.startswith("[分析失败]") if isinstance(final_result, str) else False
            status = AgentStatus.FAILED if is_failed else AgentStatus.COMPLETED
            self._agent_log_manager.log_execution_end(
                agent_id=self.agent_id,
                status=status,
                llm_calls=iteration + 1,
                summary=final_result[:200] if isinstance(final_result, str) else "",
                error_message=final_result if is_failed else None,
            )
        
        return final_result

    async def _call_llm_with_tools(
        self,
        messages: List[Any],
        tools: List[Any],
        system_prompt: str,
    ) -> Optional[Dict[str, Any]]:
        """
        调用 LLM 并处理 Tool Call
        
        Returns:
            Dict with keys:
                - is_finished: bool (if finish_analysis was called)
                - data: dict (finish_analysis result)
                - tool_calls: list (tool calls to execute)
                - content: str (text content)
        """
        try:
            result = await self._tool_client.atool_call(
                messages=messages,
                tools=tools,
                system_prompt=system_prompt,
            )
            
            if not result.success:
                return None
            
            # 检查是否是 finish_analysis
            if result.tool_calls:
                for tc in result.tool_calls:
                    if tc["name"] == "finish_analysis":
                        return {
                            "is_finished": True,
                            "data": tc["args"],
                            "tool_calls": result.tool_calls,
                        }
                return {
                    "is_finished": False,
                    "tool_calls": result.tool_calls,
                    "content": result.content,
                }
            else:
                return {
                    "is_finished": False,
                    "tool_calls": [],
                    "content": result.content,
                }
                
        except Exception as e:
            self.log(f"LLM call failed: {e}", "ERROR")
            return None

    async def run(self, **kwargs) -> str:
        """
        实现 BaseAgent 的抽象方法
        
        Args:
            query: 分析查询
            context: 可选上下文
            
        Returns:
            分析结果字符串
        """
        query = kwargs.get("query", "")
        context = kwargs.get("context")
        
        return await self.analyze(query=query, context=context)
