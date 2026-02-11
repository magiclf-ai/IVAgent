import os
import json
import fnmatch
import logging
import subprocess
import uuid
from typing import List, Dict, Any, Optional, Union
from langchain_core.messages import BaseMessage, HumanMessage, ToolMessage, AIMessage, SystemMessage
from langchain_openai import ChatOpenAI

from ivagent.agents.base import BaseAgent
from ivagent.core.tool_llm_client import ToolBasedLLMClient
from ivagent.core.agent_logger import get_agent_log_manager, AgentStatus
from ivagent.models.callsite import CallsiteInfo, ResolvedCallsite

logger = logging.getLogger(__name__)


class CallsiteAgent(BaseAgent):
    """
    Agent for identifying callsite target functions using source code analysis.
    """

    def __init__(
            self,
            llm_client: Union[ChatOpenAI, ToolBasedLLMClient],
            source_root: str,
            **kwargs
    ):
        # Agent 日志系统（必须在创建 ToolBasedLLMClient 之前初始化）
        self.agent_id = str(uuid.uuid4())
        self._agent_logger = get_agent_log_manager()
        
        # If raw LLM is passed, wrap it
        if isinstance(llm_client, ChatOpenAI):
            self.llm_tool_client = ToolBasedLLMClient(
                llm_client, 
                verbose=kwargs.get("verbose", False),
                agent_id=self.agent_id,  # 传入 agent_id 用于 LLM 日志关联
                log_metadata={"agent_type": "CallsiteAgent"}  # 传入 Agent 类型
            )
            super().__init__(engine=None, llm_client=llm_client, **kwargs)
        else:
            # 如果传入的是 ToolBasedLLMClient，更新其 agent_id 和 metadata
            self.llm_tool_client = llm_client
            self.llm_tool_client.agent_id = self.agent_id
            if not self.llm_tool_client.log_metadata:
                self.llm_tool_client.log_metadata = {}
            self.llm_tool_client.log_metadata["agent_type"] = "CallsiteAgent"
            super().__init__(engine=None, llm_client=llm_client.llm, **kwargs)

        self.source_root = source_root

    def _search_code(self, query: str, path_filter: Optional[str] = None) -> str:
        """
        Search for text in files within the source root using ripgrep (rg).

        Args:
            query: The text string to search for.
            path_filter: Glob pattern to filter file paths (e.g., "*.ts", "src/*.java").

        Returns:
            Formatted search results with file paths, line numbers, and matching content.
        """
        results = []
        limit = 50

        # Validate source_root
        if not self.source_root:
            return "Error: source_root is not configured. Please provide a valid source code directory."

        # Resolve to absolute path and validate
        source_path = os.path.abspath(os.path.expanduser(self.source_root))
        if not os.path.isdir(source_path):
            return f"Error: source_root is not a valid directory: {source_path}"

        try:
            # Construct rg command
            # -n: Show line numbers
            # --no-heading: Print one line per match
            # --fixed-strings: Treat query as literal string
            # Note: Must use source_path (absolute) to ensure we search in the right directory
            cmd = ["rg", "-n", "--no-heading", "--fixed-strings", query, source_path]

            if path_filter:
                cmd.extend(["-g", path_filter])

            # Run rg
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace'
            )

            # rg returns 0 on match, 1 on no match, 2 on error
            if process.returncode == 2:
                return f"Error executing search: {process.stderr}"

            output_lines = process.stdout.strip().split('\n')

            if not output_lines or not output_lines[0]:
                return f"No matches found for: '{query}'"

            count = 0
            for line in output_lines:
                if not line:
                    continue

                # rg output format: file_path:line_number:content
                parts = line.split(':', 2)
                if len(parts) >= 3:
                    file_path = parts[0]
                    line_num_str = parts[1]
                    content = parts[2]

                    # Handle Windows absolute paths (e.g., D:\path\to\file:10:content)
                    if len(file_path) == 1 and parts[1].startswith('\\'):
                        parts = line.split(':', 3)
                        if len(parts) >= 4:
                            file_path = f"{parts[0]}:{parts[1]}"
                            line_num_str = parts[2]
                            content = parts[3]

                    try:
                        line_num = int(line_num_str)
                        results.append((file_path, line_num, content.strip()))
                        count += 1
                    except ValueError:
                        continue

                if count >= limit:
                    break

            # Format results as human-readable text for LLM
            formatted = [f"Search results for: '{query}'\n{'=' * 60}"]
            for file_path, line_num, content in results:
                formatted.append(f"{file_path}:{line_num} | {content}")

            if len(output_lines) > limit:
                formatted.append(f"\n[Warning: Results truncated, showing first {limit} of {len(output_lines)} matches]")

            return "\n".join(formatted)

        except FileNotFoundError:
            return "Error: 'rg' (ripgrep) is not installed or not in PATH."
        except Exception as e:
            return f"Error searching code: {str(e)}"

    def _read_file(self, file_path: str, start_line: int, end_line: int) -> str:
        """
        Read a range of lines from a file with context header.

        Args:
            file_path: Absolute path to the file.
            start_line: Start line number (1-based, inclusive).
            end_line: End line number (1-based, inclusive).

        Returns:
            File content with line numbers and context header.
        """
        try:
            if not os.path.exists(file_path):
                return f"Error: File not found: {file_path}"

            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                lines = f.readlines()

            total_lines = len(lines)
            if total_lines == 0:
                return f"File: {file_path}\nStatus: Empty file (0 lines)"

            # Clamp line numbers to valid range
            start_idx = max(0, start_line - 1)
            end_idx = min(total_lines, end_line)

            if start_idx >= end_idx:
                return (
                    f"File: {file_path}\n"
                    f"Total lines: {total_lines}\n"
                    f"Error: Invalid range [{start_line}:{end_line}] (no lines to read)"
                )

            # Build output with header for context
            output = [
                f"File: {file_path}",
                f"Lines: {start_idx + 1} - {end_idx} (of {total_lines})",
                f"{'=' * 60}"
            ]

            for i in range(start_idx, end_idx):
                output.append(f"{i + 1:4d} | {lines[i].rstrip()}")

            return "\n".join(output)

        except PermissionError:
            return f"Error: Permission denied when reading: {file_path}"
        except Exception as e:
            return f"Error reading file: {str(e)}"

    async def run(
            self,
            callsite_info: CallsiteInfo,
            caller_code: Optional[str] = None,
            caller_class: Optional[str] = None,
            caller_method: Optional[str] = None
    ) -> ResolvedCallsite:
        """
        Identify the target function for the given callsite.
        
        Args:
            callsite_info: Information about the callsite.
            caller_code: Source code of the caller function.
            caller_class: Name of the class containing the caller.
            caller_method: Name of the caller function.
        """
        # 记录执行开始
        target = callsite_info.function_identifier or "unknown"
        self._agent_logger.log_execution_start(
            agent_id=self.agent_id,
            agent_type="CallsiteAgent",
            target_function=target,
            parent_id=None,
            call_stack=[],
            metadata={
                "callsite": callsite_info.to_dict(),
                "caller_class": caller_class,
                "caller_method": caller_method,
            }
        )
        
        # 构建 system prompt（agent 背景、能力、工具规范）
        system_prompt = self._build_system_prompt()
        
        # 构建 human message（用户任务信息）
        human_content = self._build_task_prompt(callsite_info, caller_code, caller_class, caller_method)
        
        messages: List[BaseMessage] = [HumanMessage(content=human_content)]
        tools = [self._search_code, self._read_file]

        candidates = []
        reasoning = ""
        resolved = False
        llm_calls = 0

        for turn in range(self.max_iterations):

            def finish_analysis(found_candidates: List[str], analysis_reasoning: str):
                """
                Call this when you have identified the candidates or determined it's impossible.
                
                Args:
                    found_candidates: List of potential function signatures or names.
                    analysis_reasoning: Explanation of how you reached this conclusion.
                """
                nonlocal candidates, reasoning, resolved
                candidates = found_candidates
                reasoning = analysis_reasoning
                resolved = True
                return "Analysis finished."

            current_tools = tools + [finish_analysis]

            result = await self.llm_tool_client.atool_call(
                messages=messages,
                tools=current_tools,
                system_prompt=system_prompt
            )
            llm_calls += 1

            if resolved:
                break

            if not result.success:
                logger.error(f"LLM call failed: {result.error}")
                # 记录执行失败
                self._agent_logger.log_execution_end(
                    agent_id=self.agent_id,
                    status=AgentStatus.FAILED,
                    llm_calls=llm_calls,
                    summary="LLM call failed",
                    error_message=str(result.error)
                )
                break

            # Handle tool calls
            if result.tool_calls:
                # Append AIMessage
                tool_calls_data = []
                for tc in result.tool_calls:
                    tool_calls_data.append({
                        "name": tc["name"],
                        "args": tc["args"],
                        "id": tc.get("id", "call_default")
                    })
                messages.append(AIMessage(content=result.content or "", tool_calls=tool_calls_data))

                # Execute tools
                for tc in result.tool_calls:
                    tool_name = tc["name"]
                    args = tc["args"]
                    tool_id = tc.get("id", "call_default")

                    if tool_name == "finish_analysis":
                        finish_analysis(**args)
                        break  # Stop processing other tools if finished

                    output = ""
                    if tool_name == "_search_code":
                        output = self._search_code(**args)
                    elif tool_name == "_read_file":
                        output = self._read_file(**args)
                    else:
                        output = f"Unknown tool: {tool_name}"

                    messages.append(ToolMessage(content=str(output), tool_call_id=tool_id))

                if resolved:
                    break
            else:
                messages.append(AIMessage(content=result.content))

        # Return result
        best_candidate = candidates[0] if candidates else ""
        resolved_successfully = bool(candidates)
        
        # 记录执行结束
        status = AgentStatus.COMPLETED if resolved_successfully else AgentStatus.FAILED
        summary = f"Resolved callsite to {best_candidate}" if resolved_successfully else f"Failed to resolve callsite: {reasoning}"
        self._agent_logger.log_execution_end(
            agent_id=self.agent_id,
            status=status,
            llm_calls=llm_calls,
            summary=summary,
            error_message=reasoning if not resolved_successfully else None
        )
        
        return ResolvedCallsite(
            callsite=callsite_info,
            function_identifier=best_candidate,
            resolved_successfully=resolved_successfully,
            error_message=reasoning if not candidates else ""
        )

    def _build_system_prompt(self) -> str:
        """
        构建 System Prompt，描述 Agent 的背景、知识、能力和工具使用规范。
        不包含具体任务信息。
        """
        return """# CallsiteAgent System Prompt

## Role & Background
You are an expert code analyst specialized in identifying function call targets in complex codebases (C/C++, Java, ArkTS).

Your primary responsibility is to identify the definition of the function being called at a specific callsite by analyzing source code.

## Capabilities
- Search source code using `_search_code` tool to find function definitions, variable declarations, and type information
- Read specific file ranges to examine implementation details
- Trace variable definitions to determine object types and method origins
- Handle multiple programming languages and their unique resolution patterns

## Available Tools

### 1. `_search_code(query: str, path_filter: Optional[str])`
Search for text in source files using ripgrep.
- **query**: The text string to search for (treated as literal string, not regex)
- **path_filter**: Optional glob pattern to filter files (e.g., "*.ts", "src/*.java")
- Returns file paths, line numbers, and matching content

**Usage Guidelines:**
- Use for finding function definitions, class declarations, imports
- Use path_filter to narrow results to relevant file types
- Start with broad searches, then narrow down based on results

### 2. `_read_file(file_path: str, start_line: int, end_line: int)`
Read a specific range of lines from a file.
- **file_path**: Absolute path to the file
- **start_line**: Start line number (1-based, inclusive)
- **end_line**: End line number (1-based, inclusive)
- Returns file content with line numbers

**Usage Guidelines:**
- Use after search to examine implementation details
- Read enough context (typically 20-50 lines) to understand the code structure
- Pay attention to variable declarations, type annotations, and import statements

### 3. `finish_analysis(found_candidates: List[str], analysis_reasoning: str)`
Complete the analysis by reporting results.
- **found_candidates**: List of potential function signatures or names
- **analysis_reasoning**: Explanation of how you reached this conclusion

**Usage Guidelines:**
- Call this when you have identified one or more candidates
- If no candidates found, explain why and what information was missing
- Provide clear reasoning showing your analysis steps

## Analysis Strategies by Language

### C/C++
1. Search for the function name directly
2. If the function is called via a pointer, trace the variable definition to find its type
3. Look for struct/class definitions to understand method pointers

### ArkTS / TypeScript / JavaScript
1. Trace variable definitions (let/const/var) to find imports or class instantiations
2. Look for `this` context or closure variables (like `_lexenv_`)
3. Identify imports to find the source file of the class/function
4. Check class declarations and method signatures

## Analysis Workflow
1. **Understand the Callsite**: Review the provided callsite information (function name, arguments, call context)
2. **Search for Context**: Use `_search_code` to find relevant definitions
3. **Examine Code**: Use `_read_file` to examine implementation details
4. **Trace Types**: For method calls, trace variables to their types
5. **Identify Target**: Determine the actual function being called
6. **Report Results**: Use `finish_analysis` to report candidates and reasoning

## Output Format
When using `finish_analysis`:
- `found_candidates`: List of fully qualified function signatures (e.g., `ClassName.methodName`, `namespace::functionName`)
- `analysis_reasoning`: Step-by-step explanation of your analysis process

## Example Analysis (ArkTS)
Given: `arg0.loadContent("pages/Index", #1#);` inside `onWindowStageCreate`

Analysis steps:
1. Search for `onWindowStageCreate` to find the caller function
2. Read the function to see where `arg0` comes from (e.g., function argument with type `WindowStage`)
3. Search for `WindowStage` class definition to confirm
4. Infer `loadContent` is a method of `WindowStage`
5. Identify `#1#` by looking at surrounding code (e.g., storage object or context)
6. Report: `WindowStage.loadContent`
"""

    def _build_task_prompt(
            self,
            callsite: CallsiteInfo,
            caller_code: Optional[str] = None,
            caller_class: Optional[str] = None,
            caller_method: Optional[str] = None
    ) -> str:
        """
        构建 Human Message，包含具体的任务信息和 callsite 详情。
        """
        # Build caller context if available
        caller_info = ""
        if caller_class or caller_method:
            caller_info = "\n## Caller Information"
            if caller_class:
                caller_info += f"\n- **Class**: {caller_class}"
            if caller_method:
                caller_info += f"\n- **Method**: {caller_method}"

        # Add source code context if available
        source_context = ""
        if caller_code:
            source_context = f"\n\n## Caller Source Code Context\n```\n{caller_code}\n```"

        return f"""# Task: Identify Function Call Target

Please analyze the following callsite and identify the target function being called.

## Callsite Information
| Field | Value |
|-------|-------|
| **Line Number** | {callsite.line_number} |
| **Target Function Identifier** | `{callsite.function_identifier or "N/A"}` |
| **Arguments** | `{callsite.arguments or "N/A"}` |
| **Call Text** | `{callsite.call_text or "N/A"}` |{caller_info}{source_context}

## Instructions
1. Analyze the callsite to understand what function is being invoked
2. Use `_search_code` and `_read_file` tools to explore the codebase
3. Trace variable types if needed to resolve method calls
4. When you have identified the target function(s), call `finish_analysis` with your findings

**Important**: If you cannot determine the exact target, provide your best candidates with reasoning about what information would be needed to confirm.

---
**Callsite Data (JSON)**:
```json
{json.dumps(callsite.to_dict(), indent=2)}
```
"""
