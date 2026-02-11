#!/usr/bin/env python3
"""
Tool Call 模式 LLM 客户端

支持通过 Tool Call 调用工具函数，替代结构化输出模式。
兼容支持 Tool Call 但不支持结构化输出的模型。
"""

from typing import TypeVar, Type, Optional, Any, List, Dict, Callable, Union
from pydantic import BaseModel
import asyncio
import json
import time
from datetime import datetime

from langchain_openai import ChatOpenAI
from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage, ToolMessage, AIMessage
from langchain_core.tools import tool, BaseTool
from langchain_core.utils.function_calling import convert_to_openai_tool

from .llm_logger import get_log_manager, LLMLogManager, LogStorageType

T = TypeVar("T", bound=BaseModel)


class ToolCallResult(BaseModel):
    """Tool Call 调用结果"""
    success: bool = True
    tool_calls: List[Dict[str, Any]] = []
    content: str = ""  # 纯文本响应内容
    error: Optional[str] = None


class ToolBasedLLMClient:
    """
    Tool Call 模式 LLM 客户端
    
    使用 bind_tools 绑定工具函数，通过 Tool Call 机制实现功能。
    兼容不支持结构化输出但支持 Tool Call 的模型。
    
    特性:
    1. 支持工具函数绑定和调用
    2. 支持纯文本响应解析（兼容模式）
    3. 自动重试机制
    4. 完整的交互日志记录
    
    示例:
        ```python
        # 定义工具函数
        def get_summary(func_sig: str) -> str:
            return f"Summary of {func_sig}"
        
        client = ToolBasedLLMClient(llm)
        tools = [get_summary]
        
        result = await client.atool_call(
            messages=[HumanMessage(content="分析这个函数")],
            tools=tools,
            system_prompt="你是一个代码分析助手"
        )
        ```
    """

    def __init__(
        self,
        llm: ChatOpenAI,
        max_retries: int = 3,
        retry_delay: float = 1.0,
        verbose: bool = False,
        enable_logging: bool = True,
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        log_metadata: Optional[Dict[str, Any]] = None,
    ):
        """
        初始化 Tool Call LLM 客户端
        
        Args:
            llm: LangChain ChatOpenAI 实例
            max_retries: 最大重试次数
            retry_delay: 重试间隔（秒）
            verbose: 是否打印详细日志
            enable_logging: 是否启用交互日志记录
            session_id: 会话 ID
            agent_id: Agent ID
            log_metadata: 日志元数据
        """
        self.llm = llm
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.verbose = verbose
        self.enable_logging = enable_logging
        self.session_id = session_id
        self.agent_id = agent_id
        self.log_metadata = log_metadata or {}
        self._log_manager = get_log_manager() if enable_logging else None

    def _log(self, message: str, level: str = "INFO"):
        """打印日志"""
        if self.verbose:
            print(f"[{level}] ToolBasedLLMClient: {message}")

    def _messages_to_dict(self, messages: List[BaseMessage]) -> List[Dict[str, Any]]:
        """将消息列表转换为字典列表"""
        result = []
        for msg in messages:
            msg_dict = {"type": type(msg).__name__}
            if hasattr(msg, "content"):
                msg_dict["content"] = msg.content
            if hasattr(msg, "name") and msg.name:
                msg_dict["name"] = msg.name
            if hasattr(msg, "tool_calls") and msg.tool_calls:
                msg_dict["tool_calls"] = msg.tool_calls
            if hasattr(msg, "tool_call_id") and msg.tool_call_id:
                msg_dict["tool_call_id"] = msg.tool_call_id
            result.append(msg_dict)
        return result

    def _tools_to_dict(self, tools: List[Callable]) -> List[Dict[str, Any]]:
        """将工具函数列表转换为可序列化的字典列表"""
        result = []
        for tool_func in tools:
            tool_dict = {
                "name": tool_func.__name__,
                "doc": tool_func.__doc__[:200] if tool_func.__doc__ else "",
            }
            # 尝试获取函数签名
            try:
                import inspect
                sig = inspect.signature(tool_func)
                tool_dict["signature"] = str(sig)
            except Exception:
                pass
            result.append(tool_dict)
        return result

    async def atool_call(
        self,
        messages: List[BaseMessage],
        tools: List[Callable],
        system_prompt: Optional[str] = None,
        allow_text_response: bool = True,
    ) -> ToolCallResult:
        """
        异步 Tool Call 调用
        
        Args:
            messages: LangChain 消息列表
            tools: 工具函数列表
            system_prompt: 可选的系统提示词
            allow_text_response: 是否允许纯文本响应（无 tool call）
        
        Returns:
            ToolCallResult 对象，包含 tool_calls 或纯文本内容
        
        Raises:
            RuntimeError: 所有重试都失败后抛出
        """
        # 处理 system_prompt
        if system_prompt:
            has_system = any(isinstance(m, SystemMessage) for m in messages)
            if has_system:
                messages = [
                    SystemMessage(content=system_prompt) if isinstance(m, SystemMessage) else m
                    for m in messages
                ]
            else:
                messages = [SystemMessage(content=system_prompt)] + messages

        # 记录调用开始
        log_entry = None
        start_time = time.time()
        if self._log_manager:
            # 合并 tool call 相关的元数据
            tool_call_metadata = {
                **self.log_metadata,
                "tools": self._tools_to_dict(tools),
                "tool_count": len(tools),
                "tool_names": [t.__name__ for t in tools],
            }
            log_entry = self._log_manager.log_start(
                call_type="tool_call",
                model=getattr(self.llm, 'model_name', 'unknown'),
                messages=self._messages_to_dict(messages),
                system_prompt=system_prompt,
                output_schema=f"tools: {[t.__name__ for t in tools]}",
                session_id=self.session_id,
                agent_id=self.agent_id,
                metadata=tool_call_metadata
            )

        last_error = None
        final_retry_count = 0

        for attempt in range(self.max_retries):
            try:
                # 绑定工具函数
                llm_with_tools = self.llm.bind_tools(tools)
                
                # 调用 LLM
                response = await llm_with_tools.ainvoke(messages)
                
                # 解析响应
                result = self._parse_tool_response(response, allow_text_response)
                
                # 记录调用成功
                final_retry_count = attempt
                if self._log_manager and log_entry:
                    latency_ms = (time.time() - start_time) * 1000
                    # 构建详细的响应数据，包含 tool call 结果
                    response_data = result.model_dump()
                    response_data["tool_call_details"] = {
                        "tool_count": len(result.tool_calls),
                        "tools_called": [tc.get('name', 'unknown') for tc in result.tool_calls],
                        "has_text_response": bool(result.content),
                    }
                    self._log_manager.log_end(
                        entry=log_entry,
                        response=response_data,
                        latency_ms=latency_ms,
                        retry_count=final_retry_count,
                        success=True
                    )

                return result

            except Exception as e:
                last_error = e
                self._log(f"Attempt {attempt + 1} failed: {str(e)}", "WARNING")

                if attempt < self.max_retries - 1:
                    delay = self.retry_delay * (2 ** attempt)  # 指数退避
                    self._log(f"Retrying in {delay:.1f}s...")
                    await asyncio.sleep(delay)
                else:
                    self._log(f"All {self.max_retries} attempts failed", "ERROR")

        # 所有重试失败
        if self._log_manager and log_entry:
            latency_ms = (time.time() - start_time) * 1000
            self._log_manager.log_end(
                entry=log_entry,
                error=str(last_error),
                latency_ms=latency_ms,
                retry_count=self.max_retries - 1,
                success=False
            )

        raise RuntimeError(
            f"Failed to execute tool call after {self.max_retries} attempts. "
            f"Last error: {last_error}"
        )

    def _parse_tool_response(
        self,
        response: AIMessage,
        allow_text_response: bool = True
    ) -> ToolCallResult:
        """
        解析 LLM 响应，提取 Tool Call
        
        Args:
            response: LLM 响应消息
            allow_text_response: 是否允许纯文本响应
        
        Returns:
            ToolCallResult 对象
        """
        # 检查是否有 tool_calls
        tool_calls = getattr(response, 'tool_calls', None)
        
        if tool_calls:
            parsed_calls = []
            for tc in tool_calls:
                parsed_calls.append({
                    'id': tc.get('id', ''),
                    'name': tc.get('name', ''),
                    'args': tc.get('args', {}),
                })
            
            return ToolCallResult(
                success=True,
                tool_calls=parsed_calls,
                content=response.content or "",
            )
        
        # 如果没有 tool call，检查是否允许纯文本响应
        if allow_text_response and response.content:
            return ToolCallResult(
                success=True,
                tool_calls=[],
                content=response.content,
            )
        
        # 既没有 tool call 也没有文本内容
        return ToolCallResult(
            success=False,
            tool_calls=[],
            content="",
            error="No tool calls or text response received",
        )

    async def atext_call(
        self,
        messages: List[BaseMessage],
        system_prompt: Optional[str] = None,
        output_hint: Optional[str] = None,
    ) -> str:
        """
        纯文本调用（无 Tool Call）
        
        用于简单的文本生成场景，支持通过提示词要求返回特定格式（如 JSON）。
        
        Args:
            messages: 消息列表
            system_prompt: 系统提示词
            output_hint: 输出格式提示（追加到最后一条消息）
        
        Returns:
            纯文本响应
        """
        # 处理 system_prompt
        if system_prompt:
            has_system = any(isinstance(m, SystemMessage) for m in messages)
            if has_system:
                messages = [
                    SystemMessage(content=system_prompt) if isinstance(m, SystemMessage) else m
                    for m in messages
                ]
            else:
                messages = [SystemMessage(content=system_prompt)] + messages

        # 追加输出格式提示
        if output_hint and messages:
            last_msg = messages[-1]
            if isinstance(last_msg, HumanMessage):
                new_content = f"{last_msg.content}\n\n{output_hint}"
                messages[-1] = HumanMessage(content=new_content)

        # 记录调用
        log_entry = None
        start_time = time.time()
        if self._log_manager:
            log_entry = self._log_manager.log_start(
                call_type="text_call",
                model=getattr(self.llm, 'model_name', 'unknown'),
                messages=self._messages_to_dict(messages),
                system_prompt=system_prompt,
                session_id=self.session_id,
                agent_id=self.agent_id,
                metadata=self.log_metadata
            )

        try:
            response = await self.llm.ainvoke(messages)
            content = response.content if hasattr(response, 'content') else str(response)
            
            # 记录成功
            if self._log_manager and log_entry:
                latency_ms = (time.time() - start_time) * 1000
                self._log_manager.log_end(
                    entry=log_entry,
                    response={"content": content},
                    latency_ms=latency_ms,
                    success=True
                )
            
            return content

        except Exception as e:
            # 记录失败
            if self._log_manager and log_entry:
                latency_ms = (time.time() - start_time) * 1000
                self._log_manager.log_end(
                    entry=log_entry,
                    error=str(e),
                    latency_ms=latency_ms,
                    success=False
                )
            raise


class SimpleJSONLLMClient:
    """
    简单 JSON 输出 LLM 客户端（兼容模式）
    
    对于不支持 Tool Call 的模型，通过提示词要求返回纯 JSON 格式。
    输出结构简单，层级不超过 2 层。
    
    示例输出格式:
    ```json
    {
        "behavior": "函数行为描述",
        "constraints": ["参数1 > 0", "参数2 != NULL"],
        "return_value": "返回值含义"
    }
    ```
    """

    def __init__(
        self,
        llm: ChatOpenAI,
        max_retries: int = 3,
        verbose: bool = False,
    ):
        self.llm = llm
        self.max_retries = max_retries
        self.verbose = verbose
        self._log_manager = get_log_manager()

    def _log(self, message: str, level: str = "INFO"):
        if self.verbose:
            print(f"[{level}] SimpleJSONLLMClient: {message}")

    async def ajson_call(
        self,
        messages: List[BaseMessage],
        system_prompt: Optional[str] = None,
        json_hint: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        异步 JSON 调用
        
        Args:
            messages: 消息列表
            system_prompt: 系统提示词
            json_hint: JSON 格式提示
        
        Returns:
            解析后的 JSON 字典
        """
        # 构建 JSON 格式提示
        default_hint = """请严格按照以下 JSON 格式输出响应，不要包含其他内容：

```json
{
    "field1": "值1",
    "field2": ["列表项1", "列表项2"]
}
```

确保输出是有效的 JSON 格式。"""

        hint = json_hint or default_hint

        # 追加提示到最后一条消息
        if messages:
            last_msg = messages[-1]
            if isinstance(last_msg, HumanMessage):
                new_content = f"{last_msg.content}\n\n{hint}"
                messages[-1] = HumanMessage(content=new_content)

        # 处理 system_prompt
        if system_prompt:
            has_system = any(isinstance(m, SystemMessage) for m in messages)
            if has_system:
                messages = [
                    SystemMessage(content=system_prompt) if isinstance(m, SystemMessage) else m
                    for m in messages
                ]
            else:
                messages = [SystemMessage(content=system_prompt)] + messages

        for attempt in range(self.max_retries):
            try:
                response = await self.llm.ainvoke(messages)
                content = response.content if hasattr(response, 'content') else str(response)
                
                # 提取 JSON
                result = self._extract_json(content)
                return result

            except Exception as e:
                self._log(f"Attempt {attempt + 1} failed: {str(e)}", "WARNING")
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(1 * (2 ** attempt))
                else:
                    raise RuntimeError(f"JSON parsing failed after {self.max_retries} attempts: {e}")

        return {}

    def _extract_json(self, content: str) -> Dict[str, Any]:
        """
        从响应内容中提取 JSON
        
        支持以下格式:
        1. ```json\n{...}\n```
        2. {...}
        """
        content = content.strip()
        
        # 尝试匹配 ```json ... ```
        if "```json" in content:
            start = content.find("```json") + 7
            end = content.find("```", start)
            if end > start:
                json_str = content[start:end].strip()
                return json.loads(json_str)
        
        # 尝试匹配 ``` ... ```
        if content.startswith("```"):
            start = content.find("\n") + 1
            end = content.rfind("```")
            if end > start:
                json_str = content[start:end].strip()
                return json.loads(json_str)
        
        # 尝试直接解析 JSON
        # 找到第一个 { 和最后一个 }
        start = content.find("{")
        end = content.rfind("}")
        if start != -1 and end != -1 and end > start:
            json_str = content[start:end+1]
            return json.loads(json_str)
        
        raise ValueError("No valid JSON found in response")


__all__ = [
    'ToolBasedLLMClient',
    'ToolCallResult',
    'SimpleJSONLLMClient',
]
