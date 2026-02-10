#!/usr/bin/env python3
"""
BaseAgent - Agent 基类

为所有 Agent 提供通用功能和接口
支持高并发分析场景
"""

from typing import Dict, List, Optional, Any, Awaitable, AsyncIterator
from abc import ABC, abstractmethod
import json
import time
import asyncio


class BaseAgent(ABC):
    """
    Agent 基类
    
    提供通用的异步 LLM 交互、工具调用、状态管理等功能
    支持高并发分析场景
    """
    
    def __init__(
        self,
        engine: Any,  # 异步分析引擎实例
        llm_client,
        tools=None,
        max_iterations: int = 10,
        verbose: bool = False,
        max_concurrency: int = 10,
    ):
        """
        初始化 Agent
        
        参数:
            engine: 异步分析引擎实例
            llm_client: LLM 客户端
            tools: 工具集合
            max_iterations: 最大迭代次数
            verbose: 是否打印详细信息
            max_concurrency: 最大并发数
        """
        self.engine = engine
        self.llm_client = llm_client
        self.tools = tools
        self.max_iterations = max_iterations
        self.verbose = verbose
        self.max_concurrency = max_concurrency
        
        # 执行历史
        self.execution_history: List[Dict[str, Any]] = []
        self._history_lock = asyncio.Lock()
        
        # 状态
        self.current_state: Dict[str, Any] = {}
        self._state_lock = asyncio.Lock()
        
        # 并发控制
        self._semaphore = asyncio.Semaphore(max_concurrency)
    
    def log(self, message: str, level: str = "INFO"):
        """打印日志"""
        if self.verbose:
            print(f"[{level}] {self.__class__.__name__}: {message}")
    
    async def add_history(self, entry: Dict[str, Any]):
        """异步添加执行历史"""
        async with self._history_lock:
            entry["timestamp"] = time.time()
            self.execution_history.append(entry)
    
    def get_history(self) -> List[Dict[str, Any]]:
        """获取执行历史"""
        return self.execution_history
    
    async def reset(self):
        """异步重置 Agent 状态"""
        async with self._history_lock:
            self.execution_history = []
        async with self._state_lock:
            self.current_state = {}
    
    async def update_state(self, key: str, value: Any):
        """异步更新状态"""
        async with self._state_lock:
            self.current_state[key] = value
    
    async def get_state(self, key: str, default=None) -> Any:
        """异步获取状态"""
        async with self._state_lock:
            return self.current_state.get(key, default)
    
    @abstractmethod
    async def run(self, **kwargs) -> Dict[str, Any]:
        """
        异步执行 Agent 主逻辑
        
        子类必须实现此方法
        
        返回:
            执行结果字典
        """
        pass
    
    async def call_llm(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.1,
        json_mode: bool = True,
    ) -> Dict[str, Any]:
        """
        异步调用 LLM
        
        参数:
            prompt: 用户提示词
            system_prompt: 系统提示词
            temperature: 温度参数
            json_mode: 是否要求 JSON 输出
        
        返回:
            LLM 响应
        """
        from langchain_core.messages import HumanMessage, SystemMessage
        
        async with self._semaphore:
            try:
                messages = []
                if system_prompt:
                    messages.append(SystemMessage(content=system_prompt))
                messages.append(HumanMessage(content=prompt))
                
                # 在线程池中执行同步 LLM 调用
                loop = asyncio.get_event_loop()
                response = await loop.run_in_executor(
                    None,
                    lambda: self.llm_client.invoke(messages)
                )
                content = response.content
                
                # 尝试解析 JSON
                if json_mode:
                    try:
                        content = json.loads(content)
                    except json.JSONDecodeError:
                        pass
                
                await self.add_history({
                    "type": "llm_call",
                    "prompt_length": len(prompt),
                    "success": True,
                })
                
                return {"text": content} if isinstance(content, str) else content
                
            except Exception as e:
                await self.add_history({
                    "type": "llm_call",
                    "success": False,
                    "error": str(e),
                })
                raise
  
    async def execute_tool(
        self,
        tool_name: str,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        异步执行工具
        
        参数:
            tool_name: 工具名称
            **kwargs: 工具参数
        
        返回:
            工具执行结果
        """
        if self.tools is None:
            return {"success": False, "error": "No tools available"}
        
        # 在线程池中执行同步工具
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None,
            lambda: self.tools.execute(tool_name, **kwargs)
        )
        
        await self.add_history({
            "type": "tool_execution",
            "tool_name": tool_name,
            "parameters": kwargs,
            "success": result.success if hasattr(result, 'success') else True,
        })
        
        return result.to_dict() if hasattr(result, 'to_dict') else result
    
    async def execute_tools_batch(
        self,
        tool_calls: List[tuple],
        max_concurrency: int = 10,
    ) -> List[Dict[str, Any]]:
        """
        批量异步执行工具
        
        参数:
            tool_calls: (tool_name, kwargs) 元组列表
            max_concurrency: 最大并发数
        
        返回:
            工具执行结果列表
        """
        semaphore = asyncio.Semaphore(max_concurrency)
        
        async def _execute_one(tool_name: str, kwargs: dict) -> Dict[str, Any]:
            async with semaphore:
                return await self.execute_tool(tool_name, **kwargs)
        
        tasks = [_execute_one(name, kwargs) for name, kwargs in tool_calls]
        return await asyncio.gather(*tasks, return_exceptions=True)
    
    def format_tool_descriptions(self) -> str:
        """格式化工具描述供 LLM 使用"""
        if self.tools is None:
            return ""
        
        tools = self.tools.list_tools()
        
        descriptions = []
        for tool in tools:
            desc = f"- {tool['name']}: {tool['description']}\n  参数: {tool['parameters']}"
            descriptions.append(desc)
        
        return "\n".join(descriptions)
    
    def parse_tool_calls(
        self,
        llm_response: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """
        解析 LLM 响应中的工具调用
        
        参数:
            llm_response: LLM 响应
        
        返回:
            工具调用列表
        """
        # 支持多种格式
        if "tool_calls" in llm_response:
            return llm_response["tool_calls"]
        
        if "tools" in llm_response:
            return llm_response["tools"]
        
        # 单一工具调用
        if "tool_name" in llm_response:
            return [llm_response]
        
        return []
    
    async def __aenter__(self):
        """异步上下文管理器入口"""
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """异步上下文管理器出口"""
        await self.reset()
