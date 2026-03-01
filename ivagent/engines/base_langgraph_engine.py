#!/usr/bin/env python3
"""
LangGraphEngine - LangGraph 智能分析引擎基类

提供现代化的异步 Agent 架构支持：
1. 基于 StateGraph 的异步工作流编排
2. 异步状态管理与持久化
3. 异步 LLM 交互与工具调用
4. 内存与上下文管理
5. 高并发分析支持
"""

from typing import Dict, List, Optional, Any, Callable, TypedDict, Annotated, Sequence, Awaitable
from abc import ABC, abstractmethod
import json
import time
import asyncio
from dataclasses import dataclass, field
from enum import Enum

from langgraph.graph import StateGraph, END
from langgraph.graph.message import add_messages
from langgraph.checkpoint.memory import MemorySaver
from langchain_core.messages import BaseMessage, HumanMessage, AIMessage, SystemMessage, ToolMessage
from langchain_core.tools import BaseTool, tool
from langchain_core.runnables import RunnableConfig
from langchain_openai import ChatOpenAI
from ..core.cli_logger import CLILogger

class WorkflowStatus(str, Enum):
    """工作流状态"""
    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    ERROR = "error"


class AgentState(TypedDict):
    """
    Agent 状态类型定义
    
    使用 TypedDict 确保类型安全，支持 LangGraph 的状态传递
    """
    messages: Annotated[Sequence[BaseMessage], add_messages]
    metadata: Dict[str, Any]
    iteration: int
    max_iterations: int
    status: str
    error: Optional[str]
    result: Optional[Any]


@dataclass
class EngineConfig:
    """
    引擎配置
    
    定义引擎的运行参数和行为
    """
    max_iterations: int = 10
    temperature: float = 0.1
    verbose: bool = False
    enable_checkpointing: bool = True
    checkpoint_dir: Optional[str] = None
    timeout_seconds: Optional[int] = None
    max_concurrency: int = 10  # 最大并发数


@dataclass
class ExecutionResult:
    """执行结果"""
    success: bool
    result: Optional[Any] = None
    error: Optional[str] = None
    duration: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


class LangGraphEngine(ABC):
    """
    LangGraph 智能分析引擎基类
    
    基于 LangGraph 架构，提供现代化的异步 Agent 能力：
    1. 状态驱动的异步执行模型 (StateGraph)
    2. 节点化的异步工作流编排
    3. 异步 LLM 交互能力
    4. 异步工具注册与管理
    5. 高并发执行支持
    
    子类通过实现 build_workflow() 方法定义自己的工作流
    """
    
    def __init__(
        self,
        llm_client: ChatOpenAI,
        tools: Optional[List[BaseTool]] = None,
        config: Optional[EngineConfig] = None,
    ):
        """
        初始化引擎
        
        参数:
            llm_client: LLM 客户端实例
            tools: 工具列表
            config: 引擎配置
        """
        self.llm_client: ChatOpenAI = llm_client
        self.tools = tools or []
        self.config = config or EngineConfig()
        self._logger = CLILogger(component=self.__class__.__name__, verbose=self.config.verbose)
        
        # 工作流图
        self._workflow: Optional[StateGraph] = None
        self._compiled_workflow: Optional[Any] = None
        
        # 执行历史
        self.execution_history: List[Dict[str, Any]] = []
        
        # 状态
        self._current_status = WorkflowStatus.IDLE
        
        # 并发控制
        self._semaphore = asyncio.Semaphore(self.config.max_concurrency)
        self._lock = asyncio.Lock()
        
        # 初始化工作流
        self._initialize_workflow()
    
    def _initialize_workflow(self):
        """初始化工作流图"""
        # 创建工作流图
        self._workflow = StateGraph(AgentState)
        
        # 构建子类定义的工作流
        self.build_workflow()
        
        # 编译工作流
        checkpointer = None
        if self.config.enable_checkpointing:
            checkpointer = MemorySaver()
        
        self._compiled_workflow = self._workflow.compile(
            checkpointer=checkpointer,
            debug=self.config.verbose,
        )
    
    @abstractmethod
    def build_workflow(self):
        """
        构建工作流图
        
        子类必须实现此方法，使用 self._workflow 添加节点和边：
        
        Example:
            self._workflow.add_node("analyze", self._analyze_node)
            self._workflow.add_node("verify", self._verify_node)
            self._workflow.set_entry_point("analyze")
            self._workflow.add_edge("analyze", "verify")
            self._workflow.add_edge("verify", END)
        """
        pass
    
    async def run(
        self,
        input_data: Dict[str, Any],
        config: Optional[RunnableConfig] = None,
    ) -> Dict[str, Any]:
        """
        异步执行工作流
        
        参数:
            input_data: 输入数据
            config: 运行配置
        
        返回:
            执行结果
        """
        if not self._compiled_workflow:
            raise RuntimeError("Workflow not initialized")
        
        # 构建初始状态
        initial_state = self._create_initial_state(input_data)
        
        # 执行工作流
        self._current_status = WorkflowStatus.RUNNING
        start_time = time.time()
        
        try:
            # 使用线程池执行同步的 LangGraph 工作流
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                lambda: self._compiled_workflow.invoke(
                    initial_state,
                    config=config or self._create_default_config(),
                )
            )
            
            self._current_status = WorkflowStatus.COMPLETED
            
            # 记录历史
            await self._add_history_async({
                "type": "workflow_execution",
                "input": input_data,
                "result": result,
                "duration": time.time() - start_time,
                "status": "success",
            })
            
            return result
            
        except Exception as e:
            self._current_status = WorkflowStatus.ERROR
            
            await self._add_history_async({
                "type": "workflow_execution",
                "input": input_data,
                "error": str(e),
                "duration": time.time() - start_time,
                "status": "error",
            })
            
            raise
    
    def _create_initial_state(self, input_data: Dict[str, Any]) -> AgentState:
        """
        创建初始状态
        
        参数:
            input_data: 输入数据
        
        返回:
            AgentState 初始状态
        """
        messages: List[BaseMessage] = []
        
        # 如果有系统提示，添加系统消息
        system_prompt = input_data.get("system_prompt")
        if system_prompt:
            messages.append(SystemMessage(content=system_prompt))
        
        # 添加用户输入
        user_input = input_data.get("input")
        if user_input:
            messages.append(HumanMessage(content=str(user_input)))
        
        return AgentState(
            messages=messages,
            metadata=input_data.get("metadata", {}),
            iteration=0,
            max_iterations=self.config.max_iterations,
            status="running",
            error=None,
            result=None,
        )
    
    def _create_default_config(self) -> RunnableConfig:
        """创建默认运行配置"""
        return RunnableConfig(
            recursion_limit=self.config.max_iterations * 2,
        )
    
    async def call_llm(
        self,
        messages: List[BaseMessage],
        temperature: Optional[float] = None,
        json_mode: bool = False,
    ) -> AIMessage:
        """
        异步调用 LLM
        
        参数:
            messages: 消息列表
            temperature: 温度参数
            json_mode: 是否要求 JSON 输出
        
        返回:
            AI 消息
        """
        async with self._semaphore:
            try:
                # 在线程池中执行同步 LLM 调用
                loop = asyncio.get_event_loop()
                response = await loop.run_in_executor(
                    None,
                    lambda: self.llm_client.invoke(messages)
                )
                content = response.content
                
                # JSON 模式下尝试解析
                if json_mode:
                    try:
                        parsed = json.loads(content)
                        content = json.dumps(parsed, ensure_ascii=False)
                    except json.JSONDecodeError:
                        pass
                
                await self._add_history_async({
                    "type": "llm_call",
                    "messages_count": len(messages),
                    "success": True,
                })
                
                return AIMessage(content=content)
                
            except Exception as e:
                await self._add_history_async({
                    "type": "llm_call",
                    "success": False,
                    "error": str(e),
                })
                raise
    
    
    async def execute_tool(
        self,
        tool_name: str,
        tool_input: Dict[str, Any],
    ) -> ToolMessage:
        """
        异步执行工具
        
        参数:
            tool_name: 工具名称
            tool_input: 工具输入
        
        返回:
            工具消息
        """
        tool_map = {t.name: t for t in self.tools}
        
        if tool_name not in tool_map:
            error_msg = f"Tool '{tool_name}' not found"
            self.log(error_msg, "ERROR")
            return ToolMessage(content=error_msg, tool_call_id=tool_name)
        
        try:
            tool_instance = tool_map[tool_name]
            
            # 在线程池中执行同步工具
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                lambda: tool_instance.invoke(tool_input)
            )
            
            await self._add_history_async({
                "type": "tool_execution",
                "tool_name": tool_name,
                "input": tool_input,
                "success": True,
            })
            
            content = result
            if not isinstance(result, str):
                content = json.dumps(result, ensure_ascii=False)
            
            return ToolMessage(content=content, tool_call_id=tool_name)
            
        except Exception as e:
            error_msg = f"Tool execution failed: {str(e)}"
            await self._add_history_async({
                "type": "tool_execution",
                "tool_name": tool_name,
                "input": tool_input,
                "success": False,
                "error": str(e),
            })
            return ToolMessage(content=error_msg, tool_call_id=tool_name)
    
    def log(self, message: str, level: str = "INFO"):
        """打印日志"""
        if not self.config.verbose:
            return
        self._logger.log(level=level, event="langgraph_engine.event", message=message)
    
    async def _add_history_async(self, entry: Dict[str, Any]):
        """异步添加执行历史"""
        async with self._lock:
            entry["timestamp"] = time.time()
            self.execution_history.append(entry)
    
    def add_history(self, entry: Dict[str, Any]):
        """同步添加执行历史（供非异步上下文使用）"""
        entry["timestamp"] = time.time()
        self.execution_history.append(entry)
    
    def get_history(self) -> List[Dict[str, Any]]:
        """获取执行历史"""
        return self.execution_history
    
    def reset(self):
        """重置引擎状态"""
        self.execution_history = []
        self._current_status = WorkflowStatus.IDLE
    
    def get_status(self) -> WorkflowStatus:
        """获取当前状态"""
        return self._current_status
    
    def register_tool(self, tool_instance: BaseTool):
        """注册工具"""
        self.tools.append(tool_instance)
    
    def create_tool_from_function(
        self,
        func: Callable,
        name: Optional[str] = None,
        description: Optional[str] = None,
    ) -> BaseTool:
        """从函数创建工具"""
        return tool(func, name=name, description=description)
    
    async def __aenter__(self):
        """异步上下文管理器入口"""
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """异步上下文管理器出口"""
        self.reset()
