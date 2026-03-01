#!/usr/bin/env python3
"""
FunctionSummaryAgent - 函数摘要提取 Agent（单 Tool Call Loop）

专门用于提取函数摘要的递归分析 Agent，采用单循环多轮交互模式：
在一个 Tool Call Loop 中完成所有交互：
1. LLM 分析源码，按需调用 get_sub_function_summary 获取子函数摘要
2. Agent 处理 Tool Call，递归获取子函数摘要并返回给 LLM
3. LLM 综合分析后，调用 submit_function_summary 提交最终结果

特点：
- LLM 按需请求子函数摘要，而非预先批量获取
- 单循环多轮交互，流程简洁
- 纯文本格式，降低对 LLM 的要求
- 支持降级到纯 JSON 模式
"""

from typing import Dict, List, Optional, Any, Set, Callable
from dataclasses import dataclass, field
import json
import asyncio
import uuid

from langchain_core.messages import HumanMessage, AIMessage, ToolMessage, SystemMessage, BaseMessage
from langchain_openai import ChatOpenAI

from .base import BaseAgent
from . import prompts
from ..engines.base_static_analysis_engine import BaseStaticAnalysisEngine
from ..core.tool_llm_client import ToolBasedLLMClient, SimpleJSONLLMClient
from ..core.cache import get_cache, FunctionSummaryCache
from ..core.agent_logger import get_agent_log_manager, AgentStatus
from ..core.cli_logger import CLILogger
from ..models.function import SimpleFunctionSummary
from ..models.callsite import CallsiteInfo, ResolvedCallsite


# ============================================================================
# 工具函数定义（用于 Tool Call）
# ============================================================================

def get_sub_function_summary(
        line_number: int,
        column_number: int,
        function_identifier: str,
        arguments: List[str],
        call_text: str,
) -> Dict[str, Any]:
    """
    获取指定子函数的摘要信息。
    
    当分析当前函数需要了解某个子函数的行为和约束时，调用此工具获取子函数摘要。
    通过提供调用点的位置信息（行号、列号、函数标识符等），Agent 会自动解析出具体的函数。
    
    通常用于：
    - 子函数涉及关键安全检查
    - 子函数处理污点数据
    - 子函数返回值影响当前函数逻辑
    - 子函数执行内存操作
    
    Args:
        line_number: 调用所在行号（从代码左侧的方括号中获取，如 [ 8] 表示第8行）
        column_number: 调用所在列号（函数名开始的列）
        function_identifier: 目标函数唯一标识符（如 "sub_13E15CC", "memcpy", "Lcom/example/App;->log(Ljava/lang/String;)V"）
        arguments: 参数表达式列表（如 ["ptr", "size", "data"]）
        call_text: 完整调用文本（包含参数和调用语句，如 "result = sub_13E15CC(ptr, size);")
    
    Returns:
        子函数摘要信息字典
    
    Example:
        对于代码：
        ```
        [   8]   result = sub_13E15CC(**(*(result + 272) + 72LL), *a2, &v3);
        ```
        
        调用参数：
        - line_number: 8
        - column_number: 16
        - function_identifier: "sub_13E15CC"
        - arguments: ["**(*(result + 272) + 72LL)", "*a2", "&v3"]
        - call_text: "result = sub_13E15CC(**(*(result + 272) + 72LL), *a2, &v3);"
    """
    return {
        "action": "get_sub_function_summary",
        "callsite": {
            "line_number": line_number,
            "column_number": column_number,
            "function_identifier": function_identifier,
            "arguments": arguments,
            "call_text": call_text,
        }
    }


def submit_function_summary(
        behavior_summary: str,
        param_constraints: List[str],
        return_value_meaning: str,
        global_var_operations: str = "",
) -> Dict[str, Any]:
    """
    提交当前函数的最终摘要。
    
    在分析完源码和获取必要的子函数摘要后，调用此工具提交最终分析结果。
    
    Args:
        behavior_summary: 函数行为描述（50字以内），如 "验证输入参数并执行内存拷贝"
        param_constraints: 参数约束列表（纯文本），如 ["ptr != NULL", "size > 0", "len <= 1024"]
        return_value_meaning: 返回值含义（50字以内），如 "返回0表示成功，负数表示错误码"
        global_var_operations: 全局变量操作描述（100字以内），如 "读取 g_config，可能修改 g_state"
    
    Returns:
        函数摘要字典
    """
    return {
        "action": "submit_summary",
        "behavior_summary": behavior_summary,
        "param_constraints": param_constraints,
        "return_value_meaning": return_value_meaning,
        "global_var_operations": global_var_operations,
    }


# ============================================================================
# 数据结构定义
# ============================================================================

@dataclass
class SubFunctionSummary:
    """子函数摘要信息（精简版）"""
    function_identifier: str
    function_name: str
    behavior_summary: str
    param_constraints: List[str] = field(default_factory=list)
    return_value_meaning: str = ""
    global_var_operations: str = ""

    def to_text(self) -> str:
        """转换为纯文本格式"""
        lines = [
            f"函数: {self.function_name}",
            f"标识符: {self.function_identifier}",
            f"行为: {self.behavior_summary}",
        ]
        if self.param_constraints:
            lines.append("参数约束:")
            for c in self.param_constraints:
                lines.append(f"  - {c}")
        else:
            lines.append("参数约束: 无")

        lines.append(f"返回值: {self.return_value_meaning}")
        lines.append(f"全局变量操作: {self.global_var_operations or '无'}")
        return "\n".join(lines)


class FunctionSummaryAgent:
    """
    函数摘要提取 Agent（多轮交互模式）
    
    采用两阶段多轮交互流程：
    1. LLM 分析源码，通过 Tool Call 请求需要分析的子函数
    2. Agent 递归分析子函数，返回摘要
    3. LLM 基于源码+子函数摘要生成最终摘要
    
    关键设计原则：
    - LLM 智能决策：决定哪些子函数需要分析
    - 多轮交互：动态获取子函数信息
    - 纯文本格式：简洁高效，降低模型要求
    """

    # 类级别的共享缓存，所有 Agent 实例共享
    _shared_cache: Optional[FunctionSummaryCache] = None
    _cache_initialized = False

    def __init__(
            self,
            engine: BaseStaticAnalysisEngine,
            llm_client: ChatOpenAI,
            max_depth: int = 3,
            verbose: bool = False,
            max_llm_retries: int = 3,
            cache_type: str = "redis",
            cache_config: Optional[Dict[str, Any]] = None,
            _analysis_chain: Optional[Set[str]] = None,
            context_text: Optional[str] = None,
            parent_id: Optional[str] = None,
            call_stack: Optional[List[str]] = None,
            source_root: Optional[str] = None,
    ):
        self.engine = engine
        self.llm_client = llm_client
        self.max_llm_retries = max_llm_retries
        self.max_depth = max_depth
        self.verbose = verbose
        self._logger = CLILogger(component="FunctionSummaryAgent", verbose=verbose)
        self.cache_type = cache_type
        self.cache_config = cache_config or {}
        self.source_root = source_root or getattr(engine, 'project_root', '.')

        # Determine engine type
        engine_cls = self.engine.__class__.__name__.lower()
        if 'jeb' in engine_cls:
            self.engine_type = 'jeb'
            self.code_lang = 'java'
        elif 'abc' in engine_cls:
            self.engine_type = 'abc'
            self.code_lang = 'typescript'
        else:
            self.engine_type = 'ida'
            self.code_lang = 'c'

        # 分析链：检测循环调用
        self._analysis_chain = _analysis_chain or set()

        # 文本化分析上下文
        self.context_text = context_text or prompts.FUNCTION_SUMMARY_DEFAULT_CONTEXT

        # Agent 日志相关
        self.agent_id = str(uuid.uuid4())
        self.parent_id = parent_id
        self.call_stack = call_stack or []
        self._agent_logger = get_agent_log_manager()
        self._llm_call_count = 0

        # Tool Call 客户端（懒加载）
        self._tool_llm: Optional[ToolBasedLLMClient] = None
        self._simple_json_llm: Optional[SimpleJSONLLMClient] = None

        # 初始化共享缓存
        self._init_shared_cache()

    def _get_tool_llm(self) -> ToolBasedLLMClient:
        """获取 Tool Call LLM 客户端（懒加载）"""
        if self._tool_llm is None:
            self._tool_llm = ToolBasedLLMClient(
                llm=self.llm_client,
                max_retries=self.max_llm_retries,
                verbose=self.verbose,
                agent_id=self.agent_id,
                log_metadata={"agent_type": "FunctionSummaryAgent"},
            )
        return self._tool_llm

    @staticmethod
    def _get_function_identifier(func_def: Any) -> str:
        """统一获取 FunctionDef 唯一标识符。"""
        if func_def is None:
            return ""
        return getattr(func_def, "function_identifier", "") or ""

    def _get_simple_json_llm(self) -> SimpleJSONLLMClient:
        """获取简单 JSON LLM 客户端（兼容模式）"""
        if self._simple_json_llm is None:
            self._simple_json_llm = SimpleJSONLLMClient(
                llm=self.llm_client,
                max_retries=self.max_llm_retries,
                verbose=self.verbose,
            )
        return self._simple_json_llm

    def _init_shared_cache(self):
        """初始化类级别的共享缓存"""
        if not FunctionSummaryAgent._cache_initialized:
            namespace = self.cache_config.get("namespace", "func_summary")
            # 默认缓存 7 天 (604800 秒)，函数摘要不会频繁变化
            ttl = self.cache_config.get("ttl", 604800)
            cache_type = self.cache_config.get("type", "redis")

            if cache_type != "redis":
                cache_type = "redis"

            cache_kwargs = {
                "host": self.cache_config.get("host", "localhost"),
                "port": self.cache_config.get("port", 6379),
                "db": self.cache_config.get("db", 0),
            }
            if self.cache_config.get("password"):
                cache_kwargs["password"] = self.cache_config["password"]

            cache = get_cache(cache_type, namespace=namespace, ttl=ttl, **cache_kwargs)
            cache.ensure_available()

            FunctionSummaryAgent._shared_cache = FunctionSummaryCache(
                cache=cache,
                namespace=namespace,
                default_ttl=ttl,
                verbose=self.verbose,
            )
            FunctionSummaryAgent._cache_initialized = True
     
    @property
    def cache(self) -> FunctionSummaryCache:
        """获取共享缓存实例"""
        return FunctionSummaryAgent._shared_cache

    def log(self, message: str, level: str = "INFO"):
        """打印日志"""
        if not self.verbose:
            return
        self._logger.log(level=level, event="summary_agent.event", message=message)

    async def analyze(
            self,
            function_identifier: str,
    ) -> SimpleFunctionSummary:
        """
        分析函数并生成摘要（递归分析子函数）

        Args:
            function_identifier: 函数唯一标识符（全局唯一）

        Returns:
            SimpleFunctionSummary 对象
        """
        # 记录 Agent 执行开始
        self._agent_logger.log_execution_start(
            agent_id=self.agent_id,
            agent_type="FunctionSummaryAgent",
            target_function=function_identifier,
            parent_id=self.parent_id,
            call_stack=self.call_stack.copy(),
            metadata={
                "max_depth": self.max_depth,
                "current_stack_depth": len(self.call_stack),
            }
        )

        # 检查循环调用
        if function_identifier in self._analysis_chain:
            self.log(f"Circular dependency detected for {function_identifier}, returning empty summary", "WARNING")
            summary = self._create_circular_summary(function_identifier)
            self._agent_logger.log_execution_end(
                agent_id=self.agent_id,
                status=AgentStatus.COMPLETED,
                llm_calls=self._llm_call_count,
                summary="Circular dependency detected",
            )
            return summary

        # 将当前函数加入分析链
        self._analysis_chain.add(function_identifier)

        try:
            # 函数摘要不依赖于上下文，所以 context_hash 为 None
            summary = await self.cache.get_or_compute(
                function_identifier=function_identifier,
                compute_func=lambda: self._do_analyze(function_identifier),
                context_hash=None,
            )

            # 记录 Agent 执行结束
            self._agent_logger.log_execution_end(
                agent_id=self.agent_id,
                status=AgentStatus.COMPLETED,
                llm_calls=self._llm_call_count,
                summary=summary.behavior_summary[:200] if summary.behavior_summary else "",
            )

            return summary
        except Exception as e:
            # 记录执行失败
            self._agent_logger.log_execution_end(
                agent_id=self.agent_id,
                status=AgentStatus.FAILED,
                llm_calls=self._llm_call_count,
                summary="Analysis failed with exception",
                error_message=str(e),
            )
            raise
        finally:
            # 分析完成，从分析链中移除
            self._analysis_chain.discard(function_identifier)

    async def _do_analyze(
            self,
            function_identifier: str,
            current_depth: int = 0,
    ) -> SimpleFunctionSummary:
        """
        实际执行函数分析（单 Tool Call Loop）
        
        在一个对话循环中完成：
        1. LLM 分析代码，按需调用 get_sub_function_summary 获取子函数摘要
        2. 最终调用 submit_function_summary 提交结果
        """
        self.log(f"Starting analysis for {function_identifier} (depth: {current_depth})")

        # 检查递归深度
        if current_depth >= self.max_depth:
            self.log(f"Max depth reached for {function_identifier}, using shallow analysis")
            return await self._shallow_analysis(function_identifier)

        try:
            # 获取函数定义
            func_def = await self.engine.get_function_def(function_identifier=function_identifier)
            if not func_def:
                self.log(f"Failed to get function definition for {function_identifier}", "WARNING")
                return self._create_empty_summary(function_identifier)

            # 构建提示词
            user_prompt = prompts.FUNCTION_SUMMARY_ANALYSIS_TEMPLATE.format(
                func_name=func_def.name,
                func_identifier=func_def.function_identifier,
                func_signature=func_def.signature,
                code=func_def.code,
                context_text=self.context_text,
                code_lang=self.code_lang,
            )

            # 单 Tool Call Loop：交互直到 LLM 提交最终结果
            return await self._tool_call_loop(
                user_prompt=user_prompt,
                func_def=func_def,
                current_depth=current_depth,
            )

        except Exception as e:
            self.log(f"Analysis failed for {function_identifier}: {str(e)}", "ERROR")
            return await self._fallback_analysis(function_identifier)

    async def _tool_call_loop(
            self,
            user_prompt: str,
            func_def: Any,
            current_depth: int,
    ) -> SimpleFunctionSummary:
        """
        Tool Call Loop：与 LLM 多轮交互，按需获取子函数摘要
        """
        messages: List[BaseMessage] = [HumanMessage(content=user_prompt)]

        # 已获取的子函数摘要缓存（避免重复分析）
        sub_summaries: Dict[str, SubFunctionSummary] = {}

        tool_llm = self._get_tool_llm()
        max_rounds = 5

        for round_num in range(max_rounds):
            self.log(f"Tool Call Loop - Round {round_num + 1}")

            result = await tool_llm.atool_call(
                messages=messages,
                tools=[get_sub_function_summary, submit_function_summary],
                system_prompt=prompts.get_function_summary_system_prompt(self.engine_type),
                allow_text_response=True,
            )
            self._llm_call_count += 1

            if not result.tool_calls:
                # 没有 tool call，尝试解析文本响应
                if result.content:
                    parsed = self._parse_text_summary(
                        result.content,
                        self._get_function_identifier(func_def),
                    )
                    if parsed.behavior_summary:
                        return parsed
                    # 追加消息要求使用 tool
                    messages.append(AIMessage(content=result.content))
                    messages.append(HumanMessage(
                        content="请使用工具：get_sub_function_summary 获取子函数摘要，或 submit_function_summary 提交最终结果。"
                    ))
                    continue
                else:
                    break

            # 分类处理 tool calls
            submit_calls = []
            get_summary_calls = []

            for tc in result.tool_calls:
                tool_name = tc.get('name')
                if tool_name == 'submit_function_summary':
                    submit_calls.append(tc)
                elif tool_name == 'get_sub_function_summary':
                    get_summary_calls.append(tc)

            # 优先处理 submit（最终结果）
            if submit_calls:
                tc = submit_calls[0]
                tool_args = tc.get('args', {})
                return SimpleFunctionSummary(
                    function_identifier=self._get_function_identifier(func_def),
                    behavior_summary=tool_args.get('behavior_summary', ''),
                    param_constraints=tool_args.get('param_constraints', []),
                    return_value_meaning=tool_args.get('return_value_meaning', ''),
                    global_var_operations=tool_args.get('global_var_operations', ''),
                )

            # 并发获取所有子函数摘要
            if get_summary_calls:
                # 解析 callsite 信息并去重
                callsites_to_fetch: List[CallsiteInfo] = []
                callsite_to_tool: Dict[str, Any] = {}  # signature -> tool_call

                for tc in get_summary_calls:
                    callsite_data = tc.get('args', {})
                    if callsite_data:
                        callsite = CallsiteInfo.from_dict(callsite_data)
                        # 临时使用 function_identifier 作为 key，后面会解析成真正的标识符
                        temp_key = f"{callsite.function_identifier}:{callsite.line_number}"
                        if temp_key not in [f"{c.function_identifier}:{c.line_number}" for c in callsites_to_fetch]:
                            callsites_to_fetch.append(callsite)
                            callsite_to_tool[temp_key] = tc

                # 并发解析 callsite 并获取摘要
                if callsites_to_fetch:
                    self.log(f"Batch resolving {len(callsites_to_fetch)} callsites and fetching summaries")

                    # 第一步：解析所有 callsite 为函数标识符
                    resolve_tasks = [
                        self._resolve_callsite(
                            callsite, 
                            self._get_function_identifier(func_def) if func_def else None,
                            func_def.code if func_def else None
                        )
                        for callsite in callsites_to_fetch
                    ]
                    resolved_identifiers = await asyncio.gather(*resolve_tasks, return_exceptions=True)

                    # 第二步：获取解析成功的函数摘要
                    fetch_tasks = []
                    identifier_map: Dict[str, CallsiteInfo] = {}  # function_identifier -> callsite

                    for callsite, resolved in zip(callsites_to_fetch, resolved_identifiers):
                        if isinstance(resolved, Exception):
                            self.log(
                                f"Failed to resolve callsite {callsite.function_identifier}:{callsite.line_number}: {resolved}",
                                "WARNING")
                            temp_key = f"{callsite.function_identifier}:{callsite.line_number}"
                            sub_summaries[temp_key] = SubFunctionSummary(
                                function_identifier=callsite.function_identifier,
                                function_name=callsite.function_identifier,
                                behavior_summary=f"解析调用点失败: {str(resolved)}",
                            )
                        elif resolved:
                            identifier_map[resolved] = callsite
                            fetch_tasks.append(self._get_sub_function_summary(resolved, current_depth))
                        else:
                            # 解析失败，使用函数标识符作为回退
                            temp_key = f"{callsite.function_identifier}:{callsite.line_number}"
                            sub_summaries[temp_key] = SubFunctionSummary(
                                function_identifier=callsite.function_identifier,
                                function_name=callsite.function_identifier,
                                behavior_summary=f"无法解析调用点，请检查函数标识符 '{callsite.function_identifier}' 和行号 {callsite.line_number}",
                            )

                    # 并发获取摘要
                    if fetch_tasks:
                        summary_results = await asyncio.gather(*fetch_tasks, return_exceptions=True)
                        for (identifier, result) in zip(identifier_map.keys(), summary_results):
                            callsite = identifier_map[identifier]
                            temp_key = f"{callsite.function_identifier}:{callsite.line_number}"

                            if isinstance(result, Exception):
                                self.log(f"Failed to get summary for {identifier}: {result}", "WARNING")
                                sub_summaries[temp_key] = SubFunctionSummary(
                                    function_identifier=identifier,
                                    function_name=callsite.function_identifier,
                                    behavior_summary=f"获取摘要失败: {str(result)}",
                                )
                            else:
                                sub_summaries[temp_key] = result

                # 构建 ToolMessage 响应
                ai_tool_calls = []
                tool_messages = []

                for tc in get_summary_calls:
                    tool_id = tc.get('id', f'call_{round_num}_{len(ai_tool_calls)}')
                    callsite_data = tc.get('args', {})

                    if callsite_data:
                        temp_key = f"{callsite_data.get('function_identifier')}:{callsite_data.get('line_number')}"
                        summary = sub_summaries.get(temp_key)
                    else:
                        summary = None

                    tool_response = summary.to_text() if summary else "无法获取该函数摘要"

                    ai_tool_calls.append(tc)
                    tool_messages.append(ToolMessage(content=tool_response, tool_call_id=tool_id))

                # 构建 AIMessage，包含 tool_calls 的描述信息以便日志记录
                def _format_tool_call(tc):
                    name = tc.get('name', 'unknown')
                    args = tc.get('args', {})
                    if args:
                        # 格式化参数为 key=value 形式
                        args_str = ", ".join([f"{k}={repr(v)[:100]}" for k, v in args.items()])
                        return f"调用 {name}({args_str})"
                    return f"调用 {name}()"

                tool_call_desc = "; ".join([_format_tool_call(tc) for tc in ai_tool_calls])
                ai_content = f"[Tool Call] {tool_call_desc}" if ai_tool_calls else "[Tool Call] 请求工具调用"

                messages.extend([
                    AIMessage(content=ai_content, tool_calls=ai_tool_calls),
                    *tool_messages,
                ])

        # 循环结束仍未获取结果，尝试最后解析
        self.log("Tool Call Loop ended without final submission, trying fallback", "WARNING")
        if messages:
            last_ai_msg = None
            for msg in reversed(messages):
                if isinstance(msg, AIMessage) and msg.content:
                    last_ai_msg = msg.content
                    break
            if last_ai_msg:
                return self._parse_text_summary(
                    last_ai_msg,
                    self._get_function_identifier(func_def),
                )

        return self._create_empty_summary(self._get_function_identifier(func_def))

    async def _resolve_callsite(
            self,
            callsite: CallsiteInfo,
            caller_identifier: Optional[str],
            caller_code: Optional[str] = None,
    ) -> Optional[str]:
        """
        解析 callsite 为函数标识符
        
        通过 Engine 统一处理（Engine 内部包含了静态分析和 CallsiteAgent 回退逻辑）
        
        参数:
            callsite: 调用点信息
            caller_identifier: 调用者函数标识符
            caller_code: 调用者源代码
        
        返回:
            解析后的函数标识符，失败返回 None
        """
        try:
            # 委托给 Engine 处理
            function_identifier = await self.engine.resolve_function_by_callsite(
                callsite=callsite,
                caller_identifier=caller_identifier,
                caller_code=caller_code,
            )
            
            if function_identifier:
                self.log(f"Resolved callsite {callsite.function_identifier}:{callsite.line_number} -> {function_identifier}")
                return function_identifier
            
            self.log(
                f"Failed to resolve callsite {callsite.function_identifier}:{callsite.line_number}, using function identifier as fallback")
            return callsite.function_identifier
            
        except Exception as e:
            self.log(f"Error resolving callsite: {e}", "WARNING")
            return callsite.function_identifier

    async def _get_sub_function_summary(
            self,
            function_identifier: str,
            current_depth: int,
    ) -> SubFunctionSummary:
        """
        获取单个子函数的摘要（创建子 Agent 递归分析）
        """
        try:
            remaining_depth = self.max_depth - current_depth - 1
            if remaining_depth <= 0:
                self.log(f"Max depth reached for sub-function {function_identifier}")
                return SubFunctionSummary(
                    function_identifier=function_identifier,
                    function_name=function_identifier.split('(')[0] if '(' in function_identifier else function_identifier,
                    behavior_summary="达到最大分析深度",
                )

            # 检查循环依赖
            if function_identifier in self.call_stack:
                return SubFunctionSummary(
                    function_identifier=function_identifier,
                    function_name=function_identifier.split('(')[0] if '(' in function_identifier else function_identifier,
                    behavior_summary="循环依赖，跳过分析",
                )

            # 创建子 Agent
            new_call_stack = self.call_stack.copy()
            new_call_stack.append(function_identifier)

            sub_agent = FunctionSummaryAgent(
                engine=self.engine,
                llm_client=self.llm_client,
                max_depth=remaining_depth,
                verbose=self.verbose,
                max_llm_retries=self.max_llm_retries,
                cache_type=self.cache_type,
                cache_config=self.cache_config,
                _analysis_chain=self._analysis_chain,
                context_text=self.context_text,
                parent_id=self.agent_id,
                call_stack=new_call_stack,
            )

            summary = await sub_agent.analyze(function_identifier=function_identifier)

            return SubFunctionSummary(
                function_identifier=function_identifier,
                function_name=function_identifier.split('(')[0] if '(' in function_identifier else function_identifier,
                behavior_summary=summary.behavior_summary,
                param_constraints=summary.param_constraints,
                return_value_meaning=summary.return_value_meaning,
                global_var_operations=summary.global_var_operations,
            )

        except Exception as e:
            self.log(f"Failed to get sub-function summary for {function_identifier}: {e}", "WARNING")
            return SubFunctionSummary(
                function_identifier=function_identifier,
                function_name=function_identifier.split('(')[0] if '(' in function_identifier else function_identifier,
                behavior_summary=f"获取摘要失败: {str(e)}",
            )

    def _parse_sub_function_selection(
            self,
            content: str,
            available_functions: List[Dict[str, str]],
    ) -> List[str]:
        """
        从文本响应中解析子函数选择
        
        尝试多种格式解析，返回函数标识符列表。
        """
        selected = []
        content_lower = content.lower()

        # 尝试提取 ```json 块
        if "```json" in content:
            try:
                start = content.find("```json") + 7
                end = content.find("```", start)
                if end > start:
                    json_str = content[start:end].strip()
                    data = json.loads(json_str)
                    if isinstance(data, list):
                        return data[:5]
                    if isinstance(data, dict) and "signatures" in data:
                        return data["signatures"][:5]
            except Exception:
                pass

        # 尝试匹配函数名或签名
        available_sigs = {af["signature"] for af in available_functions}
        available_names = {af["name"]: af["signature"] for af in available_functions}

        for line in content.split('\n'):
            line = line.strip()
            # 检查是否是签名
            if line in available_sigs:
                selected.append(line)
            else:
                # 检查是否是函数名
                for name, sig in available_names.items():
                    if name in line and sig not in selected:
                        selected.append(sig)
                        break

        return selected[:5]

    def _parse_text_summary(self, content: str, function_identifier: str) -> SimpleFunctionSummary:
        """从文本响应解析函数摘要"""
        behavior = ""
        param_constraints = []
        return_value = ""
        global_ops = ""

        lines = content.strip().split('\n')
        current_section = None

        for line in lines:
            line = line.strip()
            if not line:
                continue

            if '函数行为' in line or 'behavior' in line.lower():
                current_section = 'behavior'
                if ':' in line or '：' in line:
                    behavior = line.split(':', 1)[-1].split('：', 1)[-1].strip()
            elif '参数约束' in line or 'constraints' in line.lower():
                current_section = 'constraints'
            elif '返回值' in line or 'return' in line.lower():
                current_section = 'return'
                if ':' in line or '：' in line:
                    return_value = line.split(':', 1)[-1].split('：', 1)[-1].strip()
            elif '全局变量' in line or 'global' in line.lower():
                current_section = 'global'
                if ':' in line or '：' in line:
                    global_ops = line.split(':', 1)[-1].split('：', 1)[-1].strip()
            elif current_section == 'constraints' and line.startswith('-'):
                # 参数约束列表项
                constraint = line[1:].strip()
                if constraint and constraint != '无':
                    param_constraints.append(constraint)
            elif current_section == 'behavior' and not behavior:
                behavior = line
            elif current_section == 'return' and not return_value:
                return_value = line
            elif current_section == 'global' and not global_ops:
                global_ops = line

        return SimpleFunctionSummary(
            function_identifier=function_identifier,
            behavior_summary=behavior,
            param_constraints=param_constraints,
            return_value_meaning=return_value,
            global_var_operations=global_ops,
        )

    async def _shallow_analysis(
            self,
            function_identifier: str,
    ) -> SimpleFunctionSummary:
        """
        浅层分析（达到最大深度时使用）
        
        只分析当前函数，不递归分析子函数。
        """
        try:
            func_def = await self.engine.get_function_def(function_identifier=function_identifier)
            if not func_def:
                return self._create_empty_summary(function_identifier)

            user_prompt = prompts.SIMPLE_TEXT_SUMMARY_PROMPT.format(
                func_name=func_def.name,
                func_identifier=func_def.function_identifier,
                func_signature=func_def.signature,
                code=func_def.code,
                code_lang=self.code_lang,
            )

            messages = [HumanMessage(content=user_prompt)]

            json_llm = self._get_simple_json_llm()
            result = await json_llm.ajson_call(
                messages=messages,
                json_hint='''请以 JSON 格式返回：
{
    "behavior_summary": "行为描述",
    "param_constraints": ["约束1", "约束2"],
    "return_value_meaning": "返回值含义",
    "global_var_operations": "全局变量操作"
}''',
            )

            self._llm_call_count += 1

            return SimpleFunctionSummary(
                function_identifier=function_identifier,
                behavior_summary=result.get('behavior_summary', ''),
                param_constraints=result.get('param_constraints', []),
                return_value_meaning=result.get('return_value_meaning', ''),
                global_var_operations=result.get('global_var_operations', ''),
            )

        except Exception as e:
            self.log(f"Shallow analysis failed: {e}", "WARNING")
            return self._create_empty_summary(function_identifier)

    async def _fallback_analysis(
            self,
            function_identifier: str,
    ) -> SimpleFunctionSummary:
        """
        降级分析（Tool Call 失败时使用）
        
        使用纯文本 JSON 模式进行分析。
        """
        try:
            func_def = await self.engine.get_function_def(function_identifier=function_identifier)
            if not func_def:
                return self._create_empty_summary(function_identifier)

            user_prompt = prompts.SIMPLE_TEXT_SUMMARY_PROMPT.format(
                func_name=func_def.name,
                func_identifier=func_def.function_identifier,
                func_signature=func_def.signature,
                code=func_def.code,
                code_lang=self.code_lang,
            )

            messages = [HumanMessage(content=user_prompt)]

            json_llm = self._get_simple_json_llm()
            result = await json_llm.ajson_call(
                messages=messages,
                json_hint='''请以 JSON 格式返回：
{
    "behavior_summary": "行为描述",
    "param_constraints": ["约束1", "约束2"],
    "return_value_meaning": "返回值含义",
    "global_var_operations": "全局变量操作"
}''',
            )

            self._llm_call_count += 1

            return SimpleFunctionSummary(
                function_identifier=function_identifier,
                behavior_summary=result.get('behavior_summary', ''),
                param_constraints=result.get('param_constraints', []),
                return_value_meaning=result.get('return_value_meaning', ''),
                global_var_operations=result.get('global_var_operations', ''),
            )

        except Exception as e:
            self.log(f"Fallback analysis failed: {e}", "ERROR")
            return self._create_empty_summary(function_identifier)

    def _create_empty_summary(self, function_identifier: str) -> SimpleFunctionSummary:
        """创建空的函数摘要"""
        return SimpleFunctionSummary(
            function_identifier=function_identifier,
            behavior_summary="分析失败，无法获取函数信息",
            param_constraints=[],
            return_value_meaning="",
            global_var_operations="",
        )

    def _create_circular_summary(self, function_identifier: str) -> SimpleFunctionSummary:
        """创建循环调用摘要"""
        return SimpleFunctionSummary(
            function_identifier=function_identifier,
            behavior_summary="检测到循环调用，该函数在当前分析链中已被分析",
            param_constraints=[],
            return_value_meaning="",
            global_var_operations="",
        )
