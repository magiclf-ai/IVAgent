#!/usr/bin/env python3
"""
BaseEngine - 异步分析引擎抽象基类

为所有静态分析引擎提供统一的异步接口
支持高并发分析场景
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, AsyncIterator
from dataclasses import dataclass, field
from enum import Enum
import asyncio

from ..models.callsite import CallsiteInfo, ResolvedCallsite
from ..core.cli_logger import CLILogger


class TargetType(Enum):
    """分析目标类型"""
    FUNCTION = "function"
    CLASS = "class"
    FIELD = "field"
    VARIABLE = "variable"


@dataclass
class FunctionDef:
    """函数定义信息"""
    function_identifier: str                # 函数唯一标识符（跨语言唯一锚点）
    signature: str                          # 函数可读签名（用于展示）
    name: str                               # 函数名
    code: str                               # 函数代码/伪代码
    file_path: Optional[str] = None         # 文件路径
    start_line: int = 0                     # 起始行号
    end_line: int = 0                       # 结束行号
    parameters: List[Dict[str, Any]] = field(default_factory=list)  # 参数列表
    return_type: Optional[str] = None       # 返回类型
    location: Optional[str] = None          # 位置信息（如地址）
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "function_identifier": self.function_identifier,
            "signature": self.signature,
            "name": self.name,
            "code": self.code,
            "file_path": self.file_path,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "parameters": self.parameters,
            "return_type": self.return_type,
            "location": self.location,
        }


@dataclass
class CallSite:
    """调用点信息"""
    caller_name: str                        # 调用者函数名
    caller_identifier: str                  # 调用者标识符
    callee_name: str                        # 被调用者函数名
    callee_identifier: str                  # 被调用者标识符
    line_number: int                        # 调用所在行号
    file_path: Optional[str] = None         # 文件路径
    call_context: Optional[str] = None      # 调用上下文（代码片段）
    arguments: List[str] = field(default_factory=list)  # 参数表达式
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "caller_name": self.caller_name,
            "caller_identifier": self.caller_identifier,
            "callee_name": self.callee_name,
            "callee_identifier": self.callee_identifier,
            "line_number": self.line_number,
            "file_path": self.file_path,
            "call_context": self.call_context,
            "arguments": self.arguments,
        }


@dataclass
class CrossReference:
    """交叉引用信息"""
    target_type: str                        # 目标类型
    target_signature: str                   # 目标签名
    references: List[Dict[str, Any]] = field(default_factory=list)  # 引用列表
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "target_type": self.target_type,
            "target_signature": self.target_signature,
            "references": self.references,
        }


@dataclass
class VariableConstraint:
    """变量约束信息"""
    var_name: str                           # 变量名
    var_type: Optional[str] = None          # 变量类型
    constraints: List[str] = field(default_factory=list)  # 约束条件列表
    source: Optional[str] = None            # 约束来源
    line_number: int = 0                    # 约束所在行号
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "var_name": self.var_name,
            "var_type": self.var_type,
            "constraints": self.constraints,
            "source": self.source,
            "line_number": self.line_number,
        }


@dataclass
class SearchOptions:
    """函数搜索选项"""
    case_sensitive: bool = False            # 是否区分大小写
    use_regex: bool = False                 # 是否使用正则表达式
    match_full_signature: bool = False      # 是否匹配完整签名（而非仅函数名）
    search_in_code: bool = False            # 是否在函数代码中搜索
    include_class_name: bool = True         # 是否包含类名在搜索范围内（适用于面向对象语言）
    limit: int = 50                         # 返回结果数量限制
    offset: int = 0                         # 分页偏移量
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "case_sensitive": self.case_sensitive,
            "use_regex": self.use_regex,
            "match_full_signature": self.match_full_signature,
            "search_in_code": self.search_in_code,
            "include_class_name": self.include_class_name,
            "limit": self.limit,
            "offset": self.offset,
        }


class SymbolType(Enum):
    """符号类型"""
    FUNCTION = "function"
    CLASS = "class"
    METHOD = "method"
    GLOBAL_VAR = "global_var"
    FIELD = "field"
    VARIABLE = "variable"
    UNKNOWN = "unknown"


@dataclass
class SearchResult:
    """符号搜索结果"""
    name: str                               # 符号名
    identifier: str                         # 符号唯一标识符
    symbol_type: SymbolType                 # 符号类型
    file_path: Optional[str] = None         # 文件路径
    line: int = 0                           # 行号
    match_score: float = 0.0                # 匹配分数（0-1，越高越匹配）
    match_reason: Optional[str] = None      # 匹配原因/说明

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "name": self.name,
            "function_identifier": self.identifier,
            "symbol_type": self.symbol_type.value,
            "file_path": self.file_path,
            "line": self.line,
            "match_score": self.match_score,
            "match_reason": self.match_reason,
        }


class BaseStaticAnalysisEngine(ABC):
    """
    分析引擎抽象基类
    
    所有分析引擎（IDA、JEB、Tree-sitter、Joern）必须实现这些接口
    支持高并发分析场景，所有 IO 操作均为异步
    """
    
    def __init__(
        self,
        target_path: Optional[str] = None,
        max_concurrency: int = 10,
        source_root: Optional[str] = None,
        llm_client: Optional[Any] = None,
        logger: Optional[CLILogger] = None,
    ):
        """
        初始化引擎
        
        参数:
            target_path: 分析目标路径（IDB 路径、APK 路径、源码目录等）
            max_concurrency: 最大并发数
            source_root: 源代码根目录（用于 CallsiteAgent 源码分析）
            llm_client: LLM 客户端（用于 CallsiteAgent）
        """
        self.target_path = target_path
        self._initialized = False
        self._max_concurrency = max_concurrency
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self._llm_client = llm_client
        self._source_root = source_root
        self._logger = logger or CLILogger(component=self.__class__.__name__)

    def _log(self, message: str, level: str = "info", event: str = "engine.event", **fields: Any) -> None:
        """统一引擎日志入口。"""
        self._logger.log(level=level, event=event, message=message, **fields)

    @abstractmethod
    async def get_function_def(
            self,
            function_name: Optional[str] = None,
            function_identifier: Optional[str] = None,
            location: Optional[str] = None,
    ) -> Optional[FunctionDef]:
        """
        异步获取函数定义
        
        参数:
            function_name: 函数名
            function_identifier: 函数唯一标识符（优先使用）
            location: 位置信息（如地址 0x140001000）
        
        返回:
            FunctionDef 对象，失败返回 None
        """
        pass
    
    @abstractmethod
    async def get_callee(
            self,
            function_identifier: str,
    ) -> List[CallSite]:
        """
        异步获取函数内调用的子函数（被调用者）
        
        参数:
            function_identifier: 函数唯一标识符
        
        返回:
            CallSite 列表
        """
        pass
    
    @abstractmethod
    async def get_caller(
            self,
            function_identifier: str,
    ) -> List[CallSite]:
        """
        异步获取调用该函数的父函数（调用者）
        
        参数:
            function_identifier: 函数唯一标识符
        
        返回:
            CallSite 列表
        """
        pass
    
    @abstractmethod
    async def get_cross_reference(
        self,
        target_type: str,
        signature: str,
    ) -> Optional[CrossReference]:
        """
        异步获取交叉引用
        
        参数:
            target_type: 目标类型 ("function", "class", "field", "variable")
            signature: 目标签名
        
        返回:
            CrossReference 对象，失败返回 None
        """
        pass
    
    @abstractmethod
    async def get_variable_constraints(
            self,
            function_identifier: str,
            var_name: str,
            line_number: Optional[int] = None,
    ) -> List[VariableConstraint]:
        """
        异步获取变量在指定位置的约束条件
        
        参数:
            function_identifier: 函数唯一标识符
            var_name: 变量名
            line_number: 行号（可选，默认获取所有约束）
        
        返回:
            VariableConstraint 列表
        """
        pass
    
    async def search_symbol(
        self,
        query: str,
        options: Optional[SearchOptions] = None,
    ) -> List[SearchResult]:
        """
        异步搜索符号（函数、类、全局变量等）
        
        根据关键字搜索匹配的符号。支持多种匹配模式：
        - 简单子串匹配（默认）
        - 正则表达式匹配
        - 大小写敏感/不敏感匹配
        - 在代码中搜索（如果后端支持）
        
        参数:
            query: 搜索关键词
            options: 搜索选项，None 则使用默认选项
        
        返回:
            SearchResult 列表，按 match_score 降序排列，包含符号类型信息
        
        示例:
            # 简单搜索
            results = await engine.search_symbol("memcpy")
            
            # 正则搜索，不区分大小写
            options = SearchOptions(use_regex=True, case_sensitive=False, limit=20)
            results = await engine.search_symbol(r"str.*cpy", options)
            
            # 在代码中搜索
            options = SearchOptions(search_in_code=True, limit=100)
            results = await engine.search_symbol("password", options)
        """
        # 默认实现：返回空列表
        return []
    
    async def batch_get_function_defs(
            self,
            identifiers: List[str],
            max_concurrency: Optional[int] = None,
    ) -> Dict[str, Optional[FunctionDef]]:
        """
        批量异步获取函数定义
        
        参数:
            identifiers: 函数唯一标识符列表
            max_concurrency: 最大并发数（覆盖默认设置）
        
        返回:
            函数标识符 -> FunctionDef 的字典
        """
        semaphore = asyncio.Semaphore(
            max_concurrency or self._max_concurrency
        )
        
        async def _fetch_one(ident: str) -> tuple:
            async with semaphore:
                result = await self.get_function_def(function_identifier=ident)
                return ident, result
        
        tasks = [_fetch_one(ident) for ident in identifiers]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        return {
            ident: result if not isinstance(result, Exception) else None
            for ident, result in results
        }

    async def ping(self) -> bool:
        """
        异步测试引擎连接/可用性
        
        返回:
            是否可用
        """
        return self._initialized
    
    def set_target(self, target_path: str):
        """
        设置分析目标
        
        参数:
            target_path: 分析目标路径
        """
        self.target_path = target_path
    
    async def initialize(self) -> bool:
        """
        异步初始化引擎
        
        返回:
            是否初始化成功
        """
        try:
            await self._do_initialize()
            self._initialized = True
            return True
        except Exception as e:
            self._log(str(e), "error", event="engine.initialize_failed")
            return False
    
    async def resolve_function_by_callsite(
        self,
        callsite: CallsiteInfo,
        caller_identifier: Optional[str] = None,
        caller_code: Optional[str] = None,
    ) -> Optional[str]:
        """
        根据调用点信息解析函数标识符
        
        LLM 提供 callsite 信息（行号、列号、函数名等），引擎根据这些信息
        定位到具体的函数调用点，并返回被调用函数的唯一标识符。
        
        实现策略（Template Method）：
        1. 调用 _resolve_static_callsite 进行引擎特定的静态分析
        2. 如果静态分析失败且配置了 LLM 能力，回退到 CallsiteAgent 进行动态/源码分析
        
        参数:
            callsite: 调用点信息（包含行号、列号、函数名、参数等）
            caller_identifier: 调用者函数标识符（可选，用于上下文定位）
            caller_code: 调用者源代码（可选，用于 CallsiteAgent）
        
        返回:
            被调用函数的唯一标识符，解析失败返回 None
        """
        # 1. 优先尝试静态分析
        function_identifier = await self._resolve_static_callsite(callsite, caller_identifier)
        if function_identifier:
            return function_identifier

        # 2. 如果静态分析失败，尝试使用 CallsiteAgent (如果已配置)
        if self._source_root and self._llm_client and caller_code:
            try:
                # 延迟导入以避免循环依赖
                # 注意：这里假设项目结构支持相对导入
                from ..agents.callsite_agent import CallsiteAgent, ResolvedCallsite
                
                agent = CallsiteAgent(
                    llm_client=self._llm_client,
                    source_root=self._source_root,
                    verbose=False 
                )
                
                # 提取 class 和 method 名（如果可能）
                caller_class = None
                caller_method = caller_identifier
                if caller_identifier and '.' in caller_identifier:
                    parts = caller_identifier.split('.')
                    caller_method = parts[-1]
                    if len(parts) > 1:
                        caller_class = parts[-2]
                        
                resolved_result = await agent.run(
                    callsite_info=callsite,
                    caller_code=caller_code,
                    caller_class=caller_class,
                    caller_method=caller_method
                )
                
                if resolved_result.resolved_successfully and resolved_result.function_identifier:
                    return resolved_result.function_identifier
                    
            except Exception as e:
                # 记录错误但不抛出，保持静默失败
                self._log(str(e), "warning", event="engine.callsite_fallback_failed")
                
        return None

    @abstractmethod
    async def _resolve_static_callsite(
            self,
            callsite: CallsiteInfo,
            caller_identifier: Optional[str] = None,
    ) -> Optional[str]:
        """
        [子类实现] 静态分析：根据调用点信息解析函数标识符
        
        参数:
            callsite: 调用点信息
            caller_identifier: 调用者函数标识符
            
        返回:
            解析后的函数标识符，失败返回 None
        """
        pass
    
    @abstractmethod
    async def _do_initialize(self):
        """
        子类实现具体的异步初始化逻辑
        """
        pass
    
    async def close(self):
        """
        异步关闭引擎，释放资源
        """
        await self._do_close()
        self._initialized = False
    
    async def _do_close(self):
        """
        子类实现具体的异步关闭逻辑
        """
        pass
    
    async def __aenter__(self):
        """异步上下文管理器入口"""
        await self.initialize()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """异步上下文管理器出口"""
        await self.close()
