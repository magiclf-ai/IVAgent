#!/usr/bin/env python3
"""
条件约束数据模型

定义前置条件、调用栈等数据结构
支持约束在函数调用链中的传播（使用纯文本格式）
"""

from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field


@dataclass
class Precondition:
    """
    前置条件定义
    
    用于描述目标函数的已知约束和特性，帮助 Agent 更精准地分析。
    使用文本化配置，降低对 LLM 的要求。
    """
    name: str                           # 条件名称/标识
    description: str                    # 条件描述
    target: str = "generic"             # 适用目标类型
    
    # 文本化前置条件（直接追加到提示词）
    text_content: Optional[str] = None
    # 示例: """
    # ## 前置条件
    # 1. 回调函数有两个参数：pThis 和 pMsg
    # 2. pThis 是内核分配的对象指针，攻击者不可控
    # 3. pMsg 指向攻击者控制的消息数据，需要严格检查
    # """
    
    # 污点源定义（简单列表）
    taint_sources: List[str] = field(default_factory=list)
    # 示例: ["param2", "param2->data", "msg->payload"]
    
    # 额外元数据
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "name": self.name,
            "description": self.description,
            "target": self.target,
            "text_content": self.text_content,
            "taint_sources": self.taint_sources,
            "metadata": self.metadata,
        }
    
    @classmethod
    def from_text(
        cls,
        name: str,
        text_content: str,
        description: str = "",
        target: str = "generic",
        taint_sources: Optional[List[str]] = None,
        **kwargs
    ) -> "Precondition":
        """
        从文本快速创建前置条件
        
        Args:
            name: 条件名称
            text_content: 文本化前置条件内容
            description: 可选的描述
            target: 目标类型
            taint_sources: 可选的污点源列表
            **kwargs: 其他元数据
            
        Returns:
            Precondition 实例
        """
        return cls(
            name=name,
            description=description or name,
            target=target,
            text_content=text_content,
            taint_sources=taint_sources or [],
            metadata=kwargs,
        )


@dataclass
class CallStackFrame:
    """
    调用栈帧
    
    表示调用链中的一个节点，包含函数信息和调用点细节
    用于构建可追溯、可分析的完整调用路径
    """
    function_signature: str             # 函数签名
    function_name: Optional[str] = None # 函数名（简化显示）
    
    # 调用点信息（由父函数调用当前函数时的上下文）
    call_line: int = 0                  # 调用所在行号
    call_code: str = ""                 # 调用语句代码（如 "inner_func(a, b);"）
    caller_function: str = ""           # 调用者函数签名
    
    # 参数信息（调用时传递的参数）
    arguments: List[str] = field(default_factory=list)  # 参数表达式列表
    
    # 参数约束信息（调用时的详细约束，纯文本格式）
    # 格式: ["ptr != NULL", "0 < size <= 1024"]
    argument_constraints: List[str] = field(default_factory=list)
    
    # 额外元数据
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "function_signature": self.function_signature,
            "function_name": self.function_name,
            "call_line": self.call_line,
            "call_code": self.call_code,
            "caller_function": self.caller_function,
            "arguments": self.arguments,
            "argument_constraints": self.argument_constraints,
            "metadata": self.metadata,
        }
    
    def to_short_string(self) -> str:
        """转换为简短字符串表示"""
        name = self.function_name or self.function_signature
        if self.call_line > 0:
            return f"{name}:{self.call_line}"
        return name
    
    def to_detailed_string(self) -> str:
        """转换为详细字符串表示"""
        lines = [f"Function: {self.function_name or self.function_signature}"]
        if self.call_line > 0:
            lines.append(f"  Line: {self.call_line}")
        if self.call_code:
            code = self.call_code[:60] + "..." if len(self.call_code) > 60 else self.call_code
            lines.append(f"  Code: {code}")
        if self.caller_function:
            lines.append(f"  Called by: {self.caller_function}")
        return "\n".join(lines)


@dataclass
class FunctionContext:
    """
    函数分析上下文
    
    包含函数参数约束、父函数传递的约束等信息
    用于在函数调用链中传播约束条件（纯文本格式）
    """
    function_signature: str             # 函数签名
    function_name: Optional[str] = None # 函数名
    
    # 父函数传递的约束（纯文本格式）
    # 格式: ["ptr != NULL", "0 < size <= 1024"]
    parent_constraints: List[str] = field(default_factory=list)
    
    # 调用链 - 简单版本（函数签名列表）
    call_stack: List[str] = field(default_factory=list)
    
    # 详细调用栈 - 包含调用点信息
    call_stack_detailed: List[CallStackFrame] = field(default_factory=list)
    
    # 递归深度
    depth: int = 0
    max_depth: int = 3
    
    # 污点源
    taint_sources: List[str] = field(default_factory=list)
    
    # 前置条件（用于传递目标特定的约束信息）
    precondition: Optional[Precondition] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "function_signature": self.function_signature,
            "function_name": self.function_name,
            "parent_constraints": self.parent_constraints,
            "call_stack": self.call_stack,
            "call_stack_detailed": [frame.to_dict() for frame in self.call_stack_detailed],
            "depth": self.depth,
            "max_depth": self.max_depth,
            "taint_sources": self.taint_sources,
            "precondition": self.precondition.to_dict() if self.precondition else None,
        }
    
    def get_call_stack_simple(self) -> List[str]:
        """获取简单调用栈（函数签名列表）"""
        if self.call_stack:
            return self.call_stack
        return [frame.function_signature for frame in self.call_stack_detailed]
    
    def build_call_path_with_lines(self) -> List[Dict[str, Any]]:
        """构建带行号的调用路径"""
        path = []
        for frame in self.call_stack_detailed:
            path.append({
                "function": frame.function_signature,
                "function_name": frame.function_name,
                "line_number": frame.call_line,
                "code_snippet": frame.call_code,
                "caller": frame.caller_function,
            })
        # 添加当前函数
        path.append({
            "function": self.function_signature,
            "function_name": self.function_name,
            "line_number": 0,
            "code_snippet": "",
            "caller": self.call_stack_detailed[-1].function_signature if self.call_stack_detailed else "",
        })
        return path


__all__ = ['Precondition', 'CallStackFrame', 'FunctionContext']
