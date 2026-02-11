#!/usr/bin/env python3
"""
Callsite 调用点数据模型

定义函数调用点的核心数据结构，用于描述源代码中的调用位置信息。
LLM 提供 callsite 信息，Agent 通过引擎解析出具体函数签名。
"""

from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field


@dataclass
class CallsiteInfo:
    """
    调用点信息 - 描述源代码中函数调用的位置
    
    用于 LLM 指定需要分析的子函数位置，由引擎解析为具体的函数标识符。
    这种设计使 LLM 无需关心具体的函数标识符格式，更通用且易于理解。
    
    Example:
        ```c
        [   8]   result = sub_13E15CC(**(*(result + 272) + 72LL), *a2, &v3);
        ```
        
        对应的 CallsiteInfo:
        - file_path: "src/main.c"
        - line_number: 8
        - column_number: 16
        - function_identifier: "sub_13E15CC"
        - arguments: ["**(*(result + 272) + 72LL)", "*a2", "&v3"]
        - call_text: "result = sub_13E15CC(**(*(result + 272) + 72LL), *a2, &v3);"
    """
    file_path: str                      # 调用所在文件路径
    line_number: int                    # 调用所在行号（从0或1开始，取决于代码显示格式）
    column_number: int                  # 调用所在列号（函数名开始的列）
    function_identifier: str            # 目标函数唯一标识符（如 "sub_13E15CC", "memcpy"）
    arguments: List[str] = field(default_factory=list)  # 参数表达式列表
    call_text: str = ""                 # 完整调用文本（包含参数和语句）
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "file_path": self.file_path,
            "line_number": self.line_number,
            "column_number": self.column_number,
            "function_identifier": self.function_identifier,
            "arguments": self.arguments,
            "call_text": self.call_text,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CallsiteInfo":
        """从字典创建对象"""
        return cls(
            file_path=data.get("file_path", ""),
            line_number=data.get("line_number", 0),
            column_number=data.get("column_number", 0),
            function_identifier=data.get("function_identifier", ""),
            arguments=data.get("arguments", []),
            call_text=data.get("call_text", ""),
        )
    
    def __hash__(self) -> int:
        """支持作为字典 key 用于缓存"""
        return hash((self.file_path, self.line_number, self.column_number, self.function_identifier))

    def __eq__(self, other: object) -> bool:
        """相等性比较"""
        if not isinstance(other, CallsiteInfo):
            return False
        return (
            self.file_path == other.file_path and
            self.line_number == other.line_number and
            self.column_number == other.column_number and
            self.function_identifier == other.function_identifier
        )


@dataclass
class ResolvedCallsite:
    """
    解析后的调用点信息
    
    包含原始 callsite 信息和解析得到的函数标识符。
    用于缓存解析结果，避免重复解析。
    """
    callsite: CallsiteInfo              # 原始调用点信息
    function_identifier: str            # 解析得到的函数唯一标识符
    resolved_successfully: bool = True  # 是否成功解析
    error_message: str = ""             # 解析失败时的错误信息
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "callsite": self.callsite.to_dict(),
            "function_identifier": self.function_identifier,
            "resolved_successfully": self.resolved_successfully,
            "error_message": self.error_message,
        }


__all__ = ['CallsiteInfo', 'ResolvedCallsite']
