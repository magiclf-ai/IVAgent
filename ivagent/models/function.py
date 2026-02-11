#!/usr/bin/env python3
"""
函数摘要数据模型

定义函数摘要的核心数据结构，用于描述函数行为、参数约束、返回值
"""

from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field


@dataclass
class SimpleFunctionSummary:
    """
    精简函数摘要 - 纯文本表示
    
    只包含必要信息，使用纯文本格式降低对 LLM 的要求，
    提升响应速度和解析稳定性。
    """
    function_identifier: str            # 函数/方法唯一标识符（全局唯一，跨语言通用）
    
    # 函数行为描述（50字以内）
    # 例如: "验证输入参数并执行内存拷贝操作"
    behavior_summary: str = ""
    
    # 参数约束列表（纯文本表示）
    # 格式: ["参数1 > 0", "参数2 != NULL", "参数3 在 [0, 100] 范围内"]
    param_constraints: List[str] = field(default_factory=list)
    
    # 返回值含义（50字以内）
    # 例如: "返回0表示成功，负数表示错误码"
    return_value_meaning: str = ""
    
    # 全局变量操作描述（100字以内）
    # 例如: "读取全局配置变量 g_config，可能修改 g_state"
    global_var_operations: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "function_identifier": self.function_identifier,
            "behavior_summary": self.behavior_summary,
            "param_constraints": self.param_constraints,
            "return_value_meaning": self.return_value_meaning,
            "global_var_operations": self.global_var_operations,
        }
    
    @classmethod
    def from_text(
            cls,
            function_identifier: str,
            behavior_summary: str = "",
            param_constraints: Optional[List[str]] = None,
            return_value_meaning: str = "",
            global_var_operations: str = "",
    ) -> "SimpleFunctionSummary":
        """从文本快速创建摘要"""
        return cls(
            function_identifier=function_identifier,
            behavior_summary=behavior_summary,
            param_constraints=param_constraints or [],
            return_value_meaning=return_value_meaning,
            global_var_operations=global_var_operations,
        )


__all__ = ['SimpleFunctionSummary']
