#!/usr/bin/env python3
"""
函数列表模块

提供获取 IDB 中所有函数的基础 API
"""

import idaapi
import idc
import idautils
from typing import List, Dict, Any, Optional
from dataclasses import dataclass


@dataclass
class FunctionSummary:
    """函数摘要信息"""
    address: int
    name: str
    size: int


def get_function_list(limit: int = 1000) -> List[FunctionSummary]:
    """
    获取函数列表
    
    参数:
        limit: 最大返回数量
    返回:
        FunctionSummary 列表
    """
    functions = []
    count = 0
    
    for ea in idautils.Functions():
        if count >= limit:
            break
        name = idc.get_func_name(ea)
        func = idaapi.get_func(ea)
        functions.append(FunctionSummary(
            address=ea,
            name=name,
            size=func.size() if func else 0
        ))
        count += 1
    
    return functions


def get_function_list_dict(limit: int = 1000) -> List[Dict[str, Any]]:
    """
    获取函数列表（字典格式，兼容旧接口）
    
    参数:
        limit: 最大返回数量
    返回:
        字典列表
    """
    functions = get_function_list(limit)
    return [
        {
            "address": f"0x{f.address:X}",
            "name": f.name,
            "size": f.size,
        }
        for f in functions
    ]
