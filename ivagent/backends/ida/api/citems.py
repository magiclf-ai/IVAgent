#!/usr/bin/env python3
"""
citem 操作模块

基于 DecompiledFunction 提供原子化接口操作 citem
"""

import idaapi
import ida_hexrays
from typing import List, Dict, Any, Optional, Tuple, Set
from dataclasses import dataclass

from ..decompiler import DecompiledFunction
from ..ctree.utils import CtreeUtils


@dataclass
class CitemInfo:
    """citem 信息"""
    index: int
    ea: int
    type_name: str
    text: str
    line_indices: List[int]


def _get_decompiled_function(ea: int) -> Optional[DecompiledFunction]:
    """获取 DecompiledFunction 对象"""
    func_ea = idaapi.get_func(ea)
    if func_ea is None:
        return None
    
    try:
        cfunc = ida_hexrays.decompile(func_ea.start_ea)
        if cfunc is None:
            return None
        return DecompiledFunction(cfunc)
    except Exception:
        return None


def get_citems_by_line(ea: int, line_index: int) -> List[CitemInfo]:
    """
    根据 ea 和伪代码行号获取该行所有的 citem
    
    参数:
        ea: 函数内的任意地址
        line_index: 伪代码行号
    返回:
        CitemInfo 列表
    """
    df = _get_decompiled_function(ea)
    if df is None:
        return []
    
    citem_indices = df.get_citems_in_line(line_index)
    result = []
    
    for citem_idx in citem_indices:
        item = df.get_citem(citem_idx)
        if item is None:
            continue
        
        info = CitemInfo(
            index=citem_idx,
            ea=df.get_citem_ea(citem_idx),
            type_name=CtreeUtils.get_citem_type_name(item),
            text=CtreeUtils.get_citem_string(df.cfunc, item),
            line_indices=sorted(df.get_lines_of_citem(citem_idx))
        )
        result.append(info)
    
    return sorted(result, key=lambda x: x.index)


def get_citem_by_line(ea: int, line_index: int, citem_index: int) -> Optional[CitemInfo]:
    """
    根据 ea、行号和 citem 索引获取特定 citem
    
    参数:
        ea: 函数内的任意地址
        line_index: 伪代码行号
        citem_index: citem 索引
    返回:
        CitemInfo 对象，失败返回 None
    """
    df = _get_decompiled_function(ea)
    if df is None:
        return None
    
    # 检查 citem 是否在该行中
    line_citems = df.get_citems_in_line(line_index)
    if citem_index not in line_citems:
        return None
    
    item = df.get_citem(citem_index)
    if item is None:
        return None
    
    return CitemInfo(
        index=citem_index,
        ea=df.get_citem_ea(citem_index),
        type_name=CtreeUtils.get_citem_type_name(item),
        text=CtreeUtils.get_citem_string(df.cfunc, item),
        line_indices=sorted(df.get_lines_of_citem(citem_index))
    )


def get_citem_info(ea: int, citem_index: int) -> Optional[CitemInfo]:
    """
    根据 citem 索引获取详细信息
    
    参数:
        ea: 函数内的任意地址
        citem_index: citem 索引
    返回:
        CitemInfo 对象，失败返回 None
    """
    df = _get_decompiled_function(ea)
    if df is None:
        return None
    
    item = df.get_citem(citem_index)
    if item is None:
        return None
    
    return CitemInfo(
        index=citem_index,
        ea=df.get_citem_ea(citem_index),
        type_name=CtreeUtils.get_citem_type_name(item),
        text=CtreeUtils.get_citem_string(df.cfunc, item),
        line_indices=sorted(df.get_lines_of_citem(citem_index))
    )


def find_citems_by_type(ea: int, type_name: str) -> List[CitemInfo]:
    """
    根据类型名称查找 citem
    
    参数:
        ea: 函数内的任意地址
        type_name: 类型名称，如 "call", "var", "return" 等
    返回:
        CitemInfo 列表
    """
    df = _get_decompiled_function(ea)
    if df is None:
        return []
    
    found_items = df.find_citems_by_type(type_name)
    result = []
    
    for citem_idx, item in found_items:
        info = CitemInfo(
            index=citem_idx,
            ea=df.get_citem_ea(citem_idx),
            type_name=CtreeUtils.get_citem_type_name(item),
            text=CtreeUtils.get_citem_string(df.cfunc, item),
            line_indices=sorted(df.get_lines_of_citem(citem_idx))
        )
        result.append(info)
    
    return result


def get_citems_by_ea(ea: int, target_ea: int) -> List[CitemInfo]:
    """
    根据目标地址获取所有 citem
    
    参数:
        ea: 函数内的任意地址（用于定位函数）
        target_ea: 目标地址
    返回:
        CitemInfo 列表
    """
    df = _get_decompiled_function(ea)
    if df is None:
        return []
    
    found_items = df.get_citems_by_ea(target_ea)
    result = []
    
    for citem_idx, item in found_items:
        info = CitemInfo(
            index=citem_idx,
            ea=df.get_citem_ea(citem_idx),
            type_name=CtreeUtils.get_citem_type_name(item),
            text=CtreeUtils.get_citem_string(df.cfunc, item),
            line_indices=sorted(df.get_lines_of_citem(citem_idx))
        )
        result.append(info)
    
    return result
