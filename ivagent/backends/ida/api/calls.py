#!/usr/bin/env python3
"""
子函数调用解析模块

提供获取函数调用关系的基础 API
"""

import idaapi
import idc
import idautils
from typing import List, Dict, Any, Optional
from dataclasses import dataclass


@dataclass
class CallDetail:
    """调用详细信息"""
    caller: str  # 调用者函数名
    callee: str  # 被调用函数名
    caller_address: int  # 调用者函数地址
    callee_address: int  # 被调用函数地址
    call_address: int  # 调用指令地址


@dataclass
class CalleeInfo:
    """被调用函数信息（从函数内部获取）"""
    caller: str  # 当前函数名
    callee: str  # 被调用的函数名
    callee_address: int  # 被调用函数地址
    call_address: int  # 调用指令地址
    line_index: int = -1  # 调用所在伪代码行号
    args: List[Any] = None  # 参数表达式列表（原始 cexpr_t 对象）
    arg_texts: List[str] = None  # 参数字符串表示列表


def get_callees(function_identifier: str) -> List[CalleeInfo]:
    """
    获取函数调用的子函数（从函数内部 outgoing calls）
    
    使用 DecompiledFunction 一次遍历收集所有信息，包括调用点和行号。
    
    参数:
        function_identifier: 函数唯一标识符（地址或函数名）
    返回:
        CalleeInfo 列表
    """
    import ida_hexrays
    from ..decompiler import DecompiledFunction

    # 解析地址
    ea = _parse_address(function_identifier)

    func = idaapi.get_func(ea)
    if not func:
        return []

    caller_name = idc.get_func_name(func.start_ea)

    # 使用新的 DecompiledFunction API
    try:
        cfunc = ida_hexrays.decompile(func.start_ea)
        if cfunc:
            decompiled = DecompiledFunction(cfunc)
            callees = []
            for call_info in decompiled.get_calls():
                # 转换参数为字符串表示
                arg_texts = []
                if call_info.args:
                    from ..ctree.utils import CtreeUtils
                    for arg in call_info.args:
                        arg_text = CtreeUtils.get_citem_string(cfunc, arg)
                        arg_texts.append(arg_text)
                
                callees.append(CalleeInfo(
                    caller=caller_name,
                    callee=call_info.target_name,
                    callee_address=call_info.target_ea,
                    call_address=call_info.call_ea,
                    line_index=call_info.line_index,
                    args=call_info.args,
                    arg_texts=arg_texts
                ))
            return callees
    except Exception as e:
        print(f"Decompilation failed: {e}")
        return []


def get_callers(function_identifier: str) -> List[CallDetail]:
    """
    获取调用该函数的父函数（incoming calls）
    
    参数:
        function_identifier: 函数唯一标识符（地址或函数名）
    返回:
        CallDetail 列表
    """
    import idc
    import idautils

    # 解析地址
    ea = _parse_address(function_identifier)

    callee_name = idc.get_func_name(ea)
    callers = []

    for ref in idautils.CodeRefsTo(ea, 0):
        caller_func = idaapi.get_func(ref)
        if caller_func:
            caller_name = idc.get_func_name(caller_func.start_ea)
            callers.append(CallDetail(
                caller=caller_name,
                callee=callee_name,
                caller_address=caller_func.start_ea,
                callee_address=ea,
                call_address=ref
            ))

    return callers


def _parse_address(addr) -> int:
    """
    解析地址字符串或名称
    
    支持:
    - 十六进制字符串: "0x140001000"
    - 十进制字符串: "5368713216"
    - 整数: 5368713216
    - 函数名: "main", "sub_140001000" 等
    """
    if isinstance(addr, int):
        return addr

    if isinstance(addr, str):
        addr = addr.strip()

        # 尝试作为十六进制解析
        if addr.startswith("0x") or addr.startswith("0X"):
            try:
                return int(addr, 16)
            except ValueError:
                pass

        # 尝试作为十进制数字解析
        try:
            return int(addr)
        except ValueError:
            pass

        # 尝试作为函数名解析
        ea = idc.get_name_ea_simple(addr)
        if ea and ea != 0xFFFFFFFFFFFFFFFF:  # BADADDR
            return ea

    raise ValueError(f"Cannot parse address: {addr}")
