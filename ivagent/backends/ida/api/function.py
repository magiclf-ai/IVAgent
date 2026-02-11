#!/usr/bin/env python3
"""
函数信息获取模块

基于 DecompiledFunction 提供原子化接口获取函数信息
"""

import idaapi
import ida_hexrays
import idc
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field

from ..decompiler import DecompiledFunction


@dataclass
class ParameterInfo:
    """函数参数信息"""
    name: str
    type_str: str
    size: int
    index: int


@dataclass
class FunctionInfoResult:
    """函数完整信息"""
    name: str
    ea: int
    signature: str
    return_type: str
    parameters: List[ParameterInfo]
    pseudocode: List[str]
    pseudocode_with_line_numbers: List[str]
    line_count: int
    is_decompiled: bool


def _parse_address(addr) -> int:
    """
    解析地址字符串
    
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

        ea = idc.get_name_ea_simple(f"_{addr}")
        if ea and ea != 0xFFFFFFFFFFFFFFFF:  # BADADDR
            return ea

    raise ValueError(f"Cannot parse address: {addr}")


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


def _get_func_type_info(df: DecompiledFunction) -> Tuple[str, str, List[ParameterInfo]]:
    """
    从反编译结果获取函数类型信息
    
    返回: (return_type, signature, parameters)
    """
    params = []
    return_type = "void"
    signature = "void func()"
    
    try:
        if df and df.cfunc:
            func_type = df.cfunc.type
            if func_type:
                # 获取返回类型
                ret_type = func_type.get_rettype()
                return_type = str(ret_type) if ret_type else "void"
                
                # 获取参数
                nargs = func_type.get_nargs()
                for i in range(nargs):
                    arg = func_type.get_nth_arg(i)
                    arg_name = func_type.get_nth_arg_name(i) or f"arg_{i}"
                    param = ParameterInfo(
                        name=arg_name,
                        type_str=str(arg) if arg else "unknown",
                        size=arg.get_size() if arg else 0,
                        index=i
                    )
                    params.append(param)
                
                # 构建签名
                func_name = idc.get_func_name(df.cfunc.entry_ea)
                if params:
                    param_strs = [f"{p.type_str} {p.name}" for p in params]
                    signature = f"{return_type} {func_name}({', '.join(param_strs)})"
                else:
                    signature = f"{return_type} {func_name}()"
    except Exception:
        pass
    
    return return_type, signature, params


def get_function_info(ea: int) -> Optional[FunctionInfoResult]:
    """
    获取指定地址所在函数的完整信息
    
    参数:
        ea: 函数内的任意地址
    返回:
        FunctionInfoResult 对象，失败返回 None
    """
    func_ea = idaapi.get_func(ea)
    if func_ea is None:
        return None
    
    func_start = func_ea.start_ea
    func_name = idc.get_func_name(func_start)
    
    # 获取伪代码（使用 DecompiledFunction）
    df = _get_decompiled_function(ea)
    pseudocode = []
    pseudocode_with_lines = []
    
    if df:
        all_lines = df.get_all_lines()
        pseudocode = all_lines
        pseudocode_with_lines = [f"{i:4d}: {line}" for i, line in enumerate(all_lines)]
        is_decompiled = True
    else:
        is_decompiled = False
    
    # 从反编译结果获取类型信息
    return_type, signature, params = _get_func_type_info(df)
    
    return FunctionInfoResult(
        name=func_name,
        ea=func_start,
        signature=signature,
        return_type=return_type,
        parameters=params,
        pseudocode=pseudocode,
        pseudocode_with_line_numbers=pseudocode_with_lines,
        line_count=len(pseudocode),
        is_decompiled=is_decompiled
    )


def get_function_signature(ea: int) -> Optional[str]:
    """获取函数签名"""
    func_ea = idaapi.get_func(ea)
    if func_ea is None:
        return None
    
    func_start = func_ea.start_ea
    func_name = idc.get_func_name(func_start)
    
    df = _get_decompiled_function(ea)
    _, signature, _ = _get_func_type_info(df)
    
    # 如果获取失败，返回默认签名
    if signature == "void func()":
        return f"void {func_name}()"
    
    return signature


def get_function_parameters(ea: int) -> List[ParameterInfo]:
    """获取函数参数列表"""
    func_ea = idaapi.get_func(ea)
    if func_ea is None:
        return []
    
    df = _get_decompiled_function(ea)
    _, _, params = _get_func_type_info(df)
    return params


def get_pseudocode_with_line_numbers(ea: int) -> List[str]:
    """获取带行号的伪代码"""
    df = _get_decompiled_function(ea)
    if df is None:
        return []
    
    all_lines = df.get_all_lines()
    return [f"{i:4d}: {line}" for i, line in enumerate(all_lines)]
