#!/usr/bin/env python3
"""
反汇编代码获取模块

提供获取函数汇编代码的基础 API
"""

import idaapi
import idc
from typing import List, Dict, Any, Optional
from dataclasses import dataclass


@dataclass
class Instruction:
    """指令信息"""
    address: int
    disasm: str
    bytes: str
    size: int


@dataclass
class FunctionCode:
    """函数汇编代码"""
    address: int
    name: str
    instructions: List[Instruction]
    instruction_count: int


def get_function_code(address) -> Optional[FunctionCode]:
    """
    获取函数汇编代码
    
    参数:
        address: 函数地址或名称
    返回:
        FunctionCode 对象，失败返回 None
    """
    ea = _parse_address(address)
    func = idaapi.get_func(ea)
    
    if not func:
        return None
    
    func_name = idc.get_func_name(func.start_ea)
    instructions = []
    curr = func.start_ea
    
    while curr < func.end_ea:
        disasm = idc.generate_disasm_line(curr, 0)
        insn_len = idc.get_item_size(curr)
        insn_bytes = idc.get_bytes(curr, insn_len)
        bytes_str = ' '.join(f'{b:02x}' for b in insn_bytes) if insn_bytes else ""
        
        instructions.append(Instruction(
            address=curr,
            disasm=disasm,
            bytes=bytes_str,
            size=insn_len
        ))
        curr = idc.next_head(curr)
    
    return FunctionCode(
        address=func.start_ea,
        name=func_name,
        instructions=instructions,
        instruction_count=len(instructions)
    )


def get_function_code_text(address) -> Optional[Dict[str, Any]]:
    """
    获取函数汇编代码（文本格式，兼容旧接口）
    
    参数:
        address: 函数地址或名称
    返回:
        包含 code 字段的字典
    """
    code = get_function_code(address)
    if not code:
        return None
    
    code_lines = [f"0x{insn.address:X}: {insn.disasm}" for insn in code.instructions]
    
    return {
        "address": hex(code.address),
        "name": code.name,
        "code": "\n".join(code_lines),
        "instruction_count": code.instruction_count,
    }


def _parse_address(addr) -> int:
    """解析地址字符串或名称"""
    if isinstance(addr, int):
        return addr
    
    if isinstance(addr, str):
        addr = addr.strip()
        
        if addr.startswith("0x") or addr.startswith("0X"):
            try:
                return int(addr, 16)
            except ValueError:
                pass
        
        try:
            return int(addr)
        except ValueError:
            pass
        
        ea = idc.get_name_ea_simple(addr)
        if ea and ea != 0xFFFFFFFFFFFFFFFF:
            return ea
    
    raise ValueError(f"Cannot parse address: {addr}")
