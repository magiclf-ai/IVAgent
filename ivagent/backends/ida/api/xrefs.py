#!/usr/bin/env python3
"""
交叉引用模块

提供获取代码交叉引用的基础 API
"""

import idautils
import idc
from typing import List, Dict, Any, Optional
from dataclasses import dataclass


@dataclass
class XrefInfo:
    """交叉引用信息"""
    from_addr: int
    to_addr: int
    type: str


def get_xrefs_to(address) -> List[XrefInfo]:
    """
    获取引用到指定地址的交叉引用
    
    参数:
        address: 目标地址
    返回:
        XrefInfo 列表
    """
    ea = _parse_address(address)
    xrefs = []
    
    for xref in idautils.XrefsTo(ea):
        xrefs.append(XrefInfo(
            from_addr=xref.frm,
            to_addr=xref.to,
            type=str(xref.type)
        ))
    
    return xrefs


def get_xrefs_from(address) -> List[XrefInfo]:
    """
    获取从指定地址引用的交叉引用
    
    参数:
        address: 源地址
    返回:
        XrefInfo 列表
    """
    ea = _parse_address(address)
    xrefs = []
    
    for xref in idautils.XrefsFrom(ea):
        xrefs.append(XrefInfo(
            from_addr=xref.frm,
            to_addr=xref.to,
            type=str(xref.type)
        ))
    
    return xrefs


def get_xrefs_to_dict(address) -> List[Dict[str, Any]]:
    """
    获取引用到指定地址的交叉引用（字典格式）
    
    参数:
        address: 目标地址
    返回:
        字典列表
    """
    xrefs = get_xrefs_to(address)
    return [
        {
            "from": f"0x{x.from_addr:X}",
            "to": f"0x{x.to_addr:X}",
            "type": x.type,
        }
        for x in xrefs
    ]


def get_xrefs_from_dict(address) -> List[Dict[str, Any]]:
    """
    获取从指定地址引用的交叉引用（字典格式）
    
    参数:
        address: 源地址
    返回:
        字典列表
    """
    xrefs = get_xrefs_from(address)
    return [
        {
            "from": f"0x{x.from_addr:X}",
            "to": f"0x{x.to_addr:X}",
            "type": x.type,
        }
        for x in xrefs
    ]


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
