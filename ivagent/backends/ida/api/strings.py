#!/usr/bin/env python3
"""
字符串获取模块

提供获取 IDB 中字符串的基础 API
"""

import idautils
import idc
from typing import List, Dict, Any, Optional
from dataclasses import dataclass


@dataclass
class StringInfo:
    """字符串信息"""
    address: int
    length: int
    text: str
    strtype: int


def get_strings(min_length: int = 4) -> List[StringInfo]:
    """
    获取字符串列表
    
    参数:
        min_length: 最小字符串长度
    返回:
        StringInfo 列表
    """
    strings = []
    
    for s in idautils.Strings():
        if s.length >= min_length:
            try:
                text = str(s)
                strings.append(StringInfo(
                    address=s.ea,
                    length=s.length,
                    text=text,
                    strtype=s.strtype
                ))
            except:
                pass
    
    return strings


def get_strings_dict(min_length: int = 4) -> List[Dict[str, Any]]:
    """
    获取字符串列表（字典格式，兼容旧接口）
    
    参数:
        min_length: 最小字符串长度
    返回:
        字典列表
    """
    strings = get_strings(min_length)
    return [
        {
            "address": f"0x{s.address:X}",
            "length": s.length,
            "text": s.text,
        }
        for s in strings
    ]
