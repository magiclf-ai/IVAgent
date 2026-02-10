#!/usr/bin/env python3
"""
IDB 信息模块

提供获取 IDA 数据库信息的基础 API
"""

import idaapi
from typing import Dict, Any


def get_idb_info() -> Dict[str, Any]:
    """
    获取 IDB 基本信息
    
    返回:
        包含 IDB 信息的字典
    """
    return {
        "ida_version": idaapi.get_kernel_version(),
        "input_file": idaapi.get_input_file_path(),
    }


def get_ida_version() -> str:
    """获取 IDA 版本"""
    return idaapi.get_kernel_version()


def get_input_file_path() -> str:
    """获取输入文件路径"""
    return idaapi.get_input_file_path()
