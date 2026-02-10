#!/usr/bin/env python3
"""
IDA原子化API接口

提供便捷的代码分析功能接口
"""

# IDB 信息
from .idb_info import (
    get_idb_info,
    get_ida_version,
    get_input_file_path,
)

# 函数列表
from .functions import (
    get_function_list,
    get_function_list_dict,
    FunctionSummary,
)

# 函数详细信息
from .function import (
    get_function_info,
    get_function_signature,
    get_function_parameters,
    get_pseudocode_with_line_numbers,
    FunctionInfoResult,
    ParameterInfo,
)

# 调用关系
from .calls import (
    get_callees,
    get_callers,
    CallDetail,
    CalleeInfo,
)

# citem 操作
from .citems import (
    get_citems_by_line,
    get_citem_info,
    find_citems_by_type,
    CitemInfo,
)

# 汇编代码
from .disassembly import (
    get_function_code,
    get_function_code_text,
    FunctionCode,
    Instruction,
)

# 字符串
from .strings import (
    get_strings,
    get_strings_dict,
    StringInfo,
)

# 交叉引用
from .xrefs import (
    get_xrefs_to,
    get_xrefs_from,
    get_xrefs_to_dict,
    get_xrefs_from_dict,
    XrefInfo,
)

__all__ = [
    # IDB 信息
    "get_idb_info",
    "get_ida_version",
    "get_input_file_path",
    # 函数列表
    "get_function_list",
    "get_function_list_dict",
    "FunctionSummary",
    # 函数详细信息
    "get_function_info",
    "get_function_signature",
    "get_function_parameters",
    "get_pseudocode_with_line_numbers",
    "FunctionInfoResult",
    "ParameterInfo",
    # 调用关系
    "get_callees",
    "get_callers",
    "CallDetail",
    "CalleeInfo",
    # citem
    "get_citems_by_line",
    "get_citem_info",
    "find_citems_by_type",
    "CitemInfo",
    # 汇编代码
    "get_function_code",
    "get_function_code_text",
    "FunctionCode",
    "Instruction",
    # 字符串
    "get_strings",
    "get_strings_dict",
    "StringInfo",
    # 交叉引用
    "get_xrefs_to",
    "get_xrefs_from",
    "get_xrefs_to_dict",
    "get_xrefs_from_dict",
    "XrefInfo",
]
