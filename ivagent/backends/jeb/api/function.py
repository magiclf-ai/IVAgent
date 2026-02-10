#!/usr/bin/env python3
"""
函数信息获取模块

基于 DecompiledMethod 提供原子化接口获取 Java 方法信息
"""

from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field

from ..decompiler import DecompiledMethod


def _is_valid_signature(signature: str) -> bool:
    """检查是否为有效的方法签名"""
    if not signature:
        return False
    # 基本检查：包含 -> 表示是方法签名
    return "->" in signature


def get_method_info(filepath: str, method_signature: str, client) -> Optional[Dict[str, Any]]:
    """
    获取指定方法的完整信息
    
    参数:
        filepath: APK 文件的绝对路径
        method_signature: 方法的完整签名，例如 "Lcom/example/Class;->method(Ljava/lang/String;)V"
        client: JEBClient 实例
    返回:
        方法信息字典，失败返回 None
    """
    if not _is_valid_signature(method_signature):
        return None
    
    try:
        # 获取反编译代码
        code = client.get_method_decompiled_code(filepath, method_signature)
        if not code:
            return None
        
        # 创建 DecompiledMethod 对象
        dm = DecompiledMethod(method_signature, code)
        
        # 获取调用信息
        calls = dm.get_calls()
        call_infos = []
        for call in calls:
            call_infos.append({
                "target_name": call.target_name,
                "target_signature": call.target_signature,
                "line_index": call.line_index,
                "call_text": call.call_text,
                "arguments": call.arguments,
            })
        
        return {
            "signature": method_signature,
            "name": dm.name,
            "class_name": dm.class_name,
            "code": dm.get_code(),
            "code_with_line_numbers": dm.get_code_with_line_numbers(),
            "line_count": dm.get_line_count(),
            "calls": call_infos,
            "call_count": len(calls),
        }
    
    except Exception as e:
        return None


def get_method_signature(filepath: str, method_name: str, client) -> Optional[str]:
    """
    根据方法名查找方法签名
    
    参数:
        filepath: APK 文件的绝对路径
        method_name: 方法名
        client: JEBClient 实例
    返回:
        方法签名，未找到返回 None
    """
    try:
        # 尝试通过 check_java_identifier 查找
        results = client.check_java_identifier(filepath, method_name)
        if results:
            for result in results:
                if result.get("type") == "method":
                    return result.get("signature")
        return None
    except Exception:
        return None


def get_callees(filepath: str, method_signature: str, client) -> List[Dict[str, Any]]:
    """
    获取方法内调用的子方法
    
    参数:
        filepath: APK 文件的绝对路径
        method_signature: 方法的完整签名
        client: JEBClient 实例
    返回:
        被调用方法信息列表
    """
    if not _is_valid_signature(method_signature):
        return []
    
    try:
        # 使用 JEB 客户端获取调用关系
        callees = client.get_method_callees(filepath, method_signature)
        
        # 补充方法代码信息
        result = []
        for callee in callees:
            callee_info = {
                "signature": callee.get("signature", ""),
                "name": callee.get("name", ""),
                "class_name": callee.get("class_name", ""),
                "address": callee.get("address", ""),
                "line_index": callee.get("line_index", -1),
            }
            result.append(callee_info)
        
        return result
    except Exception:
        return []


def get_callers(filepath: str, method_signature: str, client) -> List[Dict[str, Any]]:
    """
    获取调用该方法的父方法
    
    参数:
        filepath: APK 文件的绝对路径
        method_signature: 方法的完整签名
        client: JEBClient 实例
    返回:
        调用者信息列表
    """
    if not _is_valid_signature(method_signature):
        return []
    
    try:
        # 使用 JEB 客户端获取调用关系
        callers = client.get_method_callers(filepath, method_signature)
        
        result = []
        for caller in callers:
            caller_info = {
                "signature": caller.get("signature", ""),
                "name": caller.get("name", ""),
                "class_name": caller.get("class_name", ""),
                "address": caller.get("address", ""),
                "line_index": caller.get("line_index", -1),
                "details": caller.get("details", ""),
            }
            result.append(caller_info)
        
        return result
    except Exception:
        return []


def get_field_references(filepath: str, field_signature: str, client) -> List[Dict[str, Any]]:
    """
    获取访问指定字段的所有位置
    
    参数:
        filepath: APK 文件的绝对路径
        field_signature: 字段的完整签名，例如 "Lcom/example/Class;->fieldName:Ljava/lang/String;"
        client: JEBClient 实例
    返回:
        访问者信息列表
    """
    try:
        references = client.get_field_callers(filepath, field_signature)
        return references
    except Exception:
        return []


def get_class_info(filepath: str, class_signature: str, client) -> Optional[Dict[str, Any]]:
    """
    获取指定类的信息
    
    参数:
        filepath: APK 文件的绝对路径
        class_signature: 类的完整签名，例如 "Lcom/example/Class;"
        client: JEBClient 实例
    返回:
        类信息字典，失败返回 None
    """
    try:
        # 获取类的方法列表
        methods = client.get_class_methods(filepath, class_signature)
        
        # 获取类的字段列表
        fields = client.get_class_fields(filepath, class_signature)
        
        # 获取父类
        superclass = client.get_superclass(filepath, class_signature)
        
        # 获取实现的接口
        interfaces = client.get_interfaces(filepath, class_signature)
        
        return {
            "signature": class_signature,
            "methods": methods,
            "fields": fields,
            "superclass": superclass,
            "interfaces": interfaces,
        }
    except Exception:
        return None
