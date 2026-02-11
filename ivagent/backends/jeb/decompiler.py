#!/usr/bin/env python3
"""
反编译方法核心类

提供对反编译后 Java 方法的全面访问，包括：
- 代码行管理
- 行号映射
- 函数调用信息收集
"""

from typing import Set, Dict, List, Tuple, Optional
from dataclasses import dataclass, field
import re


@dataclass
class CallInfo:
    """方法调用信息"""
    target_name: str          # 目标方法名称
    target_signature: str     # 目标方法签名
    line_index: int           # 调用所在行号
    call_text: str            # 调用语句文本
    arguments: List[str] = field(default_factory=list)  # 参数列表


class DecompiledMethod:
    """
    管理反编译后的 Java 方法信息
    
    提供代码行管理、调用信息收集等功能
    """
    
    def __init__(self, signature: str, code: str):
        """
        初始化反编译方法对象

        参数:
            signature: 方法完整签名，如 "Lcom/example/Class;->method(Ljava/lang/String;)V"
            code: Java 反编译代码
        """
        self.signature = signature
        self.raw_code = code
        self._lines: List[str] = []           # 代码行文本列表
        self._calls: List[CallInfo] = []      # 收集的方法调用信息
        
        # 解析代码行
        self._parse_lines()
        # 收集调用信息
        self._collect_calls()
    
    def _parse_lines(self):
        """解析代码为行列表"""
        if not self.raw_code:
            return
        
        # 按行分割，保留空行
        self._lines = self.raw_code.splitlines()
    
    def _collect_calls(self):
        """收集方法调用信息"""
        # 正则表达式匹配方法调用
        # 匹配模式: obj.method(arg1, arg2) 或 Class.method(arg1, arg2)
        call_pattern = re.compile(
            r'(\w+)\s*\.\s*(\w+)\s*\(([^)]*)\)'
        )
        
        # 也匹配静态方法调用: ClassName.methodName(...)
        static_call_pattern = re.compile(
            r'([A-Z]\w+)\s*\.\s*(\w+)\s*\(([^)]*)\)'
        )
        
        for line_idx, line in enumerate(self._lines):
            # 跳过注释行
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('*') or stripped.startswith('/*'):
                continue
            
            # 查找方法调用
            for match in call_pattern.finditer(line):
                obj_name = match.group(1)
                method_name = match.group(2)
                args_text = match.group(3)
                
                # 跳过关键字（非方法调用）
                if obj_name in ['if', 'while', 'for', 'switch', 'return', 'new']:
                    continue
                
                # 解析参数
                args = [a.strip() for a in args_text.split(',') if a.strip()]
                
                call_info = CallInfo(
                    target_name=method_name,
                    target_signature=f"{obj_name}.{method_name}",
                    line_index=line_idx,
                    call_text=line.strip(),
                    arguments=args
                )
                self._calls.append(call_info)
    
    # ==================== 基本信息查询 ====================
    
    @property
    def name(self) -> str:
        """获取方法名"""
        # 从签名中提取方法名
        # 签名格式: Lcom/example/Class;->methodName(Ljava/lang/String;)V
        if '->' in self.signature:
            return self.signature.split('->')[1].split('(')[0]
        return self.signature
    
    @property
    def class_name(self) -> str:
        """获取类名"""
        if '->' in self.signature:
            return self.signature.split('->')[0]
        return ""
    
    def get_line_text(self, line_index: int) -> str:
        """获取指定行的代码文本"""
        if 0 <= line_index < len(self._lines):
            return self._lines[line_index]
        return ""
    
    def get_line_count(self) -> int:
        """获取总行数"""
        return len(self._lines)
    
    def get_all_lines(self) -> List[str]:
        """获取所有代码行（副本）"""
        return self._lines.copy()
    
    def get_code(self) -> str:
        """获取完整代码字符串"""
        return "\n".join(self._lines)
    
    def get_code_with_line_numbers(self) -> str:
        """获取带行号的代码字符串"""
        lines = []
        for i, line in enumerate(self._lines):
            lines.append(f"[{i:4d}] {line}")
        return "\n".join(lines)
    
    # ==================== 搜索功能 ====================
    
    def find_lines_containing_text(self, text: str, case_sensitive: bool = False) -> List[Tuple[int, str]]:
        """
        搜索包含指定文本的所有行
        
        参数:
            text: 要搜索的文本
            case_sensitive: 是否区分大小写
        返回:
            (line_index, line_text) 列表
        """
        result = []
        search_text = text if case_sensitive else text.lower()
        
        for idx, line_text in enumerate(self._lines):
            compare_text = line_text if case_sensitive else line_text.lower()
            if search_text in compare_text:
                result.append((idx, self._lines[idx]))
        
        return result
    
    def find_method_calls(self, method_name: str) -> List[CallInfo]:
        """
        查找调用指定方法名的调用信息
        
        参数:
            method_name: 目标方法名（支持部分匹配）
        返回:
            匹配的 CallInfo 列表
        """
        result = []
        search_name = method_name.lower()
        
        for call_info in self._calls:
            if search_name in call_info.target_name.lower():
                result.append(call_info)
        
        return result
    
    # ==================== 函数调用查询 ====================
    
    def get_calls(self) -> List[CallInfo]:
        """获取所有方法调用信息"""
        return self._calls.copy()
    
    def get_call_count(self) -> int:
        """获取调用次数"""
        return len(self._calls)
    
    def get_calls_in_line(self, line_index: int) -> List[CallInfo]:
        """
        获取指定行中的所有方法调用
        
        参数:
            line_index: 行号
        返回:
            CallInfo 列表
        """
        return [c for c in self._calls if c.line_index == line_index]
    
    def get_call_at_line(self, line_index: int) -> Optional[CallInfo]:
        """
        获取指定行中的第一个方法调用
        
        参数:
            line_index: 行号
        返回:
            CallInfo 或 None
        """
        calls = self.get_calls_in_line(line_index)
        return calls[0] if calls else None
    
    # ==================== 上下文信息 ====================
    
    def get_line_context(self, line_index: int, context_lines: int = 3) -> Dict:
        """
        获取行的上下文信息
        
        参数:
            line_index: 行号
            context_lines: 上下文行数
        返回:
            包含详细信息的字典
        """
        if line_index >= len(self._lines):
            return {}
        
        start = max(0, line_index - context_lines)
        end = min(len(self._lines), line_index + context_lines + 1)
        
        context_lines_list = []
        for i in range(start, end):
            context_lines_list.append({
                "index": i,
                "text": self._lines[i],
                "is_target": i == line_index
            })
        
        calls = self.get_calls_in_line(line_index)
        
        return {
            "index": line_index,
            "text": self._lines[line_index],
            "context": context_lines_list,
            "calls_in_line": calls,
        }
