#!/usr/bin/env python3
"""
反编译函数核心类

提供对反编译后函数的全面访问，包括：
- 伪代码行管理
- citem 索引映射
- 地址查询
- 函数调用信息收集
"""

import idaapi
import ida_hexrays
import ida_name
from typing import Set, Dict, List, Tuple, Optional
from dataclasses import dataclass, field


@dataclass
class CallInfo:
    """函数调用信息"""
    call_expr: ida_hexrays.cexpr_t  # 调用表达式
    target_expr: ida_hexrays.cexpr_t  # 目标表达式（被调用的函数）
    target_name: str  # 目标函数名称
    target_ea: int  # 目标函数地址（间接调用为0）
    call_ea: int  # 调用指令地址
    line_index: int  # 调用所在行号
    args: List[ida_hexrays.cexpr_t] = field(default_factory=list)  # 参数表达式列表


class DecompiledFunction:
    """
    管理反编译函数的信息，提供 citem 与伪代码行之间的双向映射
    
    在一次 ctree 遍历中完成：
    - 构建 citem <-> line 双向映射
    - 收集父节点信息
    - 收集函数调用信息（包含行号、参数）
    """
    
    def __init__(self, cfunc: ida_hexrays.cfunc_t):
        """
        初始化反编译函数对象

        参数:
            cfunc: Hex-Rays 反编译后的 cfunc_t 对象
        """
        self.cfunc = cfunc
        self._lines: List[str] = []              # 伪代码行文本列表
        self._line_to_citems: Dict[int, Set[int]] = {}  # line_idx -> citem_indices
        self._citem_to_lines: Dict[int, Set[int]] = {}  # citem_idx -> line_indices
        self._citem_eas: Dict[int, int] = {}     # citem_idx -> ea
        self._parent_info: Dict[int, int] = {}    # citem_idx -> parent_op (缓存父子关系)
        self._calls: List[CallInfo] = []         # 收集的函数调用信息

        # 先构建 citem -> line 的映射（通过伪代码行）
        self._build_line_mappings()
        # 然后一次 ctree 遍历收集所有信息
        self._collect_ctree_info()
    
    def _build_line_mappings(self):
        """构建 citem 与行之间的双向映射"""
        from .ctree.utils import CtreeUtils

        pseudo_code = self.cfunc.get_pseudocode()

        for line_idx, line in enumerate(pseudo_code):
            # 存储纯文本行
            clean_text = idaapi.tag_remove(line.line)
            self._lines.append(clean_text)

            # 提取该行包含的所有 citem 信息
            citem_info = CtreeUtils.extract_citem_indices_from_line(line.line, self.cfunc)
            citem_indices = set()

            for citem_idx, ea in citem_info:
                citem_indices.add(citem_idx)
                self._citem_eas[citem_idx] = ea

                # 建立反向映射
                if citem_idx not in self._citem_to_lines:
                    self._citem_to_lines[citem_idx] = set()
                self._citem_to_lines[citem_idx].add(line_idx)

            self._line_to_citems[line_idx] = citem_indices

    def _collect_ctree_info(self):
        """一次 ctree 遍历收集父节点信息和调用信息"""
        visitor = _UnifiedCollector(self.cfunc, self._citem_to_lines)
        visitor.apply_to(self.cfunc.body, None)
        
        # 保存收集结果
        self._parent_info = visitor.parent_info
        self._calls = visitor.calls
        
        # 为每个调用补充行号信息
        for call_info in self._calls:
            lines = self._citem_to_lines.get(call_info.call_expr.index, set())
            if lines:
                call_info.line_index = min(lines)  # 使用第一个出现的行号

    # ==================== 基本信息查询 ====================
    
    @property
    def entry_ea(self) -> int:
        """获取函数入口地址"""
        return self.cfunc.entry_ea
    
    def get_line_text(self, line_index: int) -> str:
        """获取指定行的伪代码文本"""
        if 0 <= line_index < len(self._lines):
            return self._lines[line_index]
        return ""
    
    def get_line_count(self) -> int:
        """获取总行数"""
        return len(self._lines)
    
    def get_all_lines(self) -> List[str]:
        """获取所有伪代码行（副本）"""
        return self._lines.copy()
    
    def get_pseudocode(self) -> str:
        """获取完整伪代码字符串"""
        return "\n".join(self._lines)
    
    # ==================== citem 查询 ====================
    
    def get_citem(self, citem_index: int) -> Optional[ida_hexrays.citem_t]:
        """获取 citem 对象"""
        try:
            return self.cfunc.treeitems.at(citem_index)
        except:
            return None
    
    def get_citem_ea(self, citem_index: int) -> int:
        """获取 citem 的地址"""
        return self._citem_eas.get(citem_index, idaapi.BADADDR)
    
    def get_citems_in_line(self, line_index: int) -> Set[int]:
        """
        获取指定行包含的所有 citem 索引
        
        参数:
            line_index: 行号 (从0开始)
        返回:
            citem 索引集合
        """
        return self._line_to_citems.get(line_index, set()).copy()
    
    def get_lines_of_citem(self, citem_index: int) -> Set[int]:
        """
        获取包含指定 citem 的所有行号
        
        参数:
            citem_index: citem 索引
        返回:
            行号集合
        """
        return self._citem_to_lines.get(citem_index, set()).copy()
    
    def get_all_citem_indices(self) -> Set[int]:
        """获取所有 citem 索引"""
        return set(self._citem_eas.keys())
    
    # ==================== 地址相关查询 ====================
    
    def get_lines_by_ea(self, ea: int) -> List[Tuple[int, str]]:
        """
        根据地址获取所有包含该地址的伪代码行
        
        参数:
            ea: 指令地址
        返回:
            (line_index, line_text) 列表
        """
        result = []
        for citem_idx, citem_ea in self._citem_eas.items():
            if citem_ea == ea:
                for line_idx in self._citem_to_lines.get(citem_idx, set()):
                    if line_idx not in [r[0] for r in result]:  # 去重
                        result.append((line_idx, self._lines[line_idx]))
        return sorted(result, key=lambda x: x[0])
    
    def get_citems_by_ea(self, ea: int) -> List[Tuple[int, ida_hexrays.citem_t]]:
        """
        根据地址获取所有 citem
        
        参数:
            ea: 指令地址
        返回:
            (citem_index, citem) 列表
        """
        result = []
        for citem_idx, citem_ea in self._citem_eas.items():
            if citem_ea == ea:
                item = self.get_citem(citem_idx)
                if item:
                    result.append((citem_idx, item))
        return result
    
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
    
    def find_citems_by_type(self, type_name: str) -> List[Tuple[int, ida_hexrays.citem_t]]:
        """
        根据类型名称查找 citem
        
        参数:
            type_name: 类型名称，如 "call", "var", "return" 等
        返回:
            (citem_index, citem) 列表
        """
        from .ctree.utils import CtreeUtils
        
        result = []
        # 直接遍历所有 treeitems，而不是只遍历 _citem_eas
        for idx in range(self.cfunc.treeitems.size()):
            item = self.cfunc.treeitems.at(idx)
            if item:
                item_type = CtreeUtils.get_citem_type_name(item)
                if type_name.lower() in item_type.lower():
                    result.append((idx, item))
        
        return result
    
    # ==================== 高级功能 ====================
    
    def get_citem_context(self, citem_index: int) -> Dict:
        """
        获取 citem 的完整上下文信息
        
        参数:
            citem_index: citem 索引
        返回:
            包含详细信息的字典
        """
        from .ctree.utils import CtreeUtils
        
        item = self.get_citem(citem_index)
        if item is None:
            return {}
        
        lines = self.get_lines_of_citem(citem_index)
        
        return {
            'index': citem_index,
            'ea': self.get_citem_ea(citem_index),
            'type': CtreeUtils.get_citem_type_name(item),
            'lines': sorted(lines),
            'text': CtreeUtils.get_citem_string(self.cfunc, item),
            'object': item,
        }
    
    def get_line_root_citem(self, line_index: int) -> Optional[ida_hexrays.citem_t]:
        """
        获取指定行号的根 ctree citem_t

        根据 IDA ctree 结构，每一行的根 citem 是一个表达式（cexpr_t），
        且其父节点为块语句（cblock）。这个方法返回该根 citem，
        方便用于遍历子 ctree 和提取子 ctree 的信息。

        参数:
            line_index: 行号 (从0开始)
        返回:
            该行的根 citem 对象，如果不存在则返回 None
        """
        citem_indices = self.get_citems_in_line(line_index)
        if not citem_indices:
            return None

        # 遍历该行的所有 citem，找到父节点为 cblock 的 citem
        for citem_idx in sorted(citem_indices):
            item = self.get_citem(citem_idx)
            if item is None:
                continue

            # 使用缓存的父节点信息
            parent_op = self._parent_info.get(citem_idx)
            if parent_op == ida_hexrays.cit_block:
                # 找到了根 citem（其父节点为 cblock）
                return item

        return None

    def get_line_context(self, line_index: int) -> Dict:
        """
        获取行的完整上下文信息

        参数:
            line_index: 行号
        返回:
            包含详细信息的字典
        """
        if line_index >= len(self._lines):
            return {}

        citems = self.get_citems_in_line(line_index)
        citem_details = []

        for citem_idx in citems:
            detail = self.get_citem_context(citem_idx)
            if detail:
                citem_details.append(detail)

        return {
            'index': line_index,
            'text': self._lines[line_index],
            'citem_count': len(citems),
            'citems': sorted(citem_details, key=lambda x: x['index']),
        }


    # ==================== 函数调用查询 ====================
    
    def get_calls(self) -> List[CallInfo]:
        """获取所有函数调用信息"""
        return self._calls.copy()
    
    def get_call_count(self) -> int:
        """获取调用次数"""
        return len(self._calls)
    
    def find_calls_to(self, target_name: str) -> List[CallInfo]:
        """
        查找调用指定目标函数的调用信息
        
        参数:
            target_name: 目标函数名（支持部分匹配）
        返回:
            匹配的 CallInfo 列表
        """
        result = []
        search_name = target_name.lower()
        
        for call_info in self._calls:
            if search_name in call_info.target_name.lower():
                result.append(call_info)
        
        return result
    
    def get_calls_in_line(self, line_index: int) -> List[CallInfo]:
        """
        获取指定行中的所有函数调用
        
        参数:
            line_index: 行号
        返回:
            CallInfo 列表
        """
        return [c for c in self._calls if c.line_index == line_index]
    
    def get_call_at_line(self, line_index: int) -> Optional[CallInfo]:
        """
        获取指定行中的第一个函数调用
        
        参数:
            line_index: 行号
        返回:
            CallInfo 或 None
        """
        calls = self.get_calls_in_line(line_index)
        return calls[0] if calls else None


class _UnifiedCollector(ida_hexrays.ctree_visitor_t):
    """
    统一收集器 - 一次遍历收集所有信息
    
    同时收集：
    - 父节点信息 (citem_idx -> parent_op)
    - 函数调用信息 (CallInfo 列表)
    """

    def __init__(self, cfunc: ida_hexrays.cfunc_t, citem_to_lines: Dict[int, Set[int]]):
        """
        初始化 visitor

        参数:
            cfunc: 反编译函数对象
            citem_to_lines: citem 索引到行号的映射
        """
        # 启用 CV_PARENTS 标志来维护父节点信息
        super().__init__(ida_hexrays.CV_PARENTS)
        self.cfunc = cfunc
        self._citem_to_lines = citem_to_lines
        
        # 收集结果
        self.parent_info: Dict[int, int] = {}  # citem_idx -> parent_op
        self.calls: List[CallInfo] = []  # 函数调用信息列表

    def _get_line_index(self, citem_idx: int) -> int:
        """根据 citem 索引获取行号"""
        lines = self._citem_to_lines.get(citem_idx, set())
        return min(lines) if lines else -1
    
    def _get_call_target_name(self, target_expr) -> Tuple[str, int]:
        """
        获取调用目标的名称和地址
        
        返回:
            (target_name, target_ea)
        """
        from .ctree.utils import CtreeUtils
        
        # 处理直接调用 (cot_obj)
        if target_expr.op == ida_hexrays.cot_obj:
            target_ea = target_expr.obj_ea
            name = ida_name.get_name(target_ea) or f"sub_{target_ea:X}"
            return name, target_ea
        
        # 处理其他类型的调用
        try:
            text = CtreeUtils.get_citem_string(self.cfunc, target_expr)
            if text:
                return f"<{text}>", 0
        except Exception:
            pass
        
        # 根据表达式类型返回描述
        op = target_expr.op
        if op == ida_hexrays.cot_var:
            return "<function_ptr>", 0
        elif op == ida_hexrays.cot_memptr:
            return "<virtual_call>", 0
        elif op == ida_hexrays.cot_idx:
            return "<array_call>", 0
        elif op == ida_hexrays.cot_cast:
            return "<cast_call>", 0
        else:
            return "<indirect_call>", 0

    def visit_expr(self, expr: ida_hexrays.cexpr_t) -> int:
        """访问表达式节点"""
        # 记录父节点信息
        parent = self.parent_item()
        if parent:
            self.parent_info[expr.index] = parent.op
        
        # 检测函数调用
        if expr.op == ida_hexrays.cot_call:
            self._process_call(expr)
        
        return 0  # 继续遍历

    def visit_insn(self, insn: ida_hexrays.cinsn_t) -> int:
        """访问语句节点"""
        # 记录父节点信息
        parent = self.parent_item()
        if parent:
            self.parent_info[insn.index] = parent.op
        
        return 0  # 继续遍历
    
    def _process_call(self, call_expr: ida_hexrays.cexpr_t):
        """处理函数调用表达式"""
        target_expr = call_expr.x
        target_name, target_ea = self._get_call_target_name(target_expr)
        call_ea = call_expr.ea if call_expr.ea != idaapi.BADADDR else 0
        line_idx = self._get_line_index(call_expr.index)
        
        # 收集参数
        args = []
        if call_expr.a:  # 参数列表
            for i in range(call_expr.a.size()):
                args.append(call_expr.a[i])
        
        call_info = CallInfo(
            call_expr=call_expr,
            target_expr=target_expr,
            target_name=target_name,
            target_ea=target_ea,
            call_ea=call_ea,
            line_index=line_idx,
            args=args
        )
        self.calls.append(call_info)
