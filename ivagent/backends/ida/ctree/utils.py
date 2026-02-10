#!/usr/bin/env python3
"""
CTREE 相关工具函数

提供处理 ctree 节点、操作码转换等通用功能
"""

import idaapi
import ida_hexrays


class CtreeUtils:
    """CTREE 工具类"""
    
    # 表达式操作码名称映射
    EXPR_OP_NAMES = {
        ida_hexrays.cot_empty: "empty",
        ida_hexrays.cot_comma: "comma",
        ida_hexrays.cot_asg: "asg",
        ida_hexrays.cot_asgbor: "asgbor",
        ida_hexrays.cot_asgxor: "asgxor",
        ida_hexrays.cot_asgband: "asgband",
        ida_hexrays.cot_asgadd: "asgadd",
        ida_hexrays.cot_asgsub: "asgsub",
        ida_hexrays.cot_asgmul: "asgmul",
        ida_hexrays.cot_asgsshr: "asgsshr",
        ida_hexrays.cot_asgushr: "asgushr",
        ida_hexrays.cot_asgshl: "asgshl",
        ida_hexrays.cot_asgsdiv: "asgsdiv",
        ida_hexrays.cot_asgudiv: "asgudiv",
        ida_hexrays.cot_asgsmod: "asgsmod",
        ida_hexrays.cot_asgumod: "asgumod",
        ida_hexrays.cot_tern: "tern",
        ida_hexrays.cot_lor: "lor",
        ida_hexrays.cot_land: "land",
        ida_hexrays.cot_bor: "bor",
        ida_hexrays.cot_xor: "xor",
        ida_hexrays.cot_band: "band",
        ida_hexrays.cot_eq: "eq",
        ida_hexrays.cot_ne: "ne",
        ida_hexrays.cot_sge: "sge",
        ida_hexrays.cot_uge: "uge",
        ida_hexrays.cot_sle: "sle",
        ida_hexrays.cot_ule: "ule",
        ida_hexrays.cot_sgt: "sgt",
        ida_hexrays.cot_ugt: "ugt",
        ida_hexrays.cot_slt: "slt",
        ida_hexrays.cot_ult: "ult",
        ida_hexrays.cot_sshr: "sshr",
        ida_hexrays.cot_ushr: "ushr",
        ida_hexrays.cot_shl: "shl",
        ida_hexrays.cot_add: "add",
        ida_hexrays.cot_sub: "sub",
        ida_hexrays.cot_mul: "mul",
        ida_hexrays.cot_sdiv: "sdiv",
        ida_hexrays.cot_udiv: "udiv",
        ida_hexrays.cot_smod: "smod",
        ida_hexrays.cot_umod: "umod",
        ida_hexrays.cot_fadd: "fadd",
        ida_hexrays.cot_fsub: "fsub",
        ida_hexrays.cot_fmul: "fmul",
        ida_hexrays.cot_fdiv: "fdiv",
        ida_hexrays.cot_fneg: "fneg",
        ida_hexrays.cot_neg: "neg",
        ida_hexrays.cot_cast: "cast",
        ida_hexrays.cot_lnot: "lnot",
        ida_hexrays.cot_bnot: "bnot",
        ida_hexrays.cot_ptr: "ptr",
        ida_hexrays.cot_ref: "ref",
        ida_hexrays.cot_postinc: "postinc",
        ida_hexrays.cot_postdec: "postdec",
        ida_hexrays.cot_preinc: "preinc",
        ida_hexrays.cot_predec: "predec",
        ida_hexrays.cot_call: "call",
        ida_hexrays.cot_idx: "idx",
        ida_hexrays.cot_memref: "memref",
        ida_hexrays.cot_memptr: "memptr",
        ida_hexrays.cot_num: "num",
        ida_hexrays.cot_fnum: "fnum",
        ida_hexrays.cot_str: "str",
        ida_hexrays.cot_obj: "obj",
        ida_hexrays.cot_var: "var",
        ida_hexrays.cot_insn: "insn",
        ida_hexrays.cot_sizeof: "sizeof",
        ida_hexrays.cot_helper: "helper",
        ida_hexrays.cot_type: "type",
    }
    
    # 语句操作码名称映射
    INSN_OP_NAMES = {
        ida_hexrays.cit_empty: "empty",
        ida_hexrays.cit_block: "block",
        ida_hexrays.cit_expr: "expr",
        ida_hexrays.cit_if: "if",
        ida_hexrays.cit_for: "for",
        ida_hexrays.cit_while: "while",
        ida_hexrays.cit_do: "do",
        ida_hexrays.cit_switch: "switch",
        ida_hexrays.cit_break: "break",
        ida_hexrays.cit_continue: "continue",
        ida_hexrays.cit_return: "return",
        ida_hexrays.cit_goto: "goto",
        ida_hexrays.cit_asm: "asm",
        ida_hexrays.cit_end: "end",
    }
    
    @classmethod
    def get_expr_op_name(cls, op: int) -> str:
        """获取表达式操作码名称"""
        return cls.EXPR_OP_NAMES.get(op, f"unknown({op})")
    
    @classmethod
    def get_insn_op_name(cls, op: int) -> str:
        """获取语句操作码名称"""
        return cls.INSN_OP_NAMES.get(op, f"unknown({op})")
    
    @classmethod
    def get_citem_type_name(cls, item) -> str:
        """
        获取 citem 的具体类型名称
        
        参数:
            item: citem_t 对象
        返回:
            具体类型名称，如 cexpr_t(op_name) 或 cinsn_t(op_name)
        """
        if item is None:
            return "Unknown"
        
        op = item.op
        
        # cexpr_t: 表达式操作码 < cit_empty (64)
        # cinsn_t: 语句操作码 >= cit_empty (64)
        if op < ida_hexrays.cit_empty:
            return f"cexpr_t({cls.get_expr_op_name(op)})"
        else:
            return f"cinsn_t({cls.get_insn_op_name(op)})"
    
    @staticmethod
    def tag_addrcode(s: str) -> bool:
        """检查字符串是否以地址颜色码开头"""
        return (len(s) >= 2 and 
                s[0] == idaapi.COLOR_ON and 
                s[1] == chr(idaapi.COLOR_ADDR))
    
    @classmethod
    def extract_citem_indices_from_line(cls, line: str, cfunc) -> set:
        """
        从伪代码行中提取所有 citem 索引
        
        参数:
            line: 包含颜色标签的伪代码行
            cfunc: cfunc_t 对象，用于获取 citem 信息
        返回:
            citem 索引集合，格式为 (citem_index, ea) 的元组集合
        """
        anchor = idaapi.ctree_anchor_t()
        line = str(line)
        citem_info = set()

        while len(line) > 0:
            skipcode_index = idaapi.tag_skipcode(line)
            if skipcode_index == 0:
                line = line[1:]
            else:
                if cls.tag_addrcode(line):
                    addr_tag = int(line[2:skipcode_index], 16)
                    anchor.value = addr_tag
                    if anchor.is_citem_anchor() and not anchor.is_blkcmt_anchor():
                        item = cfunc.treeitems.at(addr_tag)
                        ea = item.ea if item else idaapi.BADADDR
                        citem_info.add((addr_tag, ea))
                line = line[skipcode_index:]
        
        return citem_info
    
    @staticmethod
    def get_citem_string(cfunc, item, remove_tags: bool = True) -> str:
        """
        获取 citem 的字符串表示
        
        参数:
            cfunc: cfunc_t 对象
            item: citem_t 对象
            remove_tags: 是否移除颜色标签
        返回:
            citem 的字符串表示
        """
        if item is None:
            return ""
        
        text = item.print1(cfunc)
        if remove_tags and text:
            text = idaapi.tag_remove(text)
        return text
