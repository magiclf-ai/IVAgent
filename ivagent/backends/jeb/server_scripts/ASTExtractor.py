# -*- coding: utf-8 -*-

import json
from com.pnfsoftware.jeb.core.units.code.java import IJavaSourceUnit, IJavaClass, IJavaCall

class ASTExtractor:
    """JEB AST遍历器，用于提取方法调用和参数信息"""
    
    def __init__(self, decomp):
        self.calls = []
        self.decomp = decomp

    def find_decompiled_class_by_signature(self, signature):
        clz = self.decomp.getDecompiledUnit(signature)
        if not isinstance(clz, IJavaSourceUnit):
            return None
        elt = clz.getASTElement()
        return elt

    def find_decompiled_method(self, class_signature, method_name):
        clz = self.find_decompiled_class_by_signature(class_signature)

        if not clz:
            return None

        for m in clz.getMethods():
            if m.getName() == method_name:
                return m
        return None

    def extract_method_callee(self, class_signature, method_name):
        m = self.find_decompiled_method(class_signature, method_name)
        if not m:
            return []
        self._extract_calls_from_method(m)
        return self.calls
        
    
    def extract_callee_by_method_signature(self, method_signature):
        """
        通过方法签名提取调用信息
        
        Args:
            method_signature: 方法签名
        """
        m = self.decomp.getMethod(method_signature, True)
        self._extract_calls_from_method(m)
        return self.calls
        

    def extract_from_class(self, java_class, class_name):
        """
        从Java类中提取所有方法调用信息
        
        Args:
            java_class: IJavaClass对象
            class_name: 类名
        """
        if not isinstance(java_class, IJavaClass):
            return
        
        
        for method in java_class.getMethods():
            method_name = method.getName()
            self._extract_calls_from_method(method)
        
    def _extract_calls_from_method(self, method):
        """
        从方法中提取所有调用信息
        
        Args:
            method: 方法对象
        """
        self.calls = []
        self._traverse_ast(method, level=0)
    
    def _traverse_ast(self, element, level=0):
        """
        递归遍历AST节点
        
        Args:
            element: AST元素
            level: 当前层级
        """
        if not element:
            return
        
        # 如果是方法调用，提取详细信息
        if isinstance(element, IJavaCall):
            call_info = self._extract_call_info(element)
            if call_info:
                self.calls.append(call_info)
        
        # 递归处理子节点
        sub_elements = element.getSubElements()
        if sub_elements:
            for sub_element in sub_elements:
                self._traverse_ast(sub_element, level + 1)
    
    def _extract_call_info(self, call_element):
        """
        提取单个方法调用的信息
        
        Args:
            call_element: IJavaCall对象
            
        Returns:
            dict: 包含调用信息的字典
        """
        try:
            method_obj = call_element.getMethod()
            method_name = method_obj.getName()
            method_sig = method_obj.getSignature()
            
            # 获取参数
            args = []
            for arg in call_element.getArguments():
                args.append(str(arg))
            
            # 构建返回信息
            call_info = {
                'method': {
                    'signature': method_sig,
                    "name": method_name
                },
                'arguments': args,
                'line': str(call_element)
            }
            
            return call_info
            
        except Exception as e:
            print("[ASTExtractor] Error extracting call info: {}".format(e))
            return None
    
    def get_calls(self):
        """
        获取提取到的所有调用信息
        
        Returns:
            list: 调用信息列表
        """
        return self.calls
    
    
    def export_to_json(self, output_file):
        """
        将提取的调用信息导出为JSON文件
        
        Args:
            output_file: 输出文件路径
        """
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump({
                    'total_calls': len(self.calls),
                    'calls': self.calls
                }, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print("[ASTExtractor] Error exporting to JSON: {}".format(e))
    
    def reset(self):
        """重置提取器状态"""
        self.calls = []