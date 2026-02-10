#!/usr/bin/env python3
"""
Abc-Decompiler (Jadx-based) Decompiler Implementation

Provides access to decompiled Java methods, including:
- Code line management
- Line number mapping
- Function call collection
"""

from typing import Set, Dict, List, Tuple, Optional
from dataclasses import dataclass, field
import re


@dataclass
class CallInfo:
    """Method call information"""
    target_name: str          # Target method name
    target_signature: str     # Target method signature
    line_index: int           # Line number where call occurs
    call_text: str            # Text of the call statement
    arguments: List[str] = field(default_factory=list)  # List of arguments


class DecompiledMethod:
    """
    Manages decompiled Java method information from Abc-Decompiler
    
    Provides code line management and call information collection
    """
    
    def __init__(self, signature: str, code: str):
        """
        Initialize DecompiledMethod object

        Args:
            signature: Full method signature
            code: Decompiled Java code
        """
        self.signature = signature
        self.raw_code = code
        self._lines: List[str] = []           # List of code lines
        self._calls: List[CallInfo] = []      # Collected method calls
        
        # Parse code into lines
        self._parse_lines()
        # Collect call information
        self._collect_calls()
    
    def _parse_lines(self):
        """Parse code into a list of lines"""
        if not self.raw_code:
            return
        
        # Split by lines, keeping empty lines
        self._lines = self.raw_code.splitlines()
    
    def _collect_calls(self):
        """Collect method call information"""
        # Regex to match method calls
        # Pattern: obj.method(arg1, arg2) or Class.method(arg1, arg2)
        call_pattern = re.compile(
            r'(\w+)\s*\.\s*(\w+)\s*\(([^)]*)\)'
        )
        
        # Also match static method calls: ClassName.methodName(...)
        # And calls within the class: method(...) -> this.method(...) is implicit but hard to regex perfectly without 'this.'
        # For now, stick to explicit calls or simple calls
        
        for line_idx, line in enumerate(self._lines):
            # Skip comment lines
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('*') or stripped.startswith('/*'):
                continue
            
            # Find method calls
            for match in call_pattern.finditer(line):
                obj_name = match.group(1)
                method_name = match.group(2)
                args_text = match.group(3)
                
                # Skip keywords (control flow)
                if obj_name in ['if', 'while', 'for', 'switch', 'return', 'new', 'catch']:
                    continue
                
                # Parse arguments
                args = [a.strip() for a in args_text.split(',') if a.strip()]
                
                call_info = CallInfo(
                    target_name=method_name,
                    target_signature=f"{obj_name}.{method_name}",
                    line_index=line_idx,
                    call_text=line.strip(),
                    arguments=args
                )
                self._calls.append(call_info)

    @property
    def lines(self) -> List[str]:
        """Return list of code lines"""
        return self._lines

    @property
    def calls(self) -> List[CallInfo]:
        """Return collected method calls"""
        return self._calls
