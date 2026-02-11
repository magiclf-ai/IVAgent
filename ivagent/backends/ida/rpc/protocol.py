#!/usr/bin/env python3
"""

Simple JSON-RPC 2.0 Protocol


简化版 JSON-RPC 协议实现，用于 IDA 与 Engine 通信
"""


import json

from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field

from enum import IntEnum



class ErrorCode(IntEnum):

    """JSON-RPC 标准错误码"""

    PARSE_ERROR = -32700

    INVALID_REQUEST = -32600

    METHOD_NOT_FOUND = -32601

    INVALID_PARAMS = -32602

    INTERNAL_ERROR = -32603
    

    # 自定义错误码 (从 -32000 开始)

    IDA_NOT_INITIALIZED = -32001

    FUNCTION_NOT_FOUND = -32002

    DECOMPILE_ERROR = -32003



@dataclass

class Request:

    """JSON-RPC 请求"""

    method: str

    params: Dict[str, Any] = field(default_factory=dict)

    id: Optional[Any] = None

    jsonrpc: str = "2.0"
    

    def to_dict(self) -> Dict[str, Any]:

        result = {

            "jsonrpc": self.jsonrpc,

            "method": self.method,
            "params": self.params,

        }

        if self.id is not None:

            result["id"] = self.id
        return result
    

    def to_json(self) -> str:

        return json.dumps(self.to_dict(), ensure_ascii=False)
    

    @classmethod

    def from_dict(cls, data: Dict[str, Any]) -> 'Request':
        return cls(

            jsonrpc=data.get("jsonrpc", "2.0"),

            id=data.get("id"),

            method=data.get("method", ""),

            params=data.get("params", {}),
        )



@dataclass

class Response:

    """JSON-RPC 响应"""

    id: Optional[Any] = None

    result: Optional[Any] = None
    _error: Optional[Dict[str, Any]] = None

    jsonrpc: str = "2.0"
    

    def to_dict(self) -> Dict[str, Any]:

        result = {"jsonrpc": self.jsonrpc}

        if self.id is not None:

            result["id"] = self.id
        if self._error:

            result["error"] = self._error
        else:

            result["result"] = self.result
        return result
    

    def to_json(self) -> str:

        return json.dumps(self.to_dict(), ensure_ascii=False)
    

    @classmethod

    def success(cls, id: Optional[Any], result: Any) -> 'Response':

        """创建成功响应"""

        return cls(jsonrpc="2.0", id=id, result=result)
    

    @classmethod
    def error(cls, id: Optional[Any], code: int, message: str, data: Any = None) -> 'Response':

        """创建错误响应"""

        error = {"code": code, "message": message}
        if data:

            error["data"] = data

        return cls(jsonrpc="2.0", id=id, _error=error)
    

    @classmethod

    def from_dict(cls, data: Dict[str, Any]) -> 'Response':
        return cls(
            jsonrpc=data.get("jsonrpc", "2.0"),
            id=data.get("id"),
            result=data.get("result"),
            _error=data.get("error"),
        )



def parse_message(data: bytes) -> Optional[Request]:

    """解析 JSON-RPC 消息"""

    try:

        text = data.decode('utf-8').strip()

        if not text:

            return None

        obj = json.loads(text)

        return Request.from_dict(obj)

    except (json.JSONDecodeError, UnicodeDecodeError):

        return None



def format_message(msg: Any) -> bytes:

    """格式化消息为字节"""

    if isinstance(msg, (Request, Response)):

        return msg.to_json().encode('utf-8') + b'\n'

    elif isinstance(msg, dict):

        return json.dumps(msg, ensure_ascii=False).encode('utf-8') + b'\n'
    else:

        return str(msg).encode('utf-8') + b'\n'

