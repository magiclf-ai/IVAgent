#!/usr/bin/env python3
"""
引擎工厂 - 创建异步分析引擎实例
"""

from typing import Optional, Any, List
from .base_static_analysis_engine import (
    FunctionDef, CallSite, CrossReference, BaseStaticAnalysisEngine,
    SearchOptions, SearchResult
)

# 导入异步 IDA 引擎
from .ida_engine import IDAClient, IDAStaticAnalysisEngine

# 导入异步 JEB 引擎
from .jeb_engine import JEBClient, JEBStaticAnalysisEngine

# 导入异步 Abc-Decompiler 引擎
from .abc_engine import AbcStaticAnalysisEngine

# 导入源码引擎
from .source_code_engine import SourceCodeEngine

__all__ = [
    # 基础接口
    'FunctionDef',
    'CallSite',
    'CrossReference',
    'BaseStaticAnalysisEngine',
    'SearchOptions',
    'SearchResult',
    'create_engine',
    # IDA 引擎
    'IDAClient',
    'IDAStaticAnalysisEngine',
    'create_ida_engine',
    # JEB 引擎
    'JEBClient',
    'JEBStaticAnalysisEngine',
    'create_jeb_engine',
    # Abc 引擎
    'AbcStaticAnalysisEngine',
    'create_abc_engine',
    # 源码引擎
    'SourceCodeEngine',
    'create_source_engine',
]


def create_engine(
        engine_type: str,
        target_path: Optional[str] = None,
        source_root: Optional[str] = None,
        llm_client: Optional[Any] = None,
        **kwargs
) -> BaseStaticAnalysisEngine:
    """
    工厂函数：创建异步分析引擎实例
    
    参数:
        engine_type: 引擎类型 ("ida", "jeb", "abc", "source", "tree_sitter", "joern")
        target_path: 分析目标路径（IDB/源码目录，用于信息展示）
        source_root: 源代码根目录（用于 CallsiteAgent 源码分析）
        llm_client: LLM 客户端（用于 CallsiteAgent）
        **kwargs: 传递给引擎的额外参数
            - host: RPC Server 地址（默认 127.0.0.1）
            - port: RPC Server 端口（默认 9999）
            - timeout: 连接超时时间（默认 60 秒）
            - auto_connect: 是否自动连接（默认 True）
            - max_concurrency: 最大并发数（默认 10）
            - language: 编程语言（用于 source 引擎）
            - file_extensions: 文件扩展名列表（用于 source 引擎）
    
    返回:
        BaseEngine 实例
    """
    engine_type = engine_type.lower()

    if engine_type == "ida":
        host = kwargs.pop("host", "127.0.0.1")
        port = kwargs.pop("port", 9999)
        max_concurrency = kwargs.pop("max_concurrency", 10)
        print(f"[*] Creating IDAEngine connecting to {host}:{port}")
        return IDAStaticAnalysisEngine(
            target_path=target_path,
            host=host,
            port=port,
            max_concurrency=max_concurrency,
            source_root=source_root,
            llm_client=llm_client,
            **kwargs
        )

    elif engine_type == "jeb":
        host = kwargs.pop("host", "127.0.0.1")
        port = kwargs.pop("port", 16161)
        max_concurrency = kwargs.pop("max_concurrency", 10)
        print(f"[*] Creating JEBEngine connecting to {host}:{port}")
        return JEBStaticAnalysisEngine(
            target_path=target_path,
            host=host,
            port=port,
            max_concurrency=max_concurrency,
            source_root=source_root,
            llm_client=llm_client,
            **kwargs
        )

    elif engine_type in ["abc", "abc-decompiler"]:
        host = kwargs.pop("host", "127.0.0.1")
        port = kwargs.pop("port", 8651)

        # Construct URL if host is not already a URL
        if "://" in host:
            url = host
        else:
            url = f"http://{host}:{port}/mcp"

        print(f"[*] Creating AbcEngine connecting to {url}")
        return AbcStaticAnalysisEngine(
            target_path=target_path,
            host=url,
            source_root=source_root,
            llm_client=llm_client,
            **kwargs
        )

    elif engine_type in ["tree_sitter", "treesitter"]:
        raise NotImplementedError(
            "Tree-sitter analyzer not yet implemented. "
            "Planned for source code analysis."
        )

    elif engine_type == "joern":
        raise NotImplementedError(
            "Joern analyzer not yet implemented. "
            "Planned for CPG-based analysis."
        )

    elif engine_type in ["source", "source_code", "sourcecode"]:
        # SourceCodeEngine 不需要 host/port，弹出这些 RPC 相关参数
        kwargs.pop("host", None)
        kwargs.pop("port", None)
        kwargs.pop("timeout", None)
        kwargs.pop("auto_connect", None)
        max_concurrency = kwargs.pop("max_concurrency", 10)
        print(f"[*] Creating SourceCodeEngine for: {target_path or source_root}")
        return SourceCodeEngine(
            target_path=target_path,
            source_root=source_root,
            llm_client=llm_client,
            max_concurrency=max_concurrency,
            **kwargs
        )

    else:
        raise ValueError(
            f"Unknown engine type: {engine_type}. "
            f"Supported: ida, jeb, abc, source"
        )


def create_ida_engine(
        target_path: Optional[str] = None,
        host: str = "127.0.0.1",
        port: int = 9999,
        max_concurrency: int = 10,
        source_root: Optional[str] = None,
        llm_client: Optional[Any] = None,
        **kwargs
) -> IDAStaticAnalysisEngine:
    """
    便捷函数：创建异步 IDA 引擎
    
    参数:
        target_path: IDB 文件路径（用于信息展示）
        host: RPC Server 地址
        port: RPC Server 端口
        max_concurrency: 最大并发数
        source_root: 源代码根目录（用于 CallsiteAgent 源码分析）
        llm_client: LLM 客户端（用于 CallsiteAgent）
        **kwargs: 额外参数
    
    返回:
        IDA 引擎实例
    """
    return create_engine(
        "ida",
        target_path=target_path,
        host=host,
        port=port,
        max_concurrency=max_concurrency,
        source_root=source_root,
        llm_client=llm_client,
        **kwargs
    )


def create_jeb_engine(
        target_path: Optional[str] = None,
        host: str = "127.0.0.1",
        port: int = 16161,
        max_concurrency: int = 10,
        source_root: Optional[str] = None,
        llm_client: Optional[Any] = None,
        **kwargs
) -> JEBStaticAnalysisEngine:
    """
    便捷函数：创建异步 JEB 引擎

    参数:
        target_path: APK 文件路径（用于分析）
        host: JEB RPC Server 地址
        port: JEB RPC Server 端口（默认 16161）
        max_concurrency: 最大并发数
        source_root: 源代码根目录（用于 CallsiteAgent 源码分析）
        llm_client: LLM 客户端（用于 CallsiteAgent）
        **kwargs: 额外参数

    返回:
        JEB 引擎实例
    """
    return create_engine(
        "jeb",
        target_path=target_path,
        host=host,
        port=port,
        max_concurrency=max_concurrency,
        source_root=source_root,
        llm_client=llm_client,
        **kwargs
    )


def create_abc_engine(
        target_path: Optional[str] = None,
        host: str = "http://127.0.0.1:8651/mcp",
        source_root: Optional[str] = None,
        llm_client: Optional[Any] = None,
        **kwargs
) -> AbcStaticAnalysisEngine:
    """
    便捷函数：创建异步 Abc-Decompiler 引擎

    参数:
        target_path: 目标文件路径（用于分析）
        host: Abc-Decompiler MCP Server URL
        source_root: 源代码根目录（用于 CallsiteAgent 源码分析）
        llm_client: LLM 客户端（用于 CallsiteAgent）
        **kwargs: 额外参数

    返回:
        Abc 引擎实例
    """
    return create_engine(
        "abc",
        target_path=target_path,
        host=host,
        source_root=source_root,
        llm_client=llm_client,
        **kwargs
    )


def create_source_engine(
        source_root: str,
        target_path: Optional[str] = None,
        llm_client: Optional[Any] = None,
        language: Optional[str] = None,
        file_extensions: Optional[List[str]] = None,
        max_concurrency: int = 10,
        **kwargs
) -> SourceCodeEngine:
    """
    便捷函数：创建源码分析引擎

    基于 LLM Agent + 文本搜索的通用源码分析引擎。
    无需依赖外部反编译工具，直接分析源代码。

    参数:
        source_root: 源代码根目录（必需）
        target_path: 目标路径（可选，默认使用 source_root）
        llm_client: LLM 客户端（用于智能分析）
        language: 编程语言（c, cpp, java, python, javascript, typescript）
                如果不指定，会自动检测
        file_extensions: 文件扩展名列表（如 [".c", ".h"]）
        max_concurrency: 最大并发数
        **kwargs: 额外参数

    返回:
        SourceCodeEngine 实例

    """
    return create_engine(
        "source",
        target_path=target_path or source_root,
        source_root=source_root,
        llm_client=llm_client,
        language=language,
        file_extensions=file_extensions,
        max_concurrency=max_concurrency,
        **kwargs
    )
