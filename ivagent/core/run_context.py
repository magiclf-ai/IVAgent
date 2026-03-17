#!/usr/bin/env python3
"""
运行时执行上下文。

用于将当前运行实例的标识透传到日志与漏洞记录中，
以支持共享数据库场景下的精确切片与归档。
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Dict, Optional


ENV_RUN_ID = "IVAGENT_RUN_ID"
ENV_RUN_LABEL = "IVAGENT_RUN_LABEL"


@dataclass(frozen=True)
class RunContext:
    """当前执行实例的运行上下文。"""

    run_id: str
    run_label: Optional[str] = None


def get_run_context() -> Optional[RunContext]:
    """从环境变量读取当前运行上下文。"""

    run_id = (os.environ.get(ENV_RUN_ID) or "").strip()
    if not run_id:
        return None
    run_label = (os.environ.get(ENV_RUN_LABEL) or "").strip() or None
    return RunContext(run_id=run_id, run_label=run_label)


def get_run_metadata() -> Dict[str, Any]:
    """返回可直接写入日志 metadata 的运行上下文字段。"""

    context = get_run_context()
    if context is None:
        return {}

    metadata: Dict[str, Any] = {"run_id": context.run_id}
    if context.run_label:
        metadata["run_label"] = context.run_label
    return metadata


def merge_run_metadata(metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """合并调用方 metadata 与当前运行上下文。"""

    merged = dict(metadata) if metadata else {}
    for key, value in get_run_metadata().items():
        merged.setdefault(key, value)
    return merged
