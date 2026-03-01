#!/usr/bin/env python3
"""
CLI 日志工具：统一命令行输出格式，提升可读性与调试性。
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import os
import sys
import traceback
from typing import Any, TextIO


_LEVEL_PRIORITY = {
    "DEBUG": 10,
    "INFO": 20,
    "SUCCESS": 25,
    "WARNING": 30,
    "ERROR": 40,
}

_LEVEL_ALIASES = {
    "WARN": "WARNING",
    "WARNING": "WARNING",
    "DEBUG": "DEBUG",
    "INFO": "INFO",
    "ERROR": "ERROR",
    "SUCCESS": "SUCCESS",
}

_MODE_ALIASES = {
    "": "normal",
    "normal": "normal",
    "default": "normal",
    "verbose": "verbose",
    "debug": "debug",
}

_NOISY_EVENT_KIND_ALLOWLIST = {
    "deep_vuln.progress": {
        "normal": {"lifecycle", "tool_round", "vulnerability", "summary", "subagent", "error"},
        "verbose": {"lifecycle", "tool_round", "vulnerability", "summary", "subagent", "error"},
    },
    "tools.agent_progress": {
        "normal": {"lifecycle", "tool_round", "vulnerability", "summary", "subagent", "error"},
        "verbose": {"lifecycle", "tool_round", "vulnerability", "summary", "subagent", "error"},
    },
    "agent.progress": {
        "normal": {"lifecycle", "tool_round", "vulnerability", "summary", "subagent", "error"},
        "verbose": {"lifecycle", "tool_round", "vulnerability", "summary", "subagent", "error"},
    },
}


def format_duration(seconds: float) -> str:
    """格式化耗时，提升日志可读性。"""
    if seconds < 0:
        return "0ms"
    if seconds < 1:
        return f"{seconds * 1000:.0f}ms"
    if seconds < 60:
        return f"{seconds:.2f}s"
    minutes = int(seconds // 60)
    remain = seconds - minutes * 60
    return f"{minutes}m{remain:.2f}s"


def _normalize_level(level: str) -> str:
    return _LEVEL_ALIASES.get((level or "INFO").upper(), "INFO")


def _normalize_mode(mode: str) -> str:
    return _MODE_ALIASES.get((mode or "").strip().lower(), "normal")


def _sanitize(value: Any) -> str:
    text = str(value)
    text = text.replace("\n", "\\n").replace("\r", "\\r")
    return text


@dataclass
class CLILogger:
    """轻量命令行日志器。"""

    component: str
    verbose: bool = False
    mode: str = ""
    stream: TextIO = sys.stdout

    def _effective_mode(self) -> str:
        if self.mode:
            return _normalize_mode(self.mode)
        env_mode = os.getenv("IVAGENT_LOG_MODE", "").strip()
        if env_mode:
            return _normalize_mode(env_mode)
        return "verbose" if self.verbose else "normal"

    def _should_emit(self, level: str) -> bool:
        mode = self._effective_mode()
        threshold = _LEVEL_PRIORITY["DEBUG"] if mode == "debug" else _LEVEL_PRIORITY["INFO"]
        return _LEVEL_PRIORITY.get(level, 20) >= threshold

    def _should_emit_event(self, event: str, kind: str) -> bool:
        mode = self._effective_mode()
        if mode == "debug":
            return True

        allowlist = _NOISY_EVENT_KIND_ALLOWLIST.get(event)
        if allowlist is None:
            return True

        if not kind:
            return False
        return kind in allowlist.get(mode, allowlist["normal"])

    def log(self, level: str, event: str, message: str = "", **fields: Any) -> None:
        normalized_level = _normalize_level(level)
        if not self._should_emit(normalized_level):
            return

        kind = _sanitize(fields.pop("kind", "")).lower().strip()
        if not self._should_emit_event(event, kind):
            return

        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        parts = [f"[{ts}]", f"[{normalized_level}]", f"[{self.component}]"]

        tail = event.strip() if event else "event"
        if message:
            tail += f" | {_sanitize(message)}"

        field_items = []
        for key, value in fields.items():
            if value is None:
                continue
            field_items.append(f"{key}={_sanitize(value)}")
        if kind and self._effective_mode() == "debug":
            field_items.append(f"kind={_sanitize(kind)}")

        if field_items:
            tail += " | " + ", ".join(field_items)

        print(" ".join(parts) + " " + tail, file=self.stream, flush=True)

    def debug(self, event: str, message: str = "", **fields: Any) -> None:
        self.log("DEBUG", event, message, **fields)

    def info(self, event: str, message: str = "", **fields: Any) -> None:
        self.log("INFO", event, message, **fields)

    def success(self, event: str, message: str = "", **fields: Any) -> None:
        self.log("SUCCESS", event, message, **fields)

    def warning(self, event: str, message: str = "", **fields: Any) -> None:
        self.log("WARNING", event, message, **fields)

    def error(self, event: str, message: str = "", **fields: Any) -> None:
        self.log("ERROR", event, message, **fields)

    def exception(self, event: str, exc: Exception, **fields: Any) -> None:
        self.error(
            event,
            str(exc),
            error_type=type(exc).__name__,
            **fields,
        )
        if not self.verbose:
            return
        trace = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__)).strip()
        for line in trace.splitlines():
            if line.strip():
                self.debug("traceback", line)
