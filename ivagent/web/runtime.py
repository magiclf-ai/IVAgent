#!/usr/bin/env python3
"""
Web 服务运行时管理。
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import aiohttp

from ivagent.core.cli_logger import CLILogger
from ivagent.core.db_profiles import (
    ENV_AGENT_LOG_DB,
    ENV_KEY,
    ENV_LLM_LOG_DB,
    ENV_VULN_DB,
    PROFILE_EVAL,
    PROFILE_PRODUCTION,
    activate_db_profile,
    get_db_paths,
)


DEFAULT_WEB_HOST = "127.0.0.1"
DEFAULT_WEB_PORT = 8080
_VALID_PROFILES = {PROFILE_PRODUCTION, PROFILE_EVAL}
_REPO_ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class WebServerHandle:
    """Web 服务句柄。"""

    url: str
    profile: str
    reused: bool
    pid: Optional[int] = None


def _normalize_profile(profile: str) -> str:
    normalized = (profile or "").strip().lower()
    if normalized not in _VALID_PROFILES:
        raise ValueError(f"不支持的 Web profile: {profile!r}")
    return normalized


def _build_url(host: str, port: int) -> str:
    return f"http://{host}:{port}"


def _health_matches_profile(health: dict, profile: str) -> bool:
    active_profile = str(health.get("profile") or "").strip().lower()
    if active_profile == profile:
        return True

    try:
        expected = get_db_paths(profile)
    except ValueError:
        return False
    if active_profile:
        try:
            active_paths = get_db_paths(active_profile)
            if active_paths == expected:
                return True
        except ValueError:
            pass
    db_paths = health.get("db_paths") or {}
    return (
        str(db_paths.get("llm") or "") == str(expected.llm_log_db)
        and str(db_paths.get("agent") or "") == str(expected.agent_log_db)
        and str(db_paths.get("vuln") or "") == str(expected.vuln_db)
    )


async def _fetch_health(host: str, port: int) -> Optional[dict]:
    url = f"{_build_url(host, port)}/api/health"
    timeout = aiohttp.ClientTimeout(total=3)
    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url) as response:
                if response.status != 200:
                    return None
                try:
                    return await response.json()
                except (aiohttp.ContentTypeError, json.JSONDecodeError):
                    return None
    except Exception:
        return None


def _is_port_open(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1.0)
        return sock.connect_ex((host, port)) == 0


def _build_subprocess_env(profile: str) -> dict[str, str]:
    env = dict(os.environ)
    env[ENV_KEY] = profile
    for key in (ENV_LLM_LOG_DB, ENV_AGENT_LOG_DB, ENV_VULN_DB):
        env.pop(key, None)
    return env


def _log_file_path(profile: str) -> Path:
    db_paths = activate_db_profile(profile, clear_path_overrides=True)
    return db_paths.llm_log_db.parent / "web_server.log"


async def _wait_for_ready(host: str, port: int, profile: str, timeout_seconds: float) -> None:
    deadline = asyncio.get_running_loop().time() + timeout_seconds
    while asyncio.get_running_loop().time() < deadline:
        health = await _fetch_health(host, port)
        if health and health.get("status") == "ok" and health.get("service") == "ivagent_web":
            active_profile = str(health.get("profile") or "").strip().lower()
            if _health_matches_profile(health, profile):
                return
            raise RuntimeError(
                f"Web 服务已启动但 profile 不匹配: 期望 {profile}，实际 {active_profile or 'unknown'}"
            )
        await asyncio.sleep(0.5)
    raise TimeoutError(f"Web 服务启动超时: {host}:{port}")


async def ensure_web_server(
    *,
    profile: str,
    host: str = DEFAULT_WEB_HOST,
    port: int = DEFAULT_WEB_PORT,
    logger: Optional[CLILogger] = None,
    startup_timeout: float = 20.0,
) -> WebServerHandle:
    """确保 Web 服务已启动并绑定指定 profile。"""

    normalized_profile = _normalize_profile(profile)
    web_logger = logger or CLILogger(component="WebRuntime")
    url = _build_url(host, port)

    health = await _fetch_health(host, port)
    if health and health.get("status") == "ok" and health.get("service") == "ivagent_web":
        active_profile = str(health.get("profile") or "").strip().lower()
        if not _health_matches_profile(health, normalized_profile):
            raise RuntimeError(
                f"检测到现有 Web 服务 profile={active_profile or 'unknown'}，与当前需要的 {normalized_profile} 不一致"
            )
        web_logger.info(
            "web.reuse",
            "复用已运行的 Web 服务",
            url=url,
            profile=normalized_profile,
        )
        return WebServerHandle(url=url, profile=normalized_profile, reused=True)

    if _is_port_open(host, port):
        raise RuntimeError(
            f"端口 {host}:{port} 已被非 IVAgent Web 服务占用，请先释放该端口"
        )

    log_path = _log_file_path(normalized_profile)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    env = _build_subprocess_env(normalized_profile)
    command = [
        sys.executable,
        "-m",
        "ivagent.web.server",
        "--host",
        host,
        "--port",
        str(port),
        "--profile",
        normalized_profile,
    ]

    with log_path.open("ab") as stream:
        process = subprocess.Popen(
            command,
            cwd=str(_REPO_ROOT),
            env=env,
            stdout=stream,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )

    web_logger.info(
        "web.start",
        "已在后台启动 Web 服务",
        url=url,
        profile=normalized_profile,
        pid=process.pid,
        log_path=str(log_path),
    )
    await _wait_for_ready(host, port, normalized_profile, startup_timeout)
    return WebServerHandle(
        url=url,
        profile=normalized_profile,
        reused=False,
        pid=process.pid,
    )
