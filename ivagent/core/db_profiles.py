#!/usr/bin/env python3
"""
数据库 Profile 管理。

两个内置 profile：
- production（默认）：真实扫描运行使用
- eval：测试与评估使用

通过环境变量 IVAGENT_DB_PROFILE 选择 profile，
也可以通过精确路径环境变量覆盖单个数据库文件：
- IVAGENT_LLM_LOG_DB
- IVAGENT_AGENT_LOG_DB
- IVAGENT_VULN_DB

或直接调用 get_db_paths(profile) 获取路径。
"""

import os
from dataclasses import dataclass
from pathlib import Path

_IVAGENT_HOME = Path.home() / ".ivagent"

PROFILE_PRODUCTION = "production"
PROFILE_EVAL = "eval"
ENV_KEY = "IVAGENT_DB_PROFILE"
ENV_LLM_LOG_DB = "IVAGENT_LLM_LOG_DB"
ENV_AGENT_LOG_DB = "IVAGENT_AGENT_LOG_DB"
ENV_VULN_DB = "IVAGENT_VULN_DB"


@dataclass(frozen=True)
class DBPaths:
    """一组数据库文件路径。"""
    llm_log_db: Path
    agent_log_db: Path
    vuln_db: Path


_PROFILES = {
    PROFILE_PRODUCTION: DBPaths(
        llm_log_db=_IVAGENT_HOME / "production" / "llm_logs.db",
        agent_log_db=_IVAGENT_HOME / "production" / "agent_logs.db",
        vuln_db=_IVAGENT_HOME / "production" / "vulnerabilities.db",
    ),
    PROFILE_EVAL: DBPaths(
        llm_log_db=_IVAGENT_HOME / "eval" / "llm_logs.db",
        agent_log_db=_IVAGENT_HOME / "eval" / "agent_logs.db",
        vuln_db=_IVAGENT_HOME / "eval" / "vulnerabilities.db",
    ),
}


def get_db_paths(profile: str | None = None) -> DBPaths:
    """根据 profile 名称返回数据库路径。

    优先级：
    1. 精确路径环境变量（按文件覆盖）
    2. 参数指定的 profile
    3. IVAGENT_DB_PROFILE
    4. production
    """
    name = (profile or os.environ.get(ENV_KEY, "")).strip().lower()
    if not name:
        name = PROFILE_PRODUCTION
    paths = _PROFILES.get(name)
    if paths is None:
        raise ValueError(
            f"未知 profile: {name!r}，可选值: {list(_PROFILES.keys())}"
        )

    llm_log_db = Path(os.environ[ENV_LLM_LOG_DB]).expanduser() if os.environ.get(ENV_LLM_LOG_DB) else paths.llm_log_db
    agent_log_db = Path(os.environ[ENV_AGENT_LOG_DB]).expanduser() if os.environ.get(ENV_AGENT_LOG_DB) else paths.agent_log_db
    vuln_db = Path(os.environ[ENV_VULN_DB]).expanduser() if os.environ.get(ENV_VULN_DB) else paths.vuln_db
    resolved = DBPaths(
        llm_log_db=llm_log_db,
        agent_log_db=agent_log_db,
        vuln_db=vuln_db,
    )

    # 确保目录存在
    for p in (resolved.llm_log_db, resolved.agent_log_db, resolved.vuln_db):
        p.parent.mkdir(parents=True, exist_ok=True)
    return resolved
