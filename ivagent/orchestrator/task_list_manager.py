#!/usr/bin/env python3
"""
TaskListManager - 基于 SQLite 的任务状态管理器

设计目标:
- 单一真源: tasks.db
- 原子认领: claim_batch_tasks
- 幂等追加: task_uid 唯一约束
"""

from __future__ import annotations

import hashlib
import re
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class TaskStatus(str, Enum):
    """任务状态枚举。"""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class Task:
    """任务记录。"""

    id: str
    description: str
    status: TaskStatus
    created_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    depends_on: Optional[str] = None
    agent_type: Optional[str] = None
    function_identifier: Optional[str] = None
    task_group: Optional[str] = None
    workflow_name: Optional[str] = None
    workflow_execution_mode: Optional[str] = None
    analysis_context: Optional[str] = None
    task_uid: Optional[str] = None
    claimed_by: Optional[str] = None
    lease_expires_at: Optional[int] = None
    attempt_count: int = 0
    error_message: Optional[str] = None

    def to_markdown_line(self) -> str:
        checkbox_map = {
            TaskStatus.PENDING: "[ ]",
            TaskStatus.IN_PROGRESS: "[-]",
            TaskStatus.COMPLETED: "[x]",
            TaskStatus.FAILED: "[!]",
        }
        checkbox = checkbox_map[self.status]
        return f"- {checkbox} {self.id}: {self.description}"

    def to_metadata_comment(self) -> str:
        metadata: Dict[str, Any] = {
            "task_id": self.id,
            "created_at": self.created_at.isoformat(),
        }
        if self.completed_at:
            metadata["completed_at"] = self.completed_at.isoformat()
        if self.depends_on:
            metadata["depends_on"] = self.depends_on
        if self.agent_type:
            metadata["agent_type"] = self.agent_type
        if self.function_identifier:
            metadata["function_identifier"] = self.function_identifier
        if self.task_group:
            metadata["task_group"] = self.task_group
        if self.workflow_name:
            metadata["workflow_name"] = self.workflow_name
        if self.workflow_execution_mode:
            metadata["workflow_execution_mode"] = self.workflow_execution_mode
        if self.analysis_context:
            metadata["analysis_context"] = self.analysis_context
        if self.task_uid:
            metadata["task_uid"] = self.task_uid
        if self.claimed_by:
            metadata["claimed_by"] = self.claimed_by
        if self.lease_expires_at:
            metadata["lease_expires_at"] = self.lease_expires_at
        if self.attempt_count:
            metadata["attempt_count"] = self.attempt_count
        if self.error_message:
            metadata["error_message"] = self.error_message

        metadata_str = ", ".join(f"{k}: {v}" for k, v in metadata.items())
        return f"<!-- {metadata_str} -->"


class TaskListManager:
    """
    任务列表管理器（SQLite 后端）。

    说明:
    - `tasks.md` 仅作为可读快照，不作为状态真源。
    - `tasks.db` 才是唯一真源。
    """

    def __init__(self, tasks_file: Path):
        self.tasks_file = Path(tasks_file)
        self.db_file = self.tasks_file.with_suffix(".db")
        self.tasks_file.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
        self._save_tasks_snapshot()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_file), timeout=10, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=10000")
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS tasks (
                    id TEXT PRIMARY KEY,
                    task_uid TEXT NOT NULL UNIQUE,
                    description TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    completed_at TEXT,
                    depends_on TEXT,
                    agent_type TEXT,
                    function_identifier TEXT,
                    task_group TEXT,
                    workflow_name TEXT,
                    workflow_execution_mode TEXT,
                    analysis_context TEXT,
                    claimed_by TEXT,
                    lease_expires_at INTEGER,
                    attempt_count INTEGER NOT NULL DEFAULT 0,
                    error_message TEXT
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS task_artifacts (
                    task_id TEXT NOT NULL,
                    slot TEXT NOT NULL,
                    artifact_ref TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (task_id, slot),
                    FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_tasks_group_status ON tasks(task_group, status)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_tasks_claim_lease ON tasks(claimed_by, lease_expires_at)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_task_artifacts_task_ct ON task_artifacts(task_id, created_at DESC)"
            )

    @staticmethod
    def _normalize_description(desc: str) -> str:
        return re.sub(r"\s+", " ", (desc or "").strip())

    def _compute_task_uid(
        self,
        description: str,
        agent_type: Optional[str],
        function_identifier: Optional[str],
        task_group: Optional[str],
    ) -> str:
        group = (task_group or "").strip()
        agent = (agent_type or "").strip()
        fid = (function_identifier or "").strip()
        desc = self._normalize_description(description)
        if agent == "vuln_analysis" and fid:
            raw = f"{group}|{agent}|{fid}"
        else:
            raw = f"{group}|{agent}|{desc}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]

    def _normalize_task_payload(self, payload: Any) -> Dict[str, Any]:
        if isinstance(payload, dict):
            description = self._normalize_description(str(payload.get("description", "")))
            return {
                "description": description,
                "agent_type": (payload.get("agent_type") or None),
                "function_identifier": (payload.get("function_identifier") or None),
                "task_group": (payload.get("task_group") or None),
                "workflow_name": (payload.get("workflow_name") or None),
                "workflow_execution_mode": (payload.get("workflow_execution_mode") or None),
                "analysis_context": (
                    payload.get("analysis_context_ref")
                    or payload.get("analysis_context")
                    or None
                ),
                "depends_on": (payload.get("depends_on") or None),
            }
        return {
            "description": self._normalize_description(str(payload)),
            "agent_type": None,
            "function_identifier": None,
            "task_group": None,
            "workflow_name": None,
            "workflow_execution_mode": None,
            "analysis_context": None,
            "depends_on": None,
        }

    @staticmethod
    def _extract_task_number(task_id: str) -> int:
        match = re.match(r"task_(\d+)", task_id)
        if match:
            return int(match.group(1))
        return 0

    @staticmethod
    def _row_to_task(row: sqlite3.Row) -> Task:
        created_at = datetime.fromisoformat(row["created_at"]) if row["created_at"] else datetime.now()
        completed_at = datetime.fromisoformat(row["completed_at"]) if row["completed_at"] else None
        return Task(
            id=row["id"],
            description=row["description"],
            status=TaskStatus(row["status"]),
            created_at=created_at,
            completed_at=completed_at,
            depends_on=row["depends_on"],
            agent_type=row["agent_type"],
            function_identifier=row["function_identifier"],
            task_group=row["task_group"],
            workflow_name=row["workflow_name"],
            workflow_execution_mode=row["workflow_execution_mode"],
            analysis_context=row["analysis_context"],
            task_uid=row["task_uid"],
            claimed_by=row["claimed_by"],
            lease_expires_at=row["lease_expires_at"],
            attempt_count=int(row["attempt_count"] or 0),
            error_message=row["error_message"],
        )

    def create_tasks(self, task_descriptions: List[Any]) -> Dict[str, int]:
        """
        重建任务列表。

        返回:
            {"added": n, "skipped_duplicates": m}
        """
        added = 0
        skipped = 0
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("DELETE FROM task_artifacts")
            conn.execute("DELETE FROM tasks")
            next_num = 1
            seen_uids: set[str] = set()
            for raw in task_descriptions:
                task = self._normalize_task_payload(raw)
                uid = self._compute_task_uid(
                    description=task["description"],
                    agent_type=task["agent_type"],
                    function_identifier=task["function_identifier"],
                    task_group=task["task_group"],
                )
                if uid in seen_uids:
                    skipped += 1
                    continue
                seen_uids.add(uid)
                task_id = f"task_{next_num}"
                next_num += 1
                conn.execute(
                    """
                    INSERT INTO tasks (
                        id, task_uid, description, status, created_at, completed_at, depends_on,
                        agent_type, function_identifier, task_group, workflow_name,
                        workflow_execution_mode, analysis_context, claimed_by, lease_expires_at,
                        attempt_count, error_message
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        task_id,
                        uid,
                        task["description"],
                        TaskStatus.PENDING.value,
                        datetime.now().isoformat(),
                        None,
                        task["depends_on"],
                        task["agent_type"],
                        task["function_identifier"],
                        task["task_group"],
                        task["workflow_name"],
                        task["workflow_execution_mode"],
                        task["analysis_context"],
                        None,
                        None,
                        0,
                        None,
                    ),
                )
                if task["analysis_context"]:
                    conn.execute(
                        """
                        INSERT INTO task_artifacts(task_id, slot, artifact_ref, created_at)
                        VALUES (?, ?, ?, ?)
                        ON CONFLICT(task_id, slot) DO UPDATE SET
                            artifact_ref = excluded.artifact_ref,
                            created_at = excluded.created_at
                        """,
                        (
                            task_id,
                            "analysis_context",
                            str(task["analysis_context"]),
                            datetime.now().isoformat(),
                        ),
                    )
                added += 1
            conn.commit()
        self._save_tasks_snapshot()
        return {"added": added, "skipped_duplicates": skipped}

    def append_tasks(self, task_descriptions: List[Any]) -> Dict[str, int]:
        """
        追加任务（按 task_uid 幂等）。

        返回:
            {"added": n, "skipped_duplicates": m}
        """
        added = 0
        skipped = 0
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            rows = conn.execute("SELECT id FROM tasks").fetchall()
            max_num = 0
            for row in rows:
                max_num = max(max_num, self._extract_task_number(row["id"]))
            next_num = max_num + 1

            for raw in task_descriptions:
                task = self._normalize_task_payload(raw)
                uid = self._compute_task_uid(
                    description=task["description"],
                    agent_type=task["agent_type"],
                    function_identifier=task["function_identifier"],
                    task_group=task["task_group"],
                )
                exists = conn.execute(
                    "SELECT 1 FROM tasks WHERE task_uid = ? LIMIT 1",
                    (uid,),
                ).fetchone()
                if exists:
                    skipped += 1
                    continue

                task_id = f"task_{next_num}"
                next_num += 1
                conn.execute(
                    """
                    INSERT INTO tasks (
                        id, task_uid, description, status, created_at, completed_at, depends_on,
                        agent_type, function_identifier, task_group, workflow_name,
                        workflow_execution_mode, analysis_context, claimed_by, lease_expires_at,
                        attempt_count, error_message
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        task_id,
                        uid,
                        task["description"],
                        TaskStatus.PENDING.value,
                        datetime.now().isoformat(),
                        None,
                        task["depends_on"],
                        task["agent_type"],
                        task["function_identifier"],
                        task["task_group"],
                        task["workflow_name"],
                        task["workflow_execution_mode"],
                        task["analysis_context"],
                        None,
                        None,
                        0,
                        None,
                    ),
                )
                if task["analysis_context"]:
                    conn.execute(
                        """
                        INSERT INTO task_artifacts(task_id, slot, artifact_ref, created_at)
                        VALUES (?, ?, ?, ?)
                        ON CONFLICT(task_id, slot) DO UPDATE SET
                            artifact_ref = excluded.artifact_ref,
                            created_at = excluded.created_at
                        """,
                        (
                            task_id,
                            "analysis_context",
                            str(task["analysis_context"]),
                            datetime.now().isoformat(),
                        ),
                    )
                added += 1
            conn.commit()

        self._save_tasks_snapshot()
        return {"added": added, "skipped_duplicates": skipped}

    def requeue_expired_leases(self, now_ts: Optional[int] = None) -> int:
        """将过期 in_progress 任务回收为 pending。"""
        now = int(now_ts or time.time())
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            cursor = conn.execute(
                """
                UPDATE tasks
                SET status = ?, claimed_by = NULL, lease_expires_at = NULL
                WHERE status = ? AND lease_expires_at IS NOT NULL AND lease_expires_at < ?
                """,
                (TaskStatus.PENDING.value, TaskStatus.IN_PROGRESS.value, now),
            )
            changed = cursor.rowcount or 0
            conn.commit()
        if changed > 0:
            self._save_tasks_snapshot()
        return changed

    def claim_batch_tasks(
        self,
        task_group: Optional[str],
        agent_type: str,
        limit: int = 1,
        require_function_identifier: bool = False,
        claimant: str = "",
        lease_seconds: int = 900,
    ) -> List[Task]:
        """原子认领一批任务。"""
        if limit <= 0:
            return []
        self.requeue_expired_leases()
        now = int(time.time())
        lease_expires = now + max(30, int(lease_seconds))
        claimant_id = (claimant or "default_claimant").strip()

        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            if task_group:
                rows = conn.execute(
                    """
                    SELECT * FROM tasks
                    WHERE task_group = ?
                    ORDER BY CAST(SUBSTR(id, 6) AS INTEGER) ASC
                    """,
                    (task_group,),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT * FROM tasks
                    ORDER BY CAST(SUBSTR(id, 6) AS INTEGER) ASC
                    """
                ).fetchall()

            start_idx = None
            for idx, row in enumerate(rows):
                if row["status"] == TaskStatus.PENDING.value:
                    start_idx = idx
                    break
            if start_idx is None:
                conn.commit()
                return []

            candidates: List[sqlite3.Row] = []
            for row in rows[start_idx:]:
                if row["status"] != TaskStatus.PENDING.value:
                    break
                if (row["agent_type"] or "") != agent_type:
                    break
                if require_function_identifier and not (row["function_identifier"] or "").strip():
                    break
                candidates.append(row)
                if len(candidates) >= limit:
                    break

            claimed_ids: List[str] = []
            for row in candidates:
                cursor = conn.execute(
                    """
                    UPDATE tasks
                    SET status = ?, claimed_by = ?, lease_expires_at = ?, attempt_count = attempt_count + 1
                    WHERE id = ? AND status = ?
                    """,
                    (
                        TaskStatus.IN_PROGRESS.value,
                        claimant_id,
                        lease_expires,
                        row["id"],
                        TaskStatus.PENDING.value,
                    ),
                )
                if (cursor.rowcount or 0) == 1:
                    claimed_ids.append(row["id"])

            if not claimed_ids:
                conn.commit()
                return []

            placeholders = ",".join("?" for _ in claimed_ids)
            claimed_rows = conn.execute(
                f"SELECT * FROM tasks WHERE id IN ({placeholders}) ORDER BY CAST(SUBSTR(id, 6) AS INTEGER) ASC",
                tuple(claimed_ids),
            ).fetchall()
            conn.commit()

        self._save_tasks_snapshot()
        return [self._row_to_task(row) for row in claimed_rows]

    def claim_next_task(
        self,
        task_group: Optional[str],
        agent_type: str,
        require_function_identifier: bool = False,
        claimant: str = "",
        lease_seconds: int = 900,
    ) -> Optional[Task]:
        tasks = self.claim_batch_tasks(
            task_group=task_group,
            agent_type=agent_type,
            limit=1,
            require_function_identifier=require_function_identifier,
            claimant=claimant,
            lease_seconds=lease_seconds,
        )
        return tasks[0] if tasks else None

    def _is_task_row_runnable(
        self,
        row: sqlite3.Row,
        conn: sqlite3.Connection,
        expected_agent_type: Optional[str] = None,
        require_function_identifier: bool = False,
    ) -> Tuple[bool, str]:
        """判断任务行是否可执行，并返回原因。"""
        status = row["status"] or ""
        if status != TaskStatus.PENDING.value:
            return False, f"status={status}"

        agent_type = (row["agent_type"] or "").strip()
        if not agent_type:
            return False, "missing_agent_type"
        if expected_agent_type and agent_type != expected_agent_type:
            return False, f"agent_type_mismatch:{agent_type}"

        depends_on = (row["depends_on"] or "").strip()
        if depends_on:
            dep_row = conn.execute(
                "SELECT status FROM tasks WHERE id = ? LIMIT 1",
                (depends_on,),
            ).fetchone()
            if not dep_row:
                return False, f"depends_on_not_found:{depends_on}"
            dep_status = dep_row["status"] or ""
            if dep_status != TaskStatus.COMPLETED.value:
                return False, f"depends_on_not_completed:{depends_on}:{dep_status}"

        function_identifier = (row["function_identifier"] or "").strip()
        if require_function_identifier and not function_identifier:
            return False, "missing_function_identifier"
        if agent_type == "vuln_analysis" and not function_identifier:
            return False, "missing_function_identifier"

        return True, "ready"

    def claim_task_by_id(
        self,
        task_id: str,
        claimant: str = "",
        lease_seconds: int = 900,
        task_group: Optional[str] = None,
        expected_agent_type: Optional[str] = None,
        require_function_identifier: bool = False,
    ) -> Optional[Task]:
        """
        原子认领指定任务。

        仅当任务处于 pending 且满足依赖/参数前置时认领成功。
        """
        if not (task_id or "").strip():
            return None

        self.requeue_expired_leases()
        lease_expires = int(time.time()) + max(30, int(lease_seconds))
        claimant_id = (claimant or "default_claimant").strip()

        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM tasks WHERE id = ? LIMIT 1",
                (task_id,),
            ).fetchone()
            if not row:
                conn.commit()
                return None

            if task_group and (row["task_group"] or "") != task_group:
                conn.commit()
                return None

            runnable, _reason = self._is_task_row_runnable(
                row=row,
                conn=conn,
                expected_agent_type=expected_agent_type,
                require_function_identifier=require_function_identifier,
            )
            if not runnable:
                conn.commit()
                return None

            cursor = conn.execute(
                """
                UPDATE tasks
                SET status = ?, claimed_by = ?, lease_expires_at = ?, attempt_count = attempt_count + 1
                WHERE id = ? AND status = ?
                """,
                (
                    TaskStatus.IN_PROGRESS.value,
                    claimant_id,
                    lease_expires,
                    task_id,
                    TaskStatus.PENDING.value,
                ),
            )
            if (cursor.rowcount or 0) != 1:
                conn.commit()
                return None

            claimed_row = conn.execute(
                "SELECT * FROM tasks WHERE id = ? LIMIT 1",
                (task_id,),
            ).fetchone()
            conn.commit()

        if not claimed_row:
            return None
        self._save_tasks_snapshot()
        return self._row_to_task(claimed_row)

    def claim_tasks_by_ids(
        self,
        task_ids: List[str],
        claimant: str = "",
        lease_seconds: int = 900,
        task_group: Optional[str] = None,
        expected_agent_type: Optional[str] = None,
        require_function_identifier: bool = False,
        atomic: bool = True,
    ) -> List[Task]:
        """
        原子认领一组指定任务 ID。

        Args:
            task_ids: 待认领任务 ID 列表
            atomic: True 时任一任务不满足条件则整体失败（不认领任何任务）
        """
        ordered_ids: List[str] = []
        seen: set[str] = set()
        for task_id in task_ids or []:
            normalized = str(task_id or "").strip()
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            ordered_ids.append(normalized)
        if not ordered_ids:
            return []

        self.requeue_expired_leases()
        lease_expires = int(time.time()) + max(30, int(lease_seconds))
        claimant_id = (claimant or "default_claimant").strip()

        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")

            placeholders = ",".join("?" for _ in ordered_ids)
            rows = conn.execute(
                f"SELECT * FROM tasks WHERE id IN ({placeholders})",
                tuple(ordered_ids),
            ).fetchall()
            row_map = {row["id"]: row for row in rows}

            missing_ids = [tid for tid in ordered_ids if tid not in row_map]
            if missing_ids and atomic:
                conn.rollback()
                return []

            runnable_ids: List[str] = []
            for task_id in ordered_ids:
                row = row_map.get(task_id)
                if not row:
                    continue
                if task_group and (row["task_group"] or "") != task_group:
                    if atomic:
                        conn.rollback()
                        return []
                    continue
                runnable, _reason = self._is_task_row_runnable(
                    row=row,
                    conn=conn,
                    expected_agent_type=expected_agent_type,
                    require_function_identifier=require_function_identifier,
                )
                if not runnable:
                    if atomic:
                        conn.rollback()
                        return []
                    continue
                runnable_ids.append(task_id)

            if not runnable_ids:
                conn.commit()
                return []

            claimed_ids: List[str] = []
            for task_id in runnable_ids:
                cursor = conn.execute(
                    """
                    UPDATE tasks
                    SET status = ?, claimed_by = ?, lease_expires_at = ?, attempt_count = attempt_count + 1
                    WHERE id = ? AND status = ?
                    """,
                    (
                        TaskStatus.IN_PROGRESS.value,
                        claimant_id,
                        lease_expires,
                        task_id,
                        TaskStatus.PENDING.value,
                    ),
                )
                if (cursor.rowcount or 0) == 1:
                    claimed_ids.append(task_id)
                elif atomic:
                    conn.rollback()
                    return []

            if not claimed_ids:
                conn.commit()
                return []

            claimed_placeholders = ",".join("?" for _ in claimed_ids)
            claimed_rows = conn.execute(
                f"SELECT * FROM tasks WHERE id IN ({claimed_placeholders})",
                tuple(claimed_ids),
            ).fetchall()
            conn.commit()

        self._save_tasks_snapshot()
        ordered_claimed_rows = sorted(
            claimed_rows,
            key=lambda row: ordered_ids.index(row["id"]),
        )
        return [self._row_to_task(row) for row in ordered_claimed_rows]

    def list_tasks_with_runnable(
        self,
        task_group: Optional[str] = None,
        agent_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        返回任务列表及其可执行性判断。
        """
        self.requeue_expired_leases()
        with self._connect() as conn:
            if task_group:
                rows = conn.execute(
                    """
                    SELECT * FROM tasks
                    WHERE task_group = ?
                    ORDER BY CAST(SUBSTR(id, 6) AS INTEGER) ASC
                    """,
                    (task_group,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM tasks ORDER BY CAST(SUBSTR(id, 6) AS INTEGER) ASC"
                ).fetchall()

            items: List[Dict[str, Any]] = []
            for row in rows:
                runnable, reason = self._is_task_row_runnable(
                    row=row,
                    conn=conn,
                    expected_agent_type=agent_type,
                    require_function_identifier=(agent_type == "vuln_analysis"),
                )
                task_obj = self._row_to_task(row)
                items.append(
                    {
                        "task": task_obj,
                        "runnable": runnable,
                        "reason": reason,
                    }
                )
        return items

    def complete_claimed_task(
        self,
        task_id: str,
        claimant: str,
        success: bool,
        error_message: Optional[str] = None,
    ) -> bool:
        """结束已认领任务（成功/失败）。"""
        new_status = TaskStatus.COMPLETED if success else TaskStatus.FAILED
        completed_at = datetime.now().isoformat()
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            cursor = conn.execute(
                """
                UPDATE tasks
                SET status = ?, completed_at = ?, claimed_by = NULL, lease_expires_at = NULL, error_message = ?
                WHERE id = ? AND claimed_by = ? AND status = ?
                """,
                (
                    new_status.value,
                    completed_at,
                    error_message if not success else None,
                    task_id,
                    claimant,
                    TaskStatus.IN_PROGRESS.value,
                ),
            )
            changed = cursor.rowcount or 0
            conn.commit()
        if changed > 0:
            self._save_tasks_snapshot()
        return changed > 0

    def renew_lease(self, task_id: str, claimant: str, lease_seconds: int = 900) -> bool:
        """续租任务认领。"""
        lease_expires = int(time.time()) + max(30, int(lease_seconds))
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            cursor = conn.execute(
                """
                UPDATE tasks
                SET lease_expires_at = ?
                WHERE id = ? AND claimed_by = ? AND status = ?
                """,
                (lease_expires, task_id, claimant, TaskStatus.IN_PROGRESS.value),
            )
            changed = cursor.rowcount or 0
            conn.commit()
        return changed > 0

    def get_current_task(self, task_group: Optional[str] = None) -> Optional[Task]:
        tasks = self.get_all_tasks(task_group=task_group)
        for task in tasks:
            if task.status == TaskStatus.PENDING:
                return task
        return None

    def update_task_status(
        self,
        task_id: str,
        status: TaskStatus,
        error_message: Optional[str] = None,
    ) -> None:
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            exists = conn.execute("SELECT 1 FROM tasks WHERE id = ? LIMIT 1", (task_id,)).fetchone()
            if not exists:
                conn.rollback()
                raise ValueError(f"Task not found: {task_id}")
            completed_at = datetime.now().isoformat() if status in (TaskStatus.COMPLETED, TaskStatus.FAILED) else None
            conn.execute(
                """
                UPDATE tasks
                SET status = ?, completed_at = ?, error_message = ?, claimed_by = CASE WHEN ? IN (?, ?) THEN NULL ELSE claimed_by END,
                    lease_expires_at = CASE WHEN ? IN (?, ?) THEN NULL ELSE lease_expires_at END
                WHERE id = ?
                """,
                (
                    status.value,
                    completed_at,
                    error_message if status == TaskStatus.FAILED else None,
                    status.value,
                    TaskStatus.COMPLETED.value,
                    TaskStatus.FAILED.value,
                    status.value,
                    TaskStatus.COMPLETED.value,
                    TaskStatus.FAILED.value,
                    task_id,
                ),
            )
            conn.commit()
        self._save_tasks_snapshot()

    def set_task_function_identifier(self, task_id: str, function_identifier: str) -> None:
        normalized = (function_identifier or "").strip()
        if not normalized:
            raise ValueError("function_identifier cannot be empty")
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT * FROM tasks WHERE id = ? LIMIT 1", (task_id,)).fetchone()
            if not row:
                conn.rollback()
                raise ValueError(f"Task not found: {task_id}")

            uid = self._compute_task_uid(
                description=row["description"],
                agent_type=row["agent_type"],
                function_identifier=normalized,
                task_group=row["task_group"],
            )
            dup = conn.execute(
                "SELECT id FROM tasks WHERE task_uid = ? AND id != ? LIMIT 1",
                (uid, task_id),
            ).fetchone()
            if dup:
                conn.rollback()
                raise ValueError(
                    f"function_identifier causes duplicate task_uid with existing task: {dup['id']}"
                )

            conn.execute(
                "UPDATE tasks SET function_identifier = ?, task_uid = ? WHERE id = ?",
                (normalized, uid, task_id),
            )
            conn.commit()
        self._save_tasks_snapshot()

    def set_task_artifact(self, task_id: str, slot: str, artifact_ref: str) -> None:
        """绑定任务 Artifact 槽位（upsert）。"""
        normalized_task_id = (task_id or "").strip()
        normalized_slot = (slot or "").strip()
        normalized_ref = (artifact_ref or "").strip()
        if not normalized_task_id:
            raise ValueError("task_id cannot be empty")
        if not normalized_slot:
            raise ValueError("slot cannot be empty")
        if not normalized_ref:
            raise ValueError("artifact_ref cannot be empty")

        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT 1 FROM tasks WHERE id = ? LIMIT 1",
                (normalized_task_id,),
            ).fetchone()
            if not row:
                conn.rollback()
                raise ValueError(f"Task not found: {normalized_task_id}")
            conn.execute(
                """
                INSERT INTO task_artifacts(task_id, slot, artifact_ref, created_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(task_id, slot) DO UPDATE SET
                    artifact_ref = excluded.artifact_ref,
                    created_at = excluded.created_at
                """,
                (
                    normalized_task_id,
                    normalized_slot,
                    normalized_ref,
                    datetime.now().isoformat(),
                ),
            )
            conn.commit()

    def get_task_artifact(self, task_id: str, slot: str) -> Optional[str]:
        """读取任务指定槽位的 artifact_ref。"""
        normalized_task_id = (task_id or "").strip()
        normalized_slot = (slot or "").strip()
        if not normalized_task_id or not normalized_slot:
            return None
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT artifact_ref
                FROM task_artifacts
                WHERE task_id = ? AND slot = ?
                LIMIT 1
                """,
                (normalized_task_id, normalized_slot),
            ).fetchone()
        if not row:
            return None
        return str(row["artifact_ref"] or "").strip() or None

    def list_task_artifacts(self, task_id: str) -> Dict[str, str]:
        """列出任务全部槽位绑定。"""
        normalized_task_id = (task_id or "").strip()
        if not normalized_task_id:
            return {}
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT slot, artifact_ref
                FROM task_artifacts
                WHERE task_id = ?
                ORDER BY created_at DESC
                """,
                (normalized_task_id,),
            ).fetchall()
        return {
            str(r["slot"]): str(r["artifact_ref"])
            for r in rows
            if (r["slot"] or "") and (r["artifact_ref"] or "")
        }

    def get_all_tasks(self, task_group: Optional[str] = None) -> List[Task]:
        with self._connect() as conn:
            if task_group:
                rows = conn.execute(
                    """
                    SELECT * FROM tasks
                    WHERE task_group = ?
                    ORDER BY CAST(SUBSTR(id, 6) AS INTEGER) ASC
                    """,
                    (task_group,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM tasks ORDER BY CAST(SUBSTR(id, 6) AS INTEGER) ASC"
                ).fetchall()
        return [self._row_to_task(row) for row in rows]

    def is_all_completed(self, task_group: Optional[str] = None) -> bool:
        tasks = self.get_all_tasks(task_group=task_group)
        if not tasks:
            return False
        return all(task.status == TaskStatus.COMPLETED for task in tasks)

    def get_task(self, task_id: str) -> Optional[Task]:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM tasks WHERE id = ? LIMIT 1", (task_id,)).fetchone()
        if not row:
            return None
        return self._row_to_task(row)

    def get_statistics(self, task_group: Optional[str] = None) -> Dict[str, Any]:
        tasks = self.get_all_tasks(task_group=task_group)
        total = len(tasks)
        pending = sum(1 for t in tasks if t.status == TaskStatus.PENDING)
        in_progress = sum(1 for t in tasks if t.status == TaskStatus.IN_PROGRESS)
        completed = sum(1 for t in tasks if t.status == TaskStatus.COMPLETED)
        failed = sum(1 for t in tasks if t.status == TaskStatus.FAILED)
        completion_rate = (completed / total * 100) if total > 0 else 0.0
        return {
            "total": total,
            "pending": pending,
            "in_progress": in_progress,
            "completed": completed,
            "failed": failed,
            "completion_rate": round(completion_rate, 2),
        }

    def _generate_markdown(self) -> str:
        lines = ["# 任务列表", ""]
        for task in self.get_all_tasks():
            lines.append(task.to_metadata_comment())
            lines.append(task.to_markdown_line())
            lines.append("")
        stats = self.get_statistics()
        lines.append("---")
        lines.append("")
        lines.append(f"**总计**: {stats['total']} 个任务")
        lines.append(f"**待执行**: {stats['pending']} 个")
        lines.append(f"**执行中**: {stats['in_progress']} 个")
        lines.append(f"**已完成**: {stats['completed']} 个")
        lines.append(f"**失败**: {stats['failed']} 个")
        lines.append(f"**完成率**: {stats['completion_rate']}%")
        return "\n".join(lines)

    def _save_tasks_snapshot(self) -> None:
        self.tasks_file.parent.mkdir(parents=True, exist_ok=True)
        self.tasks_file.write_text(self._generate_markdown(), encoding="utf-8")


__all__ = [
    "TaskStatus",
    "Task",
    "TaskListManager",
]
