#!/usr/bin/env python3
"""
ArtifactStore - 统一 Artifact Ledger

统一管理消息、上下文、任务输出等文本内容的落盘与索引。
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Dict, Any, List
import json
import sqlite3
import time
import uuid
import re


@dataclass
class ArtifactReference:
    """Artifact 引用信息"""

    artifact_id: str
    content_path: str
    metadata_path: str
    size: int
    created_at: float
    summary: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """转换为可序列化字典"""
        return {
            "artifact_id": self.artifact_id,
            "content_path": self.content_path,
            "metadata_path": self.metadata_path,
            "size": self.size,
            "created_at": self.created_at,
            "summary": self.summary,
            "metadata": self.metadata,
        }


class ArtifactStore:
    """
    统一 Artifact 存储。

    存储结构：
    - `{base_dir}/objects/<artifact_id>.md`：正文内容
    - `{base_dir}/index.db`：索引元数据
    """

    def __init__(self, base_dir: Path):
        self.base_dir = Path(base_dir)
        self.objects_dir = self.base_dir / "objects"
        self.index_db = self.base_dir / "index.db"
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.objects_dir.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.index_db), timeout=10, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=10000")
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS artifacts (
                    artifact_id TEXT PRIMARY KEY,
                    created_at REAL NOT NULL,
                    kind TEXT NOT NULL,
                    content_path TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    summary TEXT,
                    session_id TEXT,
                    workflow_id TEXT,
                    task_id TEXT,
                    producer TEXT,
                    supersedes_ref TEXT,
                    tags_json TEXT NOT NULL,
                    metadata_json TEXT NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_artifacts_kind_ct ON artifacts(kind, created_at DESC)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_artifacts_task_ct ON artifacts(task_id, created_at DESC)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_artifacts_workflow_ct ON artifacts(workflow_id, created_at DESC)"
            )

    def _normalize_ref(self, artifact_ref: str) -> str:
        value = str(artifact_ref or "").strip()
        if not value:
            return ""
        match = re.match(r"^\[ARTIFACT_REF:([A-Za-z0-9_\-]+)\]$", value)
        if match:
            return match.group(1)
        return value

    def put_text(
        self,
        content: str,
        *,
        kind: str,
        summary: str = "",
        session_id: str = "",
        workflow_id: str = "",
        task_id: str = "",
        producer: str = "",
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        supersedes_ref: str = "",
    ) -> ArtifactReference:
        """
        写入文本并创建索引条目。

        Args:
            content: 正文内容
            kind: 内容类型（task_output / analysis_context / task_context / tool_output 等）
            summary: 可选摘要
            session_id: 会话 ID
            workflow_id: workflow / task_group 标识
            task_id: 任务 ID
            producer: 生产者标识（组件/agent）
            tags: 标签数组
            metadata: 额外元数据
            supersedes_ref: 被替代的旧 artifact_ref
        """
        normalized_kind = (kind or "").strip() or "generic"
        created_at = time.time()
        artifact_id = f"ar_{uuid.uuid4().hex}"
        object_path = self.objects_dir / f"{artifact_id}.md"
        text = content or ""
        object_path.write_text(text, encoding="utf-8", errors="ignore")

        payload = metadata or {}
        tags_json = json.dumps(tags or [], ensure_ascii=False)
        metadata_json = json.dumps(payload, ensure_ascii=False)

        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO artifacts (
                    artifact_id, created_at, kind, content_path, size, summary,
                    session_id, workflow_id, task_id, producer, supersedes_ref, tags_json, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    artifact_id,
                    created_at,
                    normalized_kind,
                    str(object_path),
                    len(text.encode("utf-8")),
                    summary or "",
                    (session_id or "").strip() or None,
                    (workflow_id or "").strip() or None,
                    (task_id or "").strip() or None,
                    (producer or "").strip() or None,
                    (supersedes_ref or "").strip() or None,
                    tags_json,
                    metadata_json,
                ),
            )
            conn.commit()

        return ArtifactReference(
            artifact_id=artifact_id,
            content_path=str(object_path),
            metadata_path=f"index:{artifact_id}",
            size=len(text),
            created_at=created_at,
            summary=summary or "",
            metadata=payload,
        )

    def store(
        self,
        content: str,
        summary: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ArtifactReference:
        """
        兼容入口：内部转发到 `put_text`。
        """
        meta = metadata or {}
        return self.put_text(
            content=content,
            kind=str(meta.get("kind") or "generic"),
            summary=summary,
            session_id=str(meta.get("session_id") or ""),
            workflow_id=str(meta.get("workflow_id") or ""),
            task_id=str(meta.get("task_id") or ""),
            producer=str(meta.get("producer") or ""),
            tags=meta.get("tags") if isinstance(meta.get("tags"), list) else [],
            metadata=meta,
            supersedes_ref=str(meta.get("supersedes_ref") or ""),
        )

    def _read_row(self, artifact_ref: str) -> Optional[sqlite3.Row]:
        normalized = self._normalize_ref(artifact_ref)
        if not normalized:
            return None
        with self._connect() as conn:
            return conn.execute(
                "SELECT * FROM artifacts WHERE artifact_id = ? LIMIT 1",
                (normalized,),
            ).fetchone()

    def read(
        self,
        artifact_id: str,
        offset: int = 0,
        limit: Optional[int] = None,
    ) -> str:
        """
        读取已存储内容。

        Args:
            artifact_id: artifact_ref 或 `[ARTIFACT_REF:artifact_ref]`
            offset: 起始行（从 0 开始）
            limit: 返回行数限制，None 表示全部
        """
        row = self._read_row(artifact_id)
        if not row:
            return f"[错误] Artifact 不存在: {artifact_id}"

        content_path = Path(row["content_path"])
        if not content_path.exists():
            return f"[错误] Artifact 文件不存在: {row['artifact_id']}"

        lines = content_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        start_line = max(0, offset)
        end_line = len(lines) if limit is None else min(len(lines), start_line + limit)
        if start_line >= len(lines):
            return f"[错误] 起始行 {offset} 超出范围（共 {len(lines)} 行）"
        return "\n".join(lines[start_line:end_line])

    def read_metadata(self, artifact_id: str) -> Dict[str, Any]:
        """读取 Artifact 元数据。"""
        row = self._read_row(artifact_id)
        if not row:
            return {"error": f"Artifact metadata not found: {artifact_id}"}
        metadata = json.loads(row["metadata_json"] or "{}")
        tags = json.loads(row["tags_json"] or "[]")
        return {
            "artifact_id": row["artifact_id"],
            "created_at": row["created_at"],
            "kind": row["kind"],
            "content_path": row["content_path"],
            "size": row["size"],
            "summary": row["summary"] or "",
            "session_id": row["session_id"] or "",
            "workflow_id": row["workflow_id"] or "",
            "task_id": row["task_id"] or "",
            "producer": row["producer"] or "",
            "supersedes_ref": row["supersedes_ref"] or "",
            "tags": tags,
            "metadata": metadata,
        }

    def exists(self, artifact_id: str) -> bool:
        """检查 Artifact 是否存在。"""
        row = self._read_row(artifact_id)
        if not row:
            return False
        return Path(row["content_path"]).exists()

    def list_artifacts(
        self,
        *,
        kind: str = "",
        task_id: str = "",
        workflow_id: str = "",
        limit: int = 200,
    ) -> List[str]:
        """
        列出 Artifact 引用。
        """
        query = "SELECT artifact_id FROM artifacts"
        conds: List[str] = []
        params: List[Any] = []
        if kind:
            conds.append("kind = ?")
            params.append(kind)
        if task_id:
            conds.append("task_id = ?")
            params.append(task_id)
        if workflow_id:
            conds.append("workflow_id = ?")
            params.append(workflow_id)
        if conds:
            query += " WHERE " + " AND ".join(conds)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(max(1, int(limit)))
        with self._connect() as conn:
            rows = conn.execute(query, tuple(params)).fetchall()
        return [str(r["artifact_id"]) for r in rows]

    def query_artifacts(
        self,
        *,
        kind: str = "",
        task_id: str = "",
        workflow_id: str = "",
        limit: int = 200,
    ) -> List[Dict[str, Any]]:
        """
        查询 Artifact 详情。
        """
        refs = self.list_artifacts(
            kind=kind,
            task_id=task_id,
            workflow_id=workflow_id,
            limit=limit,
        )
        return [self.read_metadata(ref) for ref in refs]
