#!/usr/bin/env python3
"""
ArtifactStore - 工具/消息大输出落盘存储

提供简单的落盘存储与读取能力，返回可引用的 ArtifactReference。
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Dict, Any, List
import json
import time
import uuid


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
    ArtifactStore - 文件落盘存储

    每个 Artifact 使用独立目录保存 content.txt 与 metadata.json。
    """

    def __init__(self, base_dir: Path):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def store(
        self,
        content: str,
        summary: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ArtifactReference:
        """
        存储内容并返回引用

        Args:
            content: 待存储内容
            summary: 内容摘要
            metadata: 元数据
        """
        artifact_id = uuid.uuid4().hex
        artifact_dir = self.base_dir / artifact_id
        artifact_dir.mkdir(parents=True, exist_ok=True)

        content_path = artifact_dir / "content.txt"
        metadata_path = artifact_dir / "metadata.json"

        content_path.write_text(content, encoding="utf-8", errors="ignore")

        payload = {
            "artifact_id": artifact_id,
            "created_at": time.time(),
            "size": len(content),
            "summary": summary,
            "metadata": metadata or {},
        }
        metadata_path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

        return ArtifactReference(
            artifact_id=artifact_id,
            content_path=str(content_path),
            metadata_path=str(metadata_path),
            size=payload["size"],
            created_at=payload["created_at"],
            summary=summary,
            metadata=payload["metadata"],
        )

    def read(
        self,
        artifact_id: str,
        offset: int = 0,
        limit: Optional[int] = None,
    ) -> str:
        """
        读取已存储的内容

        Args:
            artifact_id: Artifact ID
            offset: 起始行（从 0 开始）
            limit: 返回行数限制，None 表示全部
        """
        content_path = self._resolve_content_path(artifact_id)
        if not content_path.exists():
            return f"[错误] Artifact 不存在: {artifact_id}"

        lines = content_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        start_line = max(0, offset)
        end_line = len(lines) if limit is None else min(len(lines), start_line + limit)
        if start_line >= len(lines):
            return f"[错误] 起始行 {offset} 超出范围（共 {len(lines)} 行）"
        return "\n".join(lines[start_line:end_line])

    def read_metadata(self, artifact_id: str) -> Dict[str, Any]:
        """读取 Artifact 元数据"""
        metadata_path = self._resolve_metadata_path(artifact_id)
        if not metadata_path.exists():
            return {"error": f"Artifact metadata not found: {artifact_id}"}
        return json.loads(metadata_path.read_text(encoding="utf-8", errors="ignore"))

    def exists(self, artifact_id: str) -> bool:
        """检查 Artifact 是否存在"""
        return self._resolve_content_path(artifact_id).exists()

    def list_artifacts(self) -> List[str]:
        """列出所有 Artifact ID"""
        if not self.base_dir.exists():
            return []
        return [p.name for p in self.base_dir.iterdir() if p.is_dir()]

    def _resolve_content_path(self, artifact_id: str) -> Path:
        return self.base_dir / artifact_id / "content.txt"

    def _resolve_metadata_path(self, artifact_id: str) -> Path:
        return self.base_dir / artifact_id / "metadata.json"
