#!/usr/bin/env python3
"""
MessageManager - 结构化消息管理与引用投影

负责将大输出落盘并生成引用，维护消息投影与上下文摘要。
"""

from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
import time

from .artifact_store import ArtifactStore, ArtifactReference


@dataclass
class AgentMessage:
    """结构化消息"""
    message_id: str
    role: str
    content_display: str
    content_full: Optional[str]
    created_at: float
    artifacts: List[ArtifactReference] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class MessageManager:
    """
    消息管理器

    - 大文本落盘存储并生成引用
    - 维护消息投影内容用于上下文组装
    """

    def __init__(
        self,
        artifact_store: ArtifactStore,
        max_inline_chars: int = 4000,
    ):
        self.artifact_store = artifact_store
        self.max_inline_chars = max_inline_chars
        self._messages: List[AgentMessage] = []
        self._message_seq: int = 0
        self._pending_projection_remove_message_ids: List[str] = []
        self._pending_projection_fold_message_ids: List[str] = []
        self._pending_projection_reason: str = ""

    async def add_system_message(self, content: str, metadata: Optional[Dict[str, Any]] = None) -> AgentMessage:
        return await self._add_message("system", content, metadata)

    async def add_user_message(self, content: str, metadata: Optional[Dict[str, Any]] = None) -> AgentMessage:
        return await self._add_message("user", content, metadata)

    async def add_ai_message(
        self,
        content: str,
        tool_calls: Optional[List[Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AgentMessage:
        meta = metadata or {}
        if tool_calls:
            meta["tool_calls"] = tool_calls
        return await self._add_message("assistant", content, meta)

    async def add_tool_message(
        self,
        content: str,
        tool_name: Optional[str] = None,
        tool_call_id: Optional[str] = None,
        summary: Optional[str] = None,
        force_inline: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AgentMessage:
        """
        添加工具消息。

        Args:
            content: 工具返回的正文内容
            tool_name: 工具名称
            tool_call_id: 工具调用 ID
            summary: 工具返回的摘要（Markdown 纯文本，可选）
            force_inline: 是否强制内联显示正文
            metadata: 额外元数据
        """
        meta = metadata or {}
        if tool_name:
            meta["tool_name"] = tool_name
        if tool_call_id:
            meta["tool_call_id"] = tool_call_id
        if summary:
            meta["summary"] = summary
        return await self._add_message(
            "tool",
            content,
            meta,
            force_inline=force_inline,
            summary=summary,
        )

    def get_recent_messages(self, limit: int) -> List[AgentMessage]:
        if limit <= 0:
            return []
        return self._messages[-limit:]

    def get_all_messages(self) -> List[AgentMessage]:
        return list(self._messages)

    def replace_messages(
        self,
        start_index: int,
        end_index: int,
        new_message: AgentMessage,
    ) -> None:
        """
        用新消息替换指定范围的历史消息。

        Args:
            start_index: 起始索引（包含）
            end_index: 结束索引（不包含）
            new_message: 替换后的消息
        """
        total = len(self._messages)
        if start_index < 0:
            start_index = 0
        if end_index > total:
            end_index = total
        if start_index >= end_index:
            return

        self._messages = (
            self._messages[:start_index]
            + [new_message]
            + self._messages[end_index:]
        )

    def remove_messages_by_id(self, message_ids: List[str]) -> int:
        """
        按 message_id 移除历史消息。

        Args:
            message_ids: 需要移除的 message_id 列表

        Returns:
            实际移除的消息数量
        """
        if not message_ids:
            return 0
        remove_set = set(message_ids)
        before = len(self._messages)
        self._messages = [msg for msg in self._messages if msg.message_id not in remove_set]
        return before - len(self._messages)

    def mark_compression_projection(
        self,
        remove_message_ids: Optional[List[str]] = None,
        fold_message_ids: Optional[List[str]] = None,
        reason: str = "",
    ) -> Dict[str, Any]:
        """
        标记下一轮上下文压缩前要应用的消息级裁切清单（删除/折叠）。

        Returns:
            {
              "accepted_remove_message_ids": [...],
              "accepted_fold_message_ids": [...],
              "reason": "...",
            }
        """
        def _normalize_ids(values: Any) -> List[str]:
            if isinstance(values, list):
                raw = values
            elif values is None:
                raw = []
            else:
                raw = [values]
            accepted_ids: List[str] = []
            for item in raw:
                value = str(item or "").strip()
                if value:
                    accepted_ids.append(value)
            return list(dict.fromkeys(accepted_ids))

        accepted_remove = _normalize_ids(remove_message_ids)
        accepted_fold = _normalize_ids(fold_message_ids)
        if accepted_remove and accepted_fold:
            remove_set = set(accepted_remove)
            accepted_fold = [mid for mid in accepted_fold if mid not in remove_set]

        self._pending_projection_remove_message_ids = accepted_remove
        self._pending_projection_fold_message_ids = accepted_fold
        self._pending_projection_reason = str(reason or "").strip()
        return {
            "accepted_remove_message_ids": list(accepted_remove),
            "accepted_fold_message_ids": list(accepted_fold),
            "reason": self._pending_projection_reason,
        }

    def pop_compression_projection(self) -> Dict[str, Any]:
        """
        读取并清空待应用的压缩投影裁切清单。
        """
        payload = {
            "remove_message_ids": list(self._pending_projection_remove_message_ids),
            "fold_message_ids": list(self._pending_projection_fold_message_ids),
            "reason": self._pending_projection_reason,
        }
        self._pending_projection_remove_message_ids = []
        self._pending_projection_fold_message_ids = []
        self._pending_projection_reason = ""
        return payload

    def has_pending_compression_projection(self) -> bool:
        """是否存在待应用的压缩投影裁切清单。"""
        return bool(
            self._pending_projection_remove_message_ids
            or self._pending_projection_fold_message_ids
        )

    def build_compressed_message(
        self,
        summary: str,
        store_artifact: bool,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AgentMessage:
        """
        构建压缩后的系统消息（不直接写入列表）。

        Args:
            summary: Markdown 摘要
            store_artifact: 是否强制落盘
            metadata: 元数据
        """
        meta = metadata or {}
        meta["compressed"] = True
        created_at = time.time()
        message_id = self._next_message_id()

        if store_artifact:
            artifact = self.artifact_store.store(
                content=summary,
                summary=summary,
                metadata=meta,
            )
            display = self._format_reference_display(summary, artifact.artifact_id, "system")
            return AgentMessage(
                message_id=message_id,
                role="system",
                content_display=display,
                content_full=None,
                created_at=created_at,
                artifacts=[artifact],
                metadata=meta,
            )

        return AgentMessage(
            message_id=message_id,
            role="system",
            content_display=summary,
            content_full=summary,
            created_at=created_at,
            artifacts=[],
            metadata=meta,
        )

    async def _add_message(
        self,
        role: str,
        content: str,
        metadata: Optional[Dict[str, Any]] = None,
        force_inline: bool = False,
        summary: Optional[str] = None,
    ) -> AgentMessage:
        content = content or ""
        meta = metadata or {}
        created_at = time.time()
        message_id = self._next_message_id()

        if role != "tool":
            msg = AgentMessage(
                message_id=message_id,
                role=role,
                content_display=content,
                content_full=content,
                created_at=created_at,
                artifacts=[],
                metadata=meta,
            )
            self._messages.append(msg)
            return msg

        summary_text = (summary or meta.get("summary") or "").strip()
        if summary_text:
            artifact = self.artifact_store.store(
                content=content,
                summary=summary_text,
                metadata=meta,
            )
            # 默认保留正文到 message；摘要仅作为归档元数据供压缩/检索使用。
            meta = dict(meta)
            meta["artifact_id"] = artifact.artifact_id
            msg = AgentMessage(
                message_id=message_id,
                role=role,
                content_display=content,
                content_full=content,
                created_at=created_at,
                artifacts=[artifact],
                metadata=meta,
            )
            self._messages.append(msg)
            return msg

        if force_inline:
            msg = AgentMessage(
                message_id=message_id,
                role=role,
                content_display=content,
                content_full=content,
                created_at=created_at,
                artifacts=[],
                metadata=meta,
            )
        else:
            msg = AgentMessage(
                message_id=message_id,
                role=role,
                content_display=content,
                content_full=content,
                created_at=created_at,
                artifacts=[],
                metadata=meta,
            )

        self._messages.append(msg)
        return msg

    def _next_message_id(self) -> str:
        self._message_seq += 1
        return f"Message_{self._message_seq:06d}"

    def _format_reference_display(self, summary: str, artifact_id: str, role: str) -> str:
        prefix = "【已归档输出】" if role == "tool" else "【已归档消息】"
        return f"{prefix}\n{summary}\n[ARTIFACT_REF:{artifact_id}]"
