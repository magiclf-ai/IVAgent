#!/usr/bin/env python3
"""
ContextCompressor - LLM 上下文压缩器

当上下文超过阈值时，使用 SummaryService 将历史消息压缩为 Markdown 摘要。
"""

from dataclasses import dataclass
from typing import List, Optional, Dict, Any
import json

from .message_manager import AgentMessage
from .artifact_store import ArtifactReference
from ..summary_service import SummaryService


@dataclass
class ContextCompressionResult:
    summary: str
    store_artifact: bool
    artifact_ref: Optional[ArtifactReference] = None
    reason: str = ""
    raw_tool_args: Optional[Dict[str, Any]] = None


class ContextCompressor:
    """
    LLM 上下文压缩器

    - 输入：历史消息列表
    - 输出：Markdown 摘要 + 是否落盘
    """

    def __init__(
        self,
        summary_service: SummaryService,
    ):
        self.summary_service = summary_service

    async def compress(self, messages: List[AgentMessage]) -> ContextCompressionResult:
        """
        压缩历史消息为 Markdown 摘要。

        Args:
            messages: 需要压缩的历史消息列表

        Returns:
            ContextCompressionResult
        """
        if not messages:
            return ContextCompressionResult(summary="", store_artifact=False)

        raw_context = self._render_messages(messages)
        if not raw_context.strip():
            return ContextCompressionResult(summary="", store_artifact=False)

        try:
            payload = await self.summary_service.summarize_context_compression(
                raw_context=raw_context,
            )
        except Exception:
            return ContextCompressionResult(summary="", store_artifact=False)

        summary = (payload.summary or "").strip()
        store_artifact = bool(payload.store_artifact)
        reason = (payload.reason or "").strip()
        raw_tool_args = payload.raw_tool_args

        if not summary:
            return ContextCompressionResult(summary="", store_artifact=False)

        return ContextCompressionResult(
            summary=summary,
            store_artifact=store_artifact,
            artifact_ref=None,
            reason=reason,
            raw_tool_args=raw_tool_args,
        )

    def _render_messages(self, messages: List[AgentMessage]) -> str:
        """
        将消息列表渲染为可压缩的文本
        """
        rendered = []
        for idx, msg in enumerate(messages, 1):
            header = f"[{idx}] role={msg.role}"
            meta = {}
            if msg.metadata.get("tool_name"):
                meta["tool_name"] = msg.metadata.get("tool_name")
            if msg.metadata.get("tool_call_id"):
                meta["tool_call_id"] = msg.metadata.get("tool_call_id")
            if msg.metadata.get("tool_calls"):
                meta["tool_calls"] = msg.metadata.get("tool_calls")
            meta_text = f"\nmeta={json.dumps(meta, ensure_ascii=False)}" if meta else ""
            rendered.append(f"{header}{meta_text}\n{msg.content_display}")
        return "\n\n".join(rendered)
