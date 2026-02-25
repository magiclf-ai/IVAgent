#!/usr/bin/env python3
"""
MessageManager - 结构化消息管理与引用投影

负责将大输出落盘并生成引用，维护消息投影与上下文摘要。
"""

from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List, Callable, Awaitable
import time
import uuid

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
        summary_provider: Optional[Callable[[str, Dict[str, Any]], Awaitable[str]]] = None,
        max_inline_chars: int = 4000,
        max_summary_chars: int = 400,
    ):
        self.artifact_store = artifact_store
        self.summary_provider = summary_provider
        self.max_inline_chars = max_inline_chars
        self.max_summary_chars = max_summary_chars
        self._messages: List[AgentMessage] = []

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
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AgentMessage:
        meta = metadata or {}
        if tool_name:
            meta["tool_name"] = tool_name
        if tool_call_id:
            meta["tool_call_id"] = tool_call_id
        return await self._add_message("tool", content, meta)

    def get_recent_messages(self, limit: int) -> List[AgentMessage]:
        if limit <= 0:
            return []
        return self._messages[-limit:]

    def get_all_messages(self) -> List[AgentMessage]:
        return list(self._messages)

    async def _add_message(
        self,
        role: str,
        content: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AgentMessage:
        content = content or ""
        meta = metadata or {}
        created_at = time.time()
        message_id = uuid.uuid4().hex

        if len(content) > self.max_inline_chars:
            summary = await self._summarize_content(content, meta)
            artifact = self.artifact_store.store(
                content=content,
                summary=summary,
                metadata=meta,
            )
            display = self._format_reference_display(summary, artifact.artifact_id, role)
            msg = AgentMessage(
                message_id=message_id,
                role=role,
                content_display=display,
                content_full=None,
                created_at=created_at,
                artifacts=[artifact],
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

    async def _summarize_content(self, content: str, metadata: Dict[str, Any]) -> str:
        if self.summary_provider:
            try:
                summary = await self.summary_provider(content, metadata)
                if summary:
                    return summary.strip()
            except Exception:
                pass
        return self._fallback_summary(content)

    def _fallback_summary(self, content: str) -> str:
        """
        智能摘要生成（不使用 LLM）
        
        策略：
        1. 提取 Markdown 标题
        2. 提取包含关键词的行
        3. 保留结构化信息
        """
        lines = content.split('\n')
        summary_lines = []
        
        # 关键词列表
        keywords = ['函数ID', '函数标识符', 'identifier', '漏洞', '发现', 'vulnerability', '##', '###']
        
        # 提取关键行
        for line in lines[:30]:  # 只看前30行
            line_stripped = line.strip()
            if not line_stripped:
                continue
            
            # 保留标题
            if line_stripped.startswith('#'):
                summary_lines.append(line_stripped)
            # 保留包含关键词的行
            elif any(kw in line_stripped for kw in keywords):
                summary_lines.append(line_stripped)
            
            # 限制摘要行数
            if len(summary_lines) >= 8:
                break
        
        # 如果没有提取到关键信息，使用前几行
        if not summary_lines:
            summary_lines = [l.strip() for l in lines[:5] if l.strip()]
        
        summary = '\n'.join(summary_lines)
        
        # 限制总长度
        if len(summary) > self.max_summary_chars:
            summary = summary[:self.max_summary_chars] + "..."
        
        return summary

    def _format_reference_display(self, summary: str, artifact_id: str, role: str) -> str:
        prefix = "【已归档输出】" if role == "tool" else "【已归档消息】"
        return f"{prefix}\n{summary}\n[ARTIFACT_REF:{artifact_id}]"
