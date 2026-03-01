#!/usr/bin/env python3
"""
ContextCompressor - LLM 上下文压缩器

职责单一：
- 接收历史消息
- 生成高保真压缩摘要
- 附加 Tool Call 去重记忆块

说明：
- 压缩前推理应在“原始 Agent 对话”内完成（例如 CodeExplorerAgent），
  本压缩器不再额外引入侧路 selector/reasoner。
"""

from dataclasses import dataclass, field
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
    tool_memory_block: str = ""
    semantic_distillation_block: str = ""
    llm_cutting_block: str = ""
    dropped_message_ids: List[str] = field(default_factory=list)
    fold_message_ids: List[str] = field(default_factory=list)
    pre_reasoning_raw_tool_args: Optional[Dict[str, Any]] = None


class ContextCompressor:
    """
    LLM 上下文压缩器

    - 输入：历史消息列表
    - 输出：Markdown 摘要 + 是否落盘
    """

    def __init__(
        self,
        summary_service: SummaryService,
        compression_profile: str = "general",
        consumer_agent: str = "unknown",
        compression_purpose: str = "",
        emit_tool_memory_block: bool = True,
    ):
        self.summary_service = summary_service
        self.compression_profile = (compression_profile or "general").strip().lower()
        self.consumer_agent = (consumer_agent or "unknown").strip()
        self.compression_purpose = (compression_purpose or "").strip()
        self.emit_tool_memory_block = bool(emit_tool_memory_block)
        self._tool_memory_max_entries = 50
        self._tool_memory_max_text_chars = 240

    async def compress(
        self,
        messages: List[AgentMessage],
        anchors: Optional[Dict[str, str]] = None,
        compression_profile: Optional[str] = None,
        consumer_agent: Optional[str] = None,
        purpose: Optional[str] = None,
    ) -> ContextCompressionResult:
        """
        压缩历史消息为 Markdown 摘要。
        """
        if not messages:
            return ContextCompressionResult(summary="", store_artifact=False)

        effective_profile = (compression_profile or self.compression_profile or "general").strip().lower()
        effective_consumer = (consumer_agent or self.consumer_agent or "unknown").strip()
        effective_purpose = (purpose or self.compression_purpose or "").strip()

        raw_context = self._render_messages(messages)
        if not raw_context.strip():
            return ContextCompressionResult(summary="", store_artifact=False)

        try:
            payload = await self.summary_service.summarize_context_compression(
                raw_context=raw_context,
                anchors=anchors,
                compression_profile=effective_profile,
                consumer_agent=effective_consumer,
                purpose=effective_purpose,
            )
        except Exception:
            return ContextCompressionResult(summary="", store_artifact=False)

        generic_summary = (payload.summary or "").strip()
        if not generic_summary:
            return ContextCompressionResult(summary="", store_artifact=False)

        in_agent_reasoning_block, in_agent_cutting_block = self._extract_precompression_blocks(messages)
        merged_summary = self._merge_summary_blocks(
            in_agent_reasoning_block=in_agent_reasoning_block,
            generic_summary=generic_summary,
            in_agent_cutting_block=in_agent_cutting_block,
        )
        tool_memory_block = ""
        if self.emit_tool_memory_block and self._should_emit_tool_memory_block(merged_summary):
            tool_memory_block = self._build_tool_memory_block(messages)

        return ContextCompressionResult(
            summary=merged_summary,
            store_artifact=bool(payload.store_artifact),
            artifact_ref=None,
            reason=(payload.reason or "").strip(),
            raw_tool_args=payload.raw_tool_args,
            tool_memory_block=tool_memory_block,
            semantic_distillation_block=in_agent_reasoning_block,
            llm_cutting_block=in_agent_cutting_block,
        )

    def _render_messages(self, messages: List[AgentMessage]) -> str:
        """
        将消息列表渲染为可压缩文本。
        """
        rendered: List[str] = []
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
            content = self._project_message_content(msg)
            rendered.append(f"{header}{meta_text}\n{content}")
        return "\n\n".join(rendered)

    def _project_message_content(self, msg: AgentMessage) -> str:
        if msg.role != "tool":
            return msg.content_display or ""
        summary = str(msg.metadata.get("summary") or "").strip()
        if summary:
            return f"【工具输出摘要】\n{summary}"
        return msg.content_display or ""

    def _extract_precompression_blocks(self, messages: List[AgentMessage]) -> tuple[str, str]:
        """
        从原始 Agent 对话中提取“压缩前推理块”与“LLM 裁切块”。
        """
        reasoning = ""
        cutting = ""
        for msg in messages:
            if msg.role != "assistant":
                continue
            text = str(msg.content_display or "").strip()
            if not text:
                continue
            if "## 与当前分析目标匹配的语义理解蒸馏" in text:
                reasoning = text
            if "## LLM 驱动裁切上下文" in text:
                cutting = text
        return reasoning, cutting

    def _merge_summary_blocks(
        self,
        in_agent_reasoning_block: str,
        generic_summary: str,
        in_agent_cutting_block: str,
    ) -> str:
        """
        合并：
        - 原始 Agent 压缩前推理（若存在）
        - 通用压缩摘要
        - 原始 Agent 裁切块（若存在）
        """
        reasoning = (in_agent_reasoning_block or "").strip()
        generic = (generic_summary or "").strip()
        cutting = (in_agent_cutting_block or "").strip()

        if not reasoning and not cutting:
            return generic

        # 若原始推理块已包含标准章节，优先原样保留，避免重复嵌套标题。
        if "## 与当前分析目标匹配的语义理解蒸馏" in reasoning:
            if "## LLM 驱动裁切上下文" in reasoning:
                return f"{reasoning}\n\n## 通用蒸馏\n{generic or '无'}".strip()
            return (
                f"{reasoning}\n\n"
                f"## 通用蒸馏\n{generic or '无'}\n\n"
                f"## LLM 驱动裁切上下文\n{cutting or '无'}"
            ).strip()

        lines = [
            "## 与当前分析目标匹配的语义理解蒸馏",
            reasoning or "无",
            "",
            "## 通用蒸馏",
            generic or "无",
            "",
            "## LLM 驱动裁切上下文",
            cutting or "无",
        ]
        return "\n".join(lines).strip()

    def _build_tool_memory_block(self, messages: List[AgentMessage]) -> str:
        """
        生成“已执行 Tool Call 记忆块”，用于压缩后提示 LLM 避免同参重复调用。
        """
        if not messages:
            return ""

        tool_returns: Dict[str, AgentMessage] = {}
        for msg in messages:
            if msg.role != "tool":
                continue
            call_id = str(msg.metadata.get("tool_call_id") or "").strip()
            if call_id:
                tool_returns[call_id] = msg

        entries_by_key: Dict[str, Dict[str, Any]] = {}
        seq = 0
        for msg in messages:
            if msg.role != "assistant":
                continue
            tool_calls = msg.metadata.get("tool_calls")
            if not isinstance(tool_calls, list) or not tool_calls:
                continue
            for tc in tool_calls:
                if not isinstance(tc, dict):
                    continue
                tool_name = str(tc.get("name") or "").strip()
                if not tool_name or tool_name in {
                    "finish_exploration",
                    "mark_compression_projection",
                }:
                    continue
                args = tc.get("args", {})
                call_id = str(tc.get("id") or "").strip()
                if not call_id:
                    continue
                tool_msg = tool_returns.get(call_id)
                if not tool_msg:
                    continue

                args_text = self._canonicalize_tool_args(args)
                dedup_key = f"{tool_name}::{args_text}"
                return_summary = self._summarize_tool_return(tool_msg, tool_name)

                seq += 1
                entries_by_key[dedup_key] = {
                    "seq": seq,
                    "tool_name": tool_name,
                    "args_text": args_text,
                    "tool_call_id": call_id,
                    "dedup_key": dedup_key,
                    "return_summary": return_summary,
                }

        if not entries_by_key:
            return ""

        entries = sorted(entries_by_key.values(), key=lambda x: x["seq"], reverse=True)
        entries = entries[: self._tool_memory_max_entries]
        entries.reverse()

        lines: List[str] = [
            "## 已执行 Tool Call 与返回摘要（防重复）",
            "- 约束: 下列 `tool_name + args` 调用已执行且已返回结果；除非目标变化或证据不足，禁止重复执行同参调用。",
            f"- 记录数: {len(entries)}",
            "",
            "| tool_call_id | tool_name | args | 返回摘要 |",
            "|-------------|-----------|------|---------|",
        ]
        for entry in entries:
            tool_call_id = self._escape_markdown_cell(str(entry.get("tool_call_id") or ""))
            tool_name = self._escape_markdown_cell(str(entry.get("tool_name") or ""))
            args_text = self._escape_markdown_cell(
                self._truncate_text(str(entry.get("args_text") or ""), 220)
            )
            return_summary = self._escape_markdown_cell(
                self._truncate_text(str(entry.get("return_summary") or ""), 220)
            )
            lines.append(f"| {tool_call_id} | {tool_name} | `{args_text}` | {return_summary} |")
        return "\n".join(lines).strip()

    def _should_emit_tool_memory_block(self, summary: str) -> bool:
        """
        判断是否需要追加 Tool Call 记忆块，避免与压缩摘要内同类章节重复。
        """
        text = str(summary or "")
        if "## 已执行 Tool Call 与返回摘要（防重复）" in text:
            return False
        if "## 已执行 Tool Call 记忆（防重复）" in text:
            return False
        return True

    def _canonicalize_tool_args(self, args: Any) -> str:
        payload = {} if args is None else args
        try:
            return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        except TypeError:
            return json.dumps(str(payload), ensure_ascii=False, sort_keys=True, separators=(",", ":"))

    def _summarize_tool_return(self, tool_msg: AgentMessage, fallback_tool_name: str) -> str:
        summary = str(tool_msg.metadata.get("summary") or "").strip()
        if summary:
            return self._truncate_text(self._normalize_text(summary), self._tool_memory_max_text_chars)
        content = str(tool_msg.content_display or "").strip()
        if not content:
            tool_name = str(tool_msg.metadata.get("tool_name") or fallback_tool_name).strip()
            return f"`{tool_name or 'unknown'}` 已执行，返回为空。"
        return self._truncate_text(self._normalize_text(content), self._tool_memory_max_text_chars)

    def _normalize_text(self, text: str) -> str:
        return " ".join(text.split())

    def _escape_markdown_cell(self, text: str) -> str:
        return str(text or "").replace("|", "\\|").replace("\n", " ")

    def _truncate_text(self, text: str, limit: int) -> str:
        if len(text) <= limit:
            return text
        return text[: limit - 3] + "..."
