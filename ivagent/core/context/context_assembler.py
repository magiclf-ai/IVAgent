#!/usr/bin/env python3
"""
ContextAssembler - 上下文组装器

按策略组装系统提示 + 任务摘要 + 历史消息投影。
当上下文超过阈值时，触发 LLM 压缩历史消息。
"""

from typing import List, Optional, Tuple
import json

from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage, AIMessage, ToolMessage

from .message_manager import MessageManager, AgentMessage
from .context_compressor import ContextCompressor
from .read_artifact_pruner import ReadArtifactPruner


class ContextAssembler:
    """
    上下文组装器

    负责将 MessageManager 中的消息投影组装为 LLM 消息列表。
    """

    def __init__(
        self,
        message_manager: MessageManager,
        compressor: Optional[ContextCompressor] = None,
        read_artifact_pruner: Optional[ReadArtifactPruner] = None,
        token_threshold: int = 8000,
    ):
        self.message_manager = message_manager
        self.compressor = compressor
        self.read_artifact_pruner = read_artifact_pruner
        self.token_threshold = token_threshold

    async def build_messages(
        self,
        system_prompt: str,
        task_summary: Optional[str] = None,
    ) -> List[BaseMessage]:
        messages: List[BaseMessage] = []

        if system_prompt:
            messages.append(SystemMessage(content=system_prompt))

        if task_summary:
            messages.append(SystemMessage(content=f"【任务摘要】\n{task_summary}"))

        await self._ensure_compressed_history(
            extra_texts=[system_prompt, task_summary or ""],
        )

        history_messages = self.message_manager.get_all_messages()
        for msg in history_messages:
            messages.append(self._convert_message(msg))

        return messages

    def _convert_message(self, msg: AgentMessage) -> BaseMessage:
        if msg.role == "system":
            return SystemMessage(content=msg.content_display)
        if msg.role == "user":
            return HumanMessage(content=msg.content_display)
        if msg.role == "tool":
            tool_call_id = msg.metadata.get("tool_call_id", "unknown")
            tool_name = msg.metadata.get("tool_name", "")
            return ToolMessage(content=msg.content_display, tool_call_id=tool_call_id, name=tool_name)

        tool_calls = msg.metadata.get("tool_calls")
        if tool_calls:
            return AIMessage(content=msg.content_display, tool_calls=tool_calls)
        return AIMessage(content=msg.content_display)

    async def _ensure_compressed_history(self, extra_texts: Optional[List[str]] = None) -> None:
        if not self.compressor or self.token_threshold <= 0:
            return

        max_rounds = 2
        for _ in range(max_rounds):
            messages = self.message_manager.get_all_messages()
            if not messages:
                return

            estimated_tokens = self._estimate_messages_tokens(messages)
            if extra_texts:
                estimated_tokens += sum(self._estimate_tokens(t) for t in extra_texts if t)
            if estimated_tokens <= self.token_threshold:
                return

            first_system_idx = next((i for i, m in enumerate(messages) if m.role == "system"), None)
            first_user_idx = next((i for i, m in enumerate(messages) if m.role == "user"), None)
            preserve_indices: List[int] = []
            if first_system_idx is not None and (
                first_user_idx is None or first_system_idx < first_user_idx
            ):
                preserve_indices.append(first_system_idx)
            if first_user_idx is not None:
                preserve_indices.append(first_user_idx)
            preserve_indices = sorted(set(preserve_indices))
            preserve_set = set(preserve_indices)
            compress_candidates = [m for i, m in enumerate(messages) if i not in preserve_set]
            if not compress_candidates:
                return

            head = compress_candidates

            pruned_count = 0
            pruned_reason = ""
            if self.read_artifact_pruner and head:
                prune_result = await self.read_artifact_pruner.prune(head)
                if prune_result.remove_message_ids:
                    head_ids = {m.message_id for m in head}
                    remove_ids = [mid for mid in prune_result.remove_message_ids if mid in head_ids]
                    if remove_ids:
                        pruned_reason = prune_result.reason
                        pruned_set = set(remove_ids)
                        head = [m for m in head if m.message_id not in pruned_set]
                        pruned_count = len(remove_ids)
                        if not head:
                            return

            result = await self.compressor.compress(head)
            if not result.summary:
                return

            meta = {
                "compression_reason": result.reason,
                "compressed_count": len(head),
                "token_estimate_before": estimated_tokens,
                "store_artifact": result.store_artifact,
            }
            if pruned_count:
                meta["pruned_read_artifact_count"] = pruned_count
            if pruned_reason:
                meta["pruned_read_artifact_reason"] = pruned_reason
            compressed_message = self.message_manager.build_compressed_message(
                summary=result.summary,
                store_artifact=result.store_artifact,
                metadata=meta,
            )
            compress_ids = [m.message_id for m in compress_candidates]
            if compress_ids:
                self.message_manager.remove_messages_by_id(compress_ids)
            if preserve_indices:
                preserved = [
                    msg for i, msg in enumerate(messages) if i in preserve_set
                ]
            else:
                preserved = []
            self.message_manager._messages = preserved + [compressed_message]
            return

    def _split_for_compression(
        self,
        messages: List[AgentMessage],
    ) -> Tuple[List[AgentMessage], List[AgentMessage]]:
        last_tool_call_idx = None
        last_user_idx = None

        for idx, msg in enumerate(messages):
            if msg.role == "user":
                last_user_idx = idx
            if msg.role == "assistant" and msg.metadata.get("tool_calls"):
                last_tool_call_idx = idx

        if last_tool_call_idx is not None:
            prev_user_idx = None
            for idx in range(last_tool_call_idx - 1, -1, -1):
                if messages[idx].role == "user":
                    prev_user_idx = idx
                    break
            tail_start = prev_user_idx if prev_user_idx is not None else last_tool_call_idx
        elif last_user_idx is not None:
            tail_start = last_user_idx
        else:
            tail_start = max(0, len(messages) - 1)

        head = messages[:tail_start]
        tail = messages[tail_start:]
        return head, tail

    def _estimate_messages_tokens(self, messages: List[AgentMessage]) -> int:
        total = 0
        for msg in messages:
            total += self._estimate_message_tokens(msg)
        return total

    def _estimate_message_tokens(self, msg: AgentMessage) -> int:
        content = msg.content_display or ""
        if msg.metadata.get("tool_calls"):
            content += "\n" + json.dumps(msg.metadata.get("tool_calls"), ensure_ascii=False)
        return self._estimate_tokens(content)

    def _estimate_tokens(self, text: str) -> int:
        # 粗略估算：1 token ≈ 4 字符
        return max(1, len(text) // 4) if text else 0
