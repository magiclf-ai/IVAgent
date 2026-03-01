#!/usr/bin/env python3
"""
ContextAssembler - 上下文组装器

按策略组装系统提示 + 任务摘要 + 历史消息投影。
当上下文超过阈值时，触发 LLM 压缩历史消息。
"""

from typing import Any, Dict, List, Optional, Set, Tuple
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
        compression_profile: str = "general",
        compression_consumer: str = "context_assembler",
        compression_purpose: str = "",
    ):
        self.message_manager = message_manager
        self.compressor = compressor
        self.read_artifact_pruner = read_artifact_pruner
        self.token_threshold = token_threshold
        self.compression_profile = (compression_profile or "general").strip().lower()
        self.compression_consumer = (compression_consumer or "context_assembler").strip()
        self.compression_purpose = (compression_purpose or "").strip()
        self._precompression_notice_issued = False
        self._projection_last_validation_error = ""

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
            system_prompt=system_prompt,
            task_summary=task_summary,
        )

        history_messages = self.message_manager.get_all_messages()
        for msg in history_messages:
            messages.append(self._convert_message(msg))

        return messages

    def _convert_message(self, msg: AgentMessage) -> BaseMessage:
        content = self._with_message_id_prefix(msg.message_id, msg.content_display or "")
        if msg.role == "system":
            return SystemMessage(content=content)
        if msg.role == "user":
            return HumanMessage(content=content)
        if msg.role == "tool":
            tool_call_id = msg.metadata.get("tool_call_id", "unknown")
            tool_name = msg.metadata.get("tool_name", "")
            return ToolMessage(content=content, tool_call_id=tool_call_id, name=tool_name)

        tool_calls = msg.metadata.get("tool_calls")
        if tool_calls:
            return AIMessage(content=content, tool_calls=tool_calls)
        return AIMessage(content=content)

    async def _ensure_compressed_history(
        self,
        extra_texts: Optional[List[str]] = None,
        system_prompt: str = "",
        task_summary: Optional[str] = None,
    ) -> None:
        if not self.compressor or self.token_threshold <= 0:
            return

        max_rounds = 2
        for _ in range(max_rounds):
            messages = self.message_manager.get_all_messages()
            if not messages:
                return
            compression_anchors = self._build_compression_anchors(
                messages=messages,
                system_prompt=system_prompt,
                task_summary=task_summary,
            )

            estimated_tokens = self._estimate_messages_tokens(messages)
            if extra_texts:
                estimated_tokens += sum(self._estimate_tokens(t) for t in extra_texts if t)
            if estimated_tokens <= self.token_threshold:
                self._precompression_notice_issued = False
                return

            if (
                not self.message_manager.has_pending_compression_projection()
                and not self._precompression_notice_issued
            ):
                notice = self._build_precompression_notice(messages)
                await self.message_manager.add_user_message(
                    notice,
                    metadata={"compression_notice": True},
                )
                self._precompression_notice_issued = True
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

            projection_removed = 0
            projection_folded = 0
            projection_reason = ""
            matched_remove_ids: List[str] = []
            unmatched_remove_ids: List[str] = []
            matched_fold_ids: List[str] = []
            unmatched_fold_ids: List[str] = []
            projection_payload = self.message_manager.pop_compression_projection()
            projection_remove_ids = {
                str(mid).strip()
                for mid in (projection_payload.get("remove_message_ids") or [])
                if str(mid or "").strip()
            }
            projection_fold_ids = {
                str(mid).strip()
                for mid in (projection_payload.get("fold_message_ids") or [])
                if str(mid or "").strip()
            }
            if projection_remove_ids and projection_fold_ids:
                projection_fold_ids = projection_fold_ids - projection_remove_ids
            if projection_remove_ids or projection_fold_ids:
                self._precompression_notice_issued = False
                projection_reason = str(projection_payload.get("reason") or "").strip()
                present_ids = {m.message_id for m in compress_candidates}
                matched_remove_ids = sorted(projection_remove_ids & present_ids)
                unmatched_remove_ids = sorted(projection_remove_ids - present_ids)
                matched_fold_ids = sorted(projection_fold_ids & present_ids)
                unmatched_fold_ids = sorted(projection_fold_ids - present_ids)
                if projection_remove_ids:
                    compress_candidates, projection_removed = self._apply_projection_deletions(
                        compress_candidates=compress_candidates,
                        remove_message_ids=projection_remove_ids,
                    )
                if projection_remove_ids and matched_remove_ids and projection_removed == 0:
                    reject_reason = self._projection_last_validation_error or "会破坏 tool_call 上下文完整性"
                    projection_reason = (
                        f"{projection_reason}；裁切被拒绝：{reject_reason}"
                        if projection_reason else f"裁切被拒绝：{reject_reason}"
                    )
                    await self.message_manager.add_user_message(
                        "[系统通知] 上一轮 `mark_compression_projection` 裁切清单已被拒绝。\n"
                        f"原因: {reject_reason}\n\n"
                        "请重新提交裁切方案，并确保不会造成 tool call 链断裂。"
                    )
                    self._projection_last_validation_error = ""
                    self._precompression_notice_issued = False
                    return
                if projection_fold_ids:
                    compress_candidates, projection_folded = self._apply_projection_folding(
                        compress_candidates=compress_candidates,
                        fold_message_ids=projection_fold_ids,
                    )

                preserved = [msg for i, msg in enumerate(messages) if i in preserve_set] if preserve_indices else []
                projected_messages = preserved + compress_candidates
                self.message_manager._messages = projected_messages
                if not compress_candidates:
                    return

                projected_tokens = self._estimate_messages_tokens(projected_messages)
                if extra_texts:
                    projected_tokens += sum(self._estimate_tokens(t) for t in extra_texts if t)
                if projected_tokens <= self.token_threshold:
                    self._precompression_notice_issued = False
                    return

            head = compress_candidates

            pruned_count = 0
            pruned_reason = ""
            pruned_reject_reason = ""
            if self.read_artifact_pruner and head:
                prune_result = await self.read_artifact_pruner.prune(head)
                if prune_result.remove_message_ids:
                    head_ids = {m.message_id for m in head}
                    remove_ids = [mid for mid in prune_result.remove_message_ids if mid in head_ids]
                    if remove_ids:
                        pruned_set = set(remove_ids)
                        pruned_head = [m for m in head if m.message_id not in pruned_set]
                        valid, reason = self._validate_tool_call_linkage(pruned_head)
                        if not valid:
                            pruned_reject_reason = reason
                            logger.warning(
                                "Reject read_artifact_pruner removals due to invalid tool-call linkage: %s",
                                reason,
                            )
                        else:
                            pruned_reason = prune_result.reason
                            head = pruned_head
                            pruned_count = len(remove_ids)
                            if not head:
                                self._precompression_notice_issued = False
                                return

            result = await self.compressor.compress(
                head,
                anchors=compression_anchors,
                compression_profile=self.compression_profile,
                consumer_agent=self.compression_consumer,
                purpose=self.compression_purpose,
            )
            if not result.summary:
                return

            compressed_summary = (result.summary or "").strip()
            tool_memory_block = (result.tool_memory_block or "").strip()
            if tool_memory_block:
                compressed_summary = f"{compressed_summary}\n\n{tool_memory_block}".strip()

            meta = {
                "compression_reason": result.reason,
                "compressed_count": len(head),
                "token_estimate_before": estimated_tokens,
                "store_artifact": result.store_artifact,
                "dropped_message_count": len(result.dropped_message_ids),
                "fold_message_count": len(result.fold_message_ids),
            }
            if projection_removed:
                meta["projection_removed_count"] = projection_removed
            if projection_folded:
                meta["projection_folded_count"] = projection_folded
            if projection_reason:
                meta["projection_reason"] = projection_reason
            if matched_remove_ids:
                meta["projection_matched_remove_message_ids"] = matched_remove_ids
            if unmatched_remove_ids:
                meta["projection_unmatched_remove_message_ids"] = unmatched_remove_ids
            if matched_fold_ids:
                meta["projection_matched_fold_message_ids"] = matched_fold_ids
            if unmatched_fold_ids:
                meta["projection_unmatched_fold_message_ids"] = unmatched_fold_ids
            if pruned_count:
                meta["pruned_read_artifact_count"] = pruned_count
            if pruned_reason:
                meta["pruned_read_artifact_reason"] = pruned_reason
            if pruned_reject_reason:
                meta["pruned_read_artifact_reject_reason"] = pruned_reject_reason
            compressed_message = self.message_manager.build_compressed_message(
                summary=compressed_summary,
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
            self._precompression_notice_issued = False
            return

    def _build_compression_anchors(
        self,
        messages: List[AgentMessage],
        system_prompt: str = "",
        task_summary: Optional[str] = None,
    ) -> Dict[str, str]:
        anchors: Dict[str, str] = {}

        first_system_history = next(
            (str(m.content_display or "").strip() for m in messages if m.role == "system" and str(m.content_display or "").strip()),
            "",
        )
        first_user_goal = next(
            (str(m.content_display or "").strip() for m in messages if m.role == "user" and str(m.content_display or "").strip()),
            "",
        )

        effective_system_prompt = str(system_prompt or "").strip() or first_system_history
        if effective_system_prompt:
            anchors["system_prompt"] = effective_system_prompt
        if first_user_goal:
            anchors["first_user_goal"] = first_user_goal
        if task_summary and str(task_summary).strip():
            anchors["task_summary"] = str(task_summary).strip()

        return anchors

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

    def _build_precompression_notice(self, messages: List[AgentMessage]) -> str:
        index_table = self._build_projection_message_index(messages)
        return (
            "[系统通知] 即将触发上下文压缩。\n"
            "请基于当前会话中已收集的信息进行压缩前推理，并优先提交消息级裁切清单。\n\n"
            "必须调用：\n"
            "- `mark_compression_projection(remove_message_ids=[...], fold_message_ids=[...], reason=...)`\n"
            "- 若不删除任何消息，也必须调用："
            "`mark_compression_projection(remove_message_ids=[], fold_message_ids=[], reason=\"无可安全删除条目\")`\n\n"
            "约束：\n"
            "- `remove_message_ids` / `fold_message_ids` 必须引用消息首行 `消息ID: ...`\n"
            "- 系统仅精确删除清单内消息，不会隐式级联删除未列出的消息\n"
            "- `fold_message_ids` 会将消息内容替换为“内容已经折叠，信息如需要请重新获取。”，并保留链路结构\n"
            "- 提交删除清单必须规避 tool call 链断裂（assistant tool_call 与 ToolMessage 需成对保持）\n"
            "- 优先删除“可单独删除=是”的消息；“可单独删除=否”的消息必须按依赖提示成对处理\n"
            "- 对于“可单独删除=否”的长消息，优先使用 `fold_message_ids`\n"
            "- 仅可删除与当前目标无关或已完成闭环的冗余消息，禁止删除关键证据链\n"
            "- 同轮优先最小动作，不回退全量重复取证\n\n"
            "## 当前消息索引（可直接引用 message_id）\n"
            f"{index_table}"
        )

    def _build_projection_message_index(self, messages: List[AgentMessage]) -> str:
        if not messages:
            return "无"
        dependency_notes = self._build_projection_dependency_notes(messages)
        lines = [
            "| message_id | role | 可单独删除 | 依赖提示 | 摘要 |",
            "|------------|------|------------|----------|------|",
        ]
        for msg in messages:
            deletable, dependency_hint = dependency_notes.get(msg.message_id, ("是", "-"))
            excerpt = self._message_index_excerpt(msg.content_display or "")
            escaped_dependency = str(dependency_hint).replace("|", "\\|")
            escaped_excerpt = excerpt.replace("|", "\\|")
            lines.append(
                f"| `{msg.message_id}` | `{msg.role}` | {deletable} | {escaped_dependency} | {escaped_excerpt} |"
            )
        return "\n".join(lines)

    def _build_projection_dependency_notes(
        self,
        messages: List[AgentMessage],
    ) -> Dict[str, Tuple[str, str]]:
        notes: Dict[str, Tuple[str, str]] = {}
        call_to_assistant: Dict[str, str] = {}
        call_to_tools: Dict[str, List[str]] = {}

        for msg in messages:
            if msg.role == "assistant":
                tool_calls = msg.metadata.get("tool_calls")
                if isinstance(tool_calls, list) and tool_calls:
                    for tc in tool_calls:
                        if not isinstance(tc, dict):
                            continue
                        call_id = str(tc.get("id") or "").strip()
                        if call_id:
                            call_to_assistant[call_id] = msg.message_id
            elif msg.role == "tool":
                call_id = str(msg.metadata.get("tool_call_id") or "").strip()
                if call_id:
                    call_to_tools.setdefault(call_id, []).append(msg.message_id)

        for call_id, assistant_mid in call_to_assistant.items():
            tool_mids = call_to_tools.get(call_id) or []
            if tool_mids:
                tool_list = ", ".join(f"`{mid}`" for mid in tool_mids[:6])
                if len(tool_mids) > 6:
                    tool_list += ", ..."
                notes[assistant_mid] = ("否", f"含 tool_call；推荐折叠，若删除需同时删除 {tool_list}")
                for tool_mid in tool_mids:
                    notes[tool_mid] = ("否", f"Tool 返回；推荐折叠，删除需与 `{assistant_mid}` 成对处理")
            else:
                notes[assistant_mid] = ("否", "含 tool_call；当前无对应 Tool 返回，禁止单删")

        for call_id, tool_mids in call_to_tools.items():
            if call_id not in call_to_assistant:
                for tool_mid in tool_mids:
                    notes[tool_mid] = ("否", "孤立 Tool 返回，禁止单删")

        return notes

    def _message_index_excerpt(self, content: str, limit: int = 80) -> str:
        text = str(content or "").strip().replace("\n", " ")
        if text.startswith("消息ID: "):
            lines = text.splitlines()
            text = " ".join(lines[1:]).strip()
        if not text:
            return "empty"
        if len(text) <= limit:
            return text
        return text[: limit - 3] + "..."

    def _with_message_id_prefix(self, message_id: str, content: str) -> str:
        prefix = f"消息ID: {message_id}"
        text = str(content or "")
        if text.startswith(prefix):
            return text
        if text.startswith("消息ID: "):
            lines = text.splitlines()
            if lines:
                lines[0] = prefix
                return "\n".join(lines)
        if not text:
            return prefix
        return f"{prefix}\n{text}"

    def _apply_projection_deletions(
        self,
        compress_candidates: List[AgentMessage],
        remove_message_ids: Set[str],
    ) -> Tuple[List[AgentMessage], int]:
        """
        按 message_id 应用预裁切（不会隐式级联删除其他消息）。
        """
        if not compress_candidates or not remove_message_ids:
            return compress_candidates, 0

        explicit_remove_ids = set(remove_message_ids)
        kept: List[AgentMessage] = []
        effects = 0

        for msg in compress_candidates:
            if msg.message_id not in explicit_remove_ids:
                kept.append(msg)
                continue

            effects += 1
        valid, reason = self._validate_tool_call_linkage(kept)
        if not valid:
            self._projection_last_validation_error = reason
            return compress_candidates, 0
        self._projection_last_validation_error = ""
        return kept, effects

    def _apply_projection_folding(
        self,
        compress_candidates: List[AgentMessage],
        fold_message_ids: Set[str],
    ) -> Tuple[List[AgentMessage], int]:
        """
        按 message_id 应用预折叠：保留消息链路，仅替换正文内容。
        """
        if not compress_candidates or not fold_message_ids:
            return compress_candidates, 0

        folded: List[AgentMessage] = []
        effects = 0
        folded_text = "内容已经折叠，信息如需要请重新获取。"
        for msg in compress_candidates:
            if msg.message_id not in fold_message_ids:
                folded.append(msg)
                continue
            metadata = dict(msg.metadata or {})
            metadata["folded"] = True
            folded.append(
                AgentMessage(
                    message_id=msg.message_id,
                    role=msg.role,
                    content_display=folded_text,
                    content_full=folded_text,
                    created_at=msg.created_at,
                    artifacts=list(msg.artifacts or []),
                    metadata=metadata,
                )
            )
            effects += 1
        return folded, effects

    def _validate_tool_call_linkage(self, messages: List[AgentMessage]) -> Tuple[bool, str]:
        call_to_assistant: Dict[str, Tuple[int, str]] = {}
        call_to_tool_items: Dict[str, List[Tuple[int, str]]] = {}
        for idx, msg in enumerate(messages):
            if msg.role == "assistant":
                tool_calls = msg.metadata.get("tool_calls")
                if not isinstance(tool_calls, list):
                    continue
                for tc in tool_calls:
                    if not isinstance(tc, dict):
                        continue
                    call_id = str(tc.get("id") or "").strip()
                    if call_id:
                        call_to_assistant[call_id] = (idx, msg.message_id)
            elif msg.role == "tool":
                call_id = str(msg.metadata.get("tool_call_id") or "").strip()
                if not call_id:
                    continue
                call_to_tool_items.setdefault(call_id, []).append((idx, msg.message_id))

        for call_id, tool_items in call_to_tool_items.items():
            assistant_item = call_to_assistant.get(call_id)
            tool_message_ids = [mid for _, mid in tool_items]
            if assistant_item is None:
                return False, (
                    f"orphan tool_message call_id={call_id}; "
                    f"tool_message_ids={','.join(tool_message_ids)}"
                )
            assistant_idx, assistant_message_id = assistant_item
            if any(tidx <= assistant_idx for tidx, _ in tool_items):
                return False, (
                    f"tool_message before assistant tool_call call_id={call_id}; "
                    f"assistant_message_id={assistant_message_id}; "
                    f"tool_message_ids={','.join(tool_message_ids)}"
                )

        for call_id, assistant_item in call_to_assistant.items():
            assistant_idx, assistant_message_id = assistant_item
            tool_items = call_to_tool_items.get(call_id) or []
            if not any(tidx > assistant_idx for tidx, _ in tool_items):
                return False, (
                    f"missing tool_message for assistant tool_call call_id={call_id}; "
                    f"assistant_message_id={assistant_message_id}"
                )

        return True, ""
