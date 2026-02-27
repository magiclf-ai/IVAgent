#!/usr/bin/env python3
"""
ReadArtifactPruner - 纯代码的 read_artifact 调用清理器

仅在压缩阶段识别并移除 read_artifact 调用与返回，避免上下文膨胀。
"""

from dataclasses import dataclass
from typing import List, Dict, Set

from .message_manager import AgentMessage


@dataclass
class ReadArtifactPruneResult:
    """read_artifact 清理结果"""
    remove_message_ids: List[str]
    reason: str = ""


class ReadArtifactPruner:
    """
    纯代码的 read_artifact 清理器

    - 输入：历史消息列表
    - 输出：需要移除的 message_id 列表
    """

    async def prune(self, messages: List[AgentMessage]) -> ReadArtifactPruneResult:
        """
        识别并返回需要成对移除的 read_artifact 调用与返回消息。

        仅当满足以下条件时才移除：
        - assistant 消息的 tool_calls 全部为 read_artifact
        - 每个 tool_call 都包含 id
        - 每个 tool_call_id 在同一批消息中存在对应的 tool 返回
        - 调用与返回齐全才成对移除

        Args:
            messages: 需要清理的历史消息列表

        Returns:
            ReadArtifactPruneResult
        """
        if not messages:
            return ReadArtifactPruneResult(remove_message_ids=[])

        tool_returns: Dict[str, List[str]] = {}
        for msg in messages:
            if msg.role != "tool":
                continue
            tool_name = msg.metadata.get("tool_name")
            tool_call_id = msg.metadata.get("tool_call_id")
            if tool_name != "read_artifact" or not tool_call_id:
                continue
            tool_returns.setdefault(str(tool_call_id), []).append(msg.message_id)

        remove_ids: Set[str] = set()
        removed_pairs = 0

        for msg in messages:
            if msg.role != "assistant":
                continue
            tool_calls = msg.metadata.get("tool_calls")
            if not isinstance(tool_calls, list) or not tool_calls:
                continue

            tool_call_ids: List[str] = []
            all_read_artifact = True
            for tc in tool_calls:
                if not isinstance(tc, dict):
                    all_read_artifact = False
                    break
                if tc.get("name") != "read_artifact":
                    all_read_artifact = False
                    break
                tc_id = tc.get("id")
                if not tc_id:
                    all_read_artifact = False
                    break
                tool_call_ids.append(str(tc_id))

            if not all_read_artifact or not tool_call_ids:
                continue

            if all(tc_id in tool_returns for tc_id in tool_call_ids):
                remove_ids.add(msg.message_id)
                for tc_id in tool_call_ids:
                    for tool_msg_id in tool_returns.get(tc_id, []):
                        remove_ids.add(tool_msg_id)
                removed_pairs += 1

        if not remove_ids:
            return ReadArtifactPruneResult(remove_message_ids=[])

        reason = f"成对移除 read_artifact 调用与返回: {removed_pairs} 组"
        return ReadArtifactPruneResult(
            remove_message_ids=list(remove_ids),
            reason=reason,
        )
