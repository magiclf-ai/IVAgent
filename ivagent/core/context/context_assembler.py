#!/usr/bin/env python3
"""
ContextAssembler - 上下文组装器

按策略组装系统提示 + 任务摘要 + 最近 N 轮消息投影。
"""

from typing import List, Optional

from langchain_core.messages import BaseMessage, HumanMessage, SystemMessage, AIMessage, ToolMessage

from .message_manager import MessageManager, AgentMessage


class ContextAssembler:
    """
    上下文组装器

    负责将 MessageManager 中的消息投影组装为 LLM 消息列表。
    """

    def __init__(self, message_manager: MessageManager, recent_message_limit: int = 12):
        self.message_manager = message_manager
        self.recent_message_limit = recent_message_limit

    def build_messages(
        self,
        system_prompt: str,
        task_summary: Optional[str] = None,
    ) -> List[BaseMessage]:
        messages: List[BaseMessage] = []

        if system_prompt:
            messages.append(SystemMessage(content=system_prompt))

        if task_summary:
            messages.append(SystemMessage(content=f"【任务摘要】\n{task_summary}"))

        recent_messages = self.message_manager.get_recent_messages(self.recent_message_limit)
        for msg in recent_messages:
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
