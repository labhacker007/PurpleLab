"""Conversation manager — handles message history and context.

Manages the conversation state including message history,
context window management, and persistence to database.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

log = logging.getLogger(__name__)


class ConversationManager:
    """Manages conversation state and message history.

    TODO: Implement database persistence via backend.db.models.Conversation/Message.
    TODO: Implement sliding window for long conversations.
    TODO: Add conversation summarization for context compression.
    TODO: Support multiple concurrent conversations.
    """

    def __init__(self, max_messages: int = 50) -> None:
        self.max_messages = max_messages
        # In-memory store until DB is wired up
        self._conversations: dict[str, list[dict[str, Any]]] = {}

    async def get_or_create(self, conversation_id: Optional[str] = None) -> str:
        """Get an existing conversation or create a new one.

        TODO: Create Conversation record in database.
        """
        import uuid
        if conversation_id and conversation_id in self._conversations:
            return conversation_id
        new_id = str(uuid.uuid4())
        self._conversations[new_id] = []
        return new_id

    async def add_message(
        self,
        conversation_id: str,
        role: str,
        content: str,
        tool_calls: Optional[list[dict]] = None,
        tool_results: Optional[list[dict]] = None,
    ) -> None:
        """Add a message to the conversation history.

        TODO: Persist to Message table.
        """
        messages = self._conversations.setdefault(conversation_id, [])
        messages.append({
            "role": role,
            "content": content,
            "tool_calls": tool_calls,
            "tool_results": tool_results,
        })
        # Trim if over max
        if len(messages) > self.max_messages:
            self._conversations[conversation_id] = messages[-self.max_messages:]

    async def get_messages(self, conversation_id: str) -> list[dict[str, Any]]:
        """Get all messages for a conversation.

        TODO: Fetch from database.
        """
        return self._conversations.get(conversation_id, [])

    async def delete(self, conversation_id: str) -> bool:
        """Delete a conversation and all its messages.

        TODO: Cascade delete from database.
        """
        return self._conversations.pop(conversation_id, None) is not None
