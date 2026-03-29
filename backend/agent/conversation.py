"""Conversation manager — handles message history and context.

Manages the conversation state including message history,
context window management, and persistence to database.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

log = logging.getLogger(__name__)

# Rough token estimator: ~4 characters per token.
_CHARS_PER_TOKEN = 4


def _estimate_tokens(text: str) -> int:
    """Estimate token count from character length."""
    return max(1, len(text) // _CHARS_PER_TOKEN)


def _estimate_message_tokens(msg: dict[str, Any]) -> int:
    """Estimate the token cost of a single internal message dict."""
    content = msg.get("content", "")
    if isinstance(content, str):
        tokens = _estimate_tokens(content)
    elif isinstance(content, list):
        # Content blocks (tool_result, mixed content, etc.)
        tokens = 0
        for block in content:
            if isinstance(block, dict):
                for v in block.values():
                    if isinstance(v, str):
                        tokens += _estimate_tokens(v)
            elif isinstance(block, str):
                tokens += _estimate_tokens(block)
    else:
        tokens = 0

    # Account for tool_calls metadata
    tool_calls = msg.get("tool_calls")
    if tool_calls:
        tokens += _estimate_tokens(str(tool_calls))
    tool_results = msg.get("tool_results")
    if tool_results:
        tokens += _estimate_tokens(str(tool_results))

    return tokens


class ConversationManager:
    """Manages conversation state and message history.

    Uses in-memory storage. Database persistence can be layered in later
    by subclassing or swapping the storage backend.
    """

    def __init__(self, max_messages: int = 100, token_budget: int = 30_000) -> None:
        self.max_messages = max_messages
        self.token_budget = token_budget
        # conversation_id -> {"messages": [...], "created_at": ..., "title": ...}
        self._conversations: dict[str, dict[str, Any]] = {}

    # ── Lifecycle ───────────────────────────────────────────────────────────

    async def get_or_create(self, conversation_id: Optional[str] = None) -> str:
        """Return an existing conversation id, or create a new one."""
        if conversation_id and conversation_id in self._conversations:
            return conversation_id
        new_id = conversation_id or str(uuid.uuid4())
        self._conversations[new_id] = {
            "messages": [],
            "created_at": datetime.now(timezone.utc).isoformat(),
            "title": "",
        }
        log.info("conversation_created id=%s", new_id)
        return new_id

    async def delete(self, conversation_id: str) -> bool:
        """Delete a conversation and all its messages."""
        removed = self._conversations.pop(conversation_id, None)
        if removed is not None:
            log.info("conversation_deleted id=%s", conversation_id)
            return True
        return False

    async def list_conversations(self) -> list[dict[str, Any]]:
        """Return a summary list of all conversations."""
        result = []
        for cid, data in self._conversations.items():
            messages = data["messages"]
            # Derive title from first user message if not set
            title = data.get("title") or ""
            if not title and messages:
                for m in messages:
                    if m["role"] == "user":
                        text = m["content"] if isinstance(m["content"], str) else str(m["content"])
                        title = text[:80]
                        break
            result.append({
                "id": cid,
                "title": title,
                "message_count": len(messages),
                "created_at": data.get("created_at", ""),
            })
        return result

    # ── Messages ────────────────────────────────────────────────────────────

    async def add_message(
        self,
        conversation_id: str,
        role: str,
        content: Any,
        tool_calls: Optional[list[dict]] = None,
        tool_results: Optional[list[dict]] = None,
    ) -> None:
        """Append a message to the conversation.

        Args:
            conversation_id: Target conversation.
            role: ``"user"`` or ``"assistant"``.
            content: Text string or list of content blocks.
            tool_calls: Tool-use blocks the assistant emitted (stored for replay).
            tool_results: Tool-result blocks (stored for replay).
        """
        conv = self._conversations.get(conversation_id)
        if conv is None:
            await self.get_or_create(conversation_id)
            conv = self._conversations[conversation_id]

        messages = conv["messages"]
        messages.append({
            "role": role,
            "content": content,
            "tool_calls": tool_calls,
            "tool_results": tool_results,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        # Hard cap on stored messages
        if len(messages) > self.max_messages:
            conv["messages"] = messages[-self.max_messages:]

    async def get_messages(self, conversation_id: str) -> list[dict[str, Any]]:
        """Return all raw internal messages for a conversation."""
        conv = self._conversations.get(conversation_id)
        if conv is None:
            return []
        return list(conv["messages"])

    async def get_conversation(self, conversation_id: str) -> Optional[dict[str, Any]]:
        """Return the full conversation record, or None."""
        conv = self._conversations.get(conversation_id)
        if conv is None:
            return None
        return {
            "id": conversation_id,
            **conv,
        }

    # ── Anthropic Format Conversion ─────────────────────────────────────────

    async def get_anthropic_messages(
        self, conversation_id: str
    ) -> list[dict[str, Any]]:
        """Convert internal messages to Anthropic messages API format.

        The Anthropic API expects:
        - ``{"role": "user", "content": "..."}``
        - ``{"role": "assistant", "content": "..."}`` (can contain tool_use blocks)
        - ``{"role": "user", "content": [{"type": "tool_result", ...}]}``

        This method reconstructs that sequence, including tool-call and
        tool-result round-trips stored in our internal format.
        """
        raw = await self.get_messages(conversation_id)
        api_messages: list[dict[str, Any]] = []

        for msg in raw:
            role = msg["role"]
            content = msg["content"]
            tool_calls = msg.get("tool_calls")
            tool_results = msg.get("tool_results")

            if role == "assistant" and tool_calls:
                # Reconstruct assistant message with tool_use blocks
                blocks: list[dict[str, Any]] = []
                # Include any text content
                if content and isinstance(content, str):
                    blocks.append({"type": "text", "text": content})
                # Append tool_use blocks
                for tc in tool_calls:
                    blocks.append({
                        "type": "tool_use",
                        "id": tc["id"],
                        "name": tc["name"],
                        "input": tc["input"],
                    })
                api_messages.append({"role": "assistant", "content": blocks})
            elif role == "user" and tool_results:
                # Tool result message
                blocks = []
                for tr in tool_results:
                    blocks.append({
                        "type": "tool_result",
                        "tool_use_id": tr["tool_use_id"],
                        "content": tr.get("content", ""),
                    })
                api_messages.append({"role": "user", "content": blocks})
            else:
                # Plain text message
                text = content if isinstance(content, str) else str(content)
                api_messages.append({"role": role, "content": text})

        return api_messages

    # ── OpenAI Format Conversion ────────────────────────────────────────────

    async def get_openai_messages(
        self, conversation_id: str
    ) -> list[dict[str, Any]]:
        """Convert internal messages to OpenAI chat completion format.

        Note: system message is NOT included here — the caller injects it.
        Tool call/result pairs are converted to OpenAI function_calling format.
        """
        raw = await self.get_messages(conversation_id)
        api_messages: list[dict[str, Any]] = []

        for msg in raw:
            role = msg["role"]
            content = msg["content"] or ""
            tool_calls = msg.get("tool_calls")
            tool_results = msg.get("tool_results")

            if role == "assistant" and tool_calls:
                import json as _json
                oai_msg: dict[str, Any] = {"role": "assistant", "content": content or None}
                oai_msg["tool_calls"] = [
                    {
                        "id": tc["id"],
                        "type": "function",
                        "function": {
                            "name": tc["name"],
                            "arguments": _json.dumps(tc["input"], default=str),
                        },
                    }
                    for tc in tool_calls
                ]
                api_messages.append(oai_msg)
            elif role == "user" and tool_results:
                for tr in tool_results:
                    api_messages.append({
                        "role": "tool",
                        "tool_call_id": tr["tool_use_id"],
                        "content": tr.get("content", ""),
                    })
            else:
                text = content if isinstance(content, str) else str(content)
                api_messages.append({"role": role, "content": text})

        return api_messages

    # ── Context Window Management ───────────────────────────────────────────

    async def trim_to_budget(
        self, conversation_id: str, budget: Optional[int] = None
    ) -> None:
        """Trim oldest messages to stay under the token budget.

        Always preserves the very first message (assumed to be the
        initial user query that sets context). Tool-result pairs are
        removed together to avoid orphaned tool results.
        """
        budget = budget or self.token_budget
        conv = self._conversations.get(conversation_id)
        if conv is None:
            return

        messages = conv["messages"]
        if not messages:
            return

        total = sum(_estimate_message_tokens(m) for m in messages)

        if total <= budget:
            return

        # Keep first message, trim from the front of the rest
        first = messages[0]
        rest = messages[1:]

        while rest and total > budget:
            removed = rest.pop(0)
            total -= _estimate_message_tokens(removed)
            # If we removed an assistant message with tool_calls, the next
            # message is likely a tool_result — remove it too to keep
            # the conversation valid.
            if (
                removed.get("tool_calls")
                and rest
                and rest[0].get("tool_results")
            ):
                extra = rest.pop(0)
                total -= _estimate_message_tokens(extra)

        conv["messages"] = [first] + rest
        log.info(
            "conversation_trimmed id=%s remaining=%d est_tokens=%d",
            conversation_id,
            len(conv["messages"]),
            total,
        )
