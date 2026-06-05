"""Conversation manager — DB-backed message history with sticky context.

Stores conversations and messages in PostgreSQL via async SQLAlchemy.
Falls back to in-memory storage when the DB is unavailable (dev/test).

Sticky context:
  Each conversation carries a ``context_state`` JSON object that the
  agent updates after every turn. It persists across browser refreshes
  and server restarts so the analyst never has to re-explain their
  environment or goal.

  context_state schema (all optional):
    {
      "environment_id": "uuid",
      "environment_name": "Staging CrowdStrike",
      "goal": "red_team" | "detection_validation" | "tabletop" | "coverage" | "free",
      "active_session_id": "uuid",
      "working_set": {
        "session_ids": [],
        "rule_ids": [],
        "use_case_ids": [],
        "technique_ids": [],
        "scenario_ids": []
      },
      "last_tool": "run_scenario",
      "suggested_followups": []
    }
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

log = logging.getLogger(__name__)

_CHARS_PER_TOKEN = 4


def _estimate_tokens(text: str) -> int:
    return max(1, len(text) // _CHARS_PER_TOKEN)


def _estimate_message_tokens(msg: dict[str, Any]) -> int:
    content = msg.get("content", "")
    if isinstance(content, str):
        tokens = _estimate_tokens(content)
    elif isinstance(content, list):
        tokens = sum(
            _estimate_tokens(str(b)) for b in content
        )
    else:
        tokens = 0
    if msg.get("tool_calls"):
        tokens += _estimate_tokens(str(msg["tool_calls"]))
    if msg.get("tool_results"):
        tokens += _estimate_tokens(str(msg["tool_results"]))
    return tokens


class ConversationManager:
    """DB-backed conversation manager with in-memory fallback.

    Preserves the original public API (get_or_create, add_message,
    get_anthropic_messages, get_openai_messages, trim_to_budget,
    get_conversation, list_conversations, delete).

    New methods for sticky context:
      get_context(conv_id) -> dict
      update_context(conv_id, patch, goal?, title?)
    """

    def __init__(self, max_messages: int = 50, token_budget: int = 18_000) -> None:
        self.max_messages = max_messages
        self.token_budget = token_budget
        # in-memory: conv_id -> {messages, title, goal, context_state, created_at, updated_at}
        self._conversations: dict[str, dict[str, Any]] = {}
        self._db_ok: bool | None = None  # None = not checked yet

    # ── DB availability check ───────────────────────────────────────────────

    async def _db_available(self) -> bool:
        if self._db_ok is not None:
            return self._db_ok
        try:
            from backend.db.session import async_session
            from sqlalchemy import text as _t
            async with async_session() as db:
                await db.execute(_t("SELECT 1"))
            self._db_ok = True
        except Exception as exc:
            log.warning("conversation_manager: DB unavailable (%s) — in-memory mode", exc)
            self._db_ok = False
        return self._db_ok

    # ── DB helpers ──────────────────────────────────────────────────────────

    async def _db_load_conv(self, conv_id: str) -> Any | None:
        try:
            from backend.db.session import async_session
            from backend.db.models import Conversation
            from sqlalchemy import select
            async with async_session() as db:
                result = await db.execute(
                    select(Conversation).where(Conversation.id == uuid.UUID(conv_id))
                )
                return result.scalar_one_or_none()
        except Exception as exc:
            log.warning("db_load_conv failed: %s", exc)
            return None

    async def _db_create_conv(self, conv_id: str, title: str = "",
                               goal: str | None = None) -> None:
        try:
            from backend.db.session import async_session
            from backend.db.models import Conversation
            async with async_session() as db:
                conv = Conversation(id=uuid.UUID(conv_id), title=title or "New Conversation",
                                    goal=goal, context_state={})
                db.add(conv)
                await db.commit()
        except Exception as exc:
            log.warning("db_create_conv failed: %s", exc)

    async def _db_persist_message(self, conv_id: str, role: str, content: Any,
                                   tool_calls: list | None, tool_results: list | None) -> None:
        try:
            from backend.db.session import async_session
            from backend.db.models import Message, Conversation
            from sqlalchemy import update
            async with async_session() as db:
                msg = Message(
                    conversation_id=uuid.UUID(conv_id),
                    role=role,
                    content=content if isinstance(content, str) else str(content),
                    tool_calls=tool_calls,
                    tool_results=tool_results,
                )
                db.add(msg)
                await db.execute(
                    update(Conversation)
                    .where(Conversation.id == uuid.UUID(conv_id))
                    .values(updated_at=datetime.utcnow())
                )
                await db.commit()
        except Exception as exc:
            log.warning("db_persist_message failed: %s", exc)

    async def _db_load_messages(self, conv_id: str) -> list[dict]:
        try:
            from backend.db.session import async_session
            from backend.db.models import Message
            from sqlalchemy import select
            async with async_session() as db:
                result = await db.execute(
                    select(Message)
                    .where(Message.conversation_id == uuid.UUID(conv_id))
                    .order_by(Message.created_at)
                )
                msgs = result.scalars().all()
                return [{
                    "role": m.role,
                    "content": m.content or "",
                    "tool_calls": m.tool_calls,
                    "tool_results": m.tool_results,
                    "timestamp": str(m.created_at),
                } for m in msgs]
        except Exception as exc:
            log.warning("db_load_messages failed: %s", exc)
            return []

    async def _db_update_context(self, conv_id: str, context_state: dict,
                                  goal: str | None, title: str | None) -> None:
        try:
            from backend.db.session import async_session
            from backend.db.models import Conversation
            from sqlalchemy import update
            values: dict[str, Any] = {
                "context_state": context_state,
                "updated_at": datetime.utcnow(),
            }
            if goal is not None:
                values["goal"] = goal
            if title is not None:
                values["title"] = title
            async with async_session() as db:
                await db.execute(
                    update(Conversation)
                    .where(Conversation.id == uuid.UUID(conv_id))
                    .values(**values)
                )
                await db.commit()
        except Exception as exc:
            log.warning("db_update_context failed: %s", exc)

    # ── Lifecycle ───────────────────────────────────────────────────────────

    async def get_or_create(self, conversation_id: Optional[str] = None,
                             goal: Optional[str] = None) -> str:
        """Return an existing conversation id, or create a new one."""
        conv_id = conversation_id or str(uuid.uuid4())

        if await self._db_available():
            existing = await self._db_load_conv(conv_id)
            if not existing:
                await self._db_create_conv(conv_id, goal=goal)
                # Seed in-memory record
                self._conversations[conv_id] = {
                    "messages": [],
                    "created_at": datetime.utcnow().isoformat(),
                    "updated_at": datetime.utcnow().isoformat(),
                    "title": "",
                    "goal": goal,
                    "context_state": {},
                }
            elif conv_id not in self._conversations:
                # Load from DB into memory on first access this session
                msgs = await self._db_load_messages(conv_id)
                self._conversations[conv_id] = {
                    "messages": msgs,
                    "created_at": str(existing.created_at),
                    "updated_at": str(existing.updated_at),
                    "title": existing.title or "",
                    "goal": existing.goal,
                    "context_state": existing.context_state or {},
                }
        else:
            if conv_id not in self._conversations:
                self._conversations[conv_id] = {
                    "messages": [],
                    "created_at": datetime.utcnow().isoformat(),
                    "updated_at": datetime.utcnow().isoformat(),
                    "title": "",
                    "goal": goal,
                    "context_state": {},
                }

        log.info("conversation_ready id=%s", conv_id)
        return conv_id

    async def delete(self, conversation_id: str) -> bool:
        removed = self._conversations.pop(conversation_id, None)
        if await self._db_available():
            try:
                from backend.db.session import async_session
                from backend.db.models import Conversation
                from sqlalchemy import delete as sa_delete
                async with async_session() as db:
                    result = await db.execute(
                        sa_delete(Conversation)
                        .where(Conversation.id == uuid.UUID(conversation_id))
                    )
                    await db.commit()
                    return result.rowcount > 0
            except Exception as exc:
                log.warning("db_delete_conversation failed: %s", exc)
        return removed is not None

    async def list_conversations(self) -> list[dict[str, Any]]:
        if await self._db_available():
            try:
                from backend.db.session import async_session
                from backend.db.models import Conversation, Message
                from sqlalchemy import select, func
                async with async_session() as db:
                    # Subquery: count messages per conversation
                    msg_count_sq = (
                        select(
                            Message.conversation_id,
                            func.count(Message.id).label("cnt")
                        )
                        .group_by(Message.conversation_id)
                        .subquery()
                    )
                    result = await db.execute(
                        select(Conversation, func.coalesce(msg_count_sq.c.cnt, 0).label("msg_count"))
                        .outerjoin(msg_count_sq, Conversation.id == msg_count_sq.c.conversation_id)
                        .order_by(Conversation.updated_at.desc())
                        .limit(50)
                    )
                    rows = result.all()
                    return [{
                        "id": str(c.id),
                        "title": c.title or "",
                        "goal": c.goal,
                        "context_state": c.context_state or {},
                        "message_count": int(cnt),
                        "created_at": str(c.created_at),
                        "updated_at": str(c.updated_at),
                    } for c, cnt in rows]
            except Exception as exc:
                log.warning("list_conversations_db_failed: %s", exc)

        # Fallback to in-memory
        result = []
        for cid, data in sorted(
            self._conversations.items(),
            key=lambda x: x[1].get("updated_at", ""),
            reverse=True
        ):
            title = data.get("title") or ""
            if not title:
                for m in data["messages"]:
                    if m["role"] == "user":
                        t = m["content"] if isinstance(m["content"], str) else str(m["content"])
                        title = t[:80]
                        break
            result.append({
                "id": cid, "title": title, "goal": data.get("goal"),
                "context_state": data.get("context_state", {}),
                "message_count": len(data["messages"]),
                "created_at": data.get("created_at", ""),
                "updated_at": data.get("updated_at", ""),
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
        """Append a message to the conversation."""
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
            "timestamp": datetime.utcnow().isoformat(),
        })
        conv["updated_at"] = datetime.utcnow().isoformat()

        if len(messages) > self.max_messages:
            conv["messages"] = messages[-self.max_messages:]

        if await self._db_available():
            await self._db_persist_message(conversation_id, role, content,
                                            tool_calls, tool_results)

    async def get_messages(self, conversation_id: str) -> list[dict[str, Any]]:
        conv = self._conversations.get(conversation_id)
        if conv is None:
            return []
        return list(conv["messages"])

    async def get_conversation(self, conversation_id: str) -> Optional[dict[str, Any]]:
        conv = self._conversations.get(conversation_id)
        if conv:
            return {"id": conversation_id, **conv}

        if await self._db_available():
            existing = await self._db_load_conv(conversation_id)
            if existing:
                msgs = await self._db_load_messages(conversation_id)
                return {
                    "id": conversation_id,
                    "title": existing.title or "",
                    "goal": existing.goal,
                    "context_state": existing.context_state or {},
                    "messages": msgs,
                    "message_count": len(msgs),
                    "created_at": str(existing.created_at),
                    "updated_at": str(existing.updated_at),
                }
        return None

    # ── Sticky context ──────────────────────────────────────────────────────

    async def get_context(self, conversation_id: str) -> dict:
        """Return the sticky context_state for this conversation."""
        conv = self._conversations.get(conversation_id)
        if conv:
            return conv.get("context_state") or {}
        if await self._db_available():
            existing = await self._db_load_conv(conversation_id)
            if existing:
                return existing.context_state or {}
        return {}

    async def update_context(self, conversation_id: str, patch: dict,
                              goal: str | None = None,
                              title: str | None = None) -> None:
        """Merge patch into the conversation's context_state.

        working_set sub-keys are deduplicated-unioned rather than replaced
        so the agent can accumulate IDs across turns.
        """
        conv = self._conversations.get(conversation_id)
        if conv is None:
            return

        current = conv.get("context_state") or {}

        # Deep-merge working_set: union lists, don't replace
        if "working_set" in patch:
            ws_patch = patch["working_set"]
            ws_cur = current.get("working_set", {})
            for key, val in ws_patch.items():
                if isinstance(val, list) and isinstance(ws_cur.get(key), list):
                    ws_cur[key] = list(dict.fromkeys(ws_cur[key] + val))
                else:
                    ws_cur[key] = val
            current["working_set"] = ws_cur
            patch = {k: v for k, v in patch.items() if k != "working_set"}

        current.update(patch)
        conv["context_state"] = current

        if goal is not None:
            conv["goal"] = goal
        if title is not None:
            conv["title"] = title
        conv["updated_at"] = datetime.utcnow().isoformat()

        if await self._db_available():
            await self._db_update_context(conversation_id, current, goal, title)

    # ── Anthropic Format Conversion ─────────────────────────────────────────

    async def get_anthropic_messages(
        self, conversation_id: str
    ) -> list[dict[str, Any]]:
        """Convert stored messages to Anthropic messages API format."""
        raw = await self.get_messages(conversation_id)
        api_messages: list[dict[str, Any]] = []

        for msg in raw:
            role = msg["role"]
            content = msg["content"]
            tool_calls = msg.get("tool_calls")
            tool_results = msg.get("tool_results")

            if role == "assistant" and tool_calls:
                blocks: list[dict[str, Any]] = []
                if content and isinstance(content, str):
                    blocks.append({"type": "text", "text": content})
                for tc in tool_calls:
                    blocks.append({
                        "type": "tool_use",
                        "id": tc["id"],
                        "name": tc["name"],
                        "input": tc.get("input", {}),
                    })
                api_messages.append({"role": "assistant", "content": blocks})
            elif role == "user" and tool_results:
                api_messages.append({"role": "user", "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": tr["tool_use_id"],
                        "content": str(tr.get("content", "")),
                    }
                    for tr in tool_results
                ]})
            else:
                text = content if isinstance(content, str) else str(content)
                api_messages.append({"role": role, "content": text})

        return api_messages

    # ── OpenAI Format Conversion ────────────────────────────────────────────

    async def get_openai_messages(
        self, conversation_id: str
    ) -> list[dict[str, Any]]:
        """Convert stored messages to OpenAI chat completion format."""
        import json as _json
        raw = await self.get_messages(conversation_id)
        api_messages: list[dict[str, Any]] = []

        for msg in raw:
            role = msg["role"]
            content = msg["content"] or ""
            tool_calls = msg.get("tool_calls")
            tool_results = msg.get("tool_results")

            if role == "assistant" and tool_calls:
                oai_msg: dict[str, Any] = {"role": "assistant", "content": content or None}
                oai_msg["tool_calls"] = [
                    {
                        "id": tc["id"],
                        "type": "function",
                        "function": {
                            "name": tc["name"],
                            "arguments": _json.dumps(tc.get("input", {}), default=str),
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
                        "content": str(tr.get("content", "")),
                    })
            else:
                text = content if isinstance(content, str) else str(content)
                api_messages.append({"role": role, "content": text})

        return api_messages

    # ── Context Window Management ───────────────────────────────────────────

    async def trim_to_budget(
        self, conversation_id: str, budget: Optional[int] = None
    ) -> None:
        """Trim oldest messages to stay under the token budget."""
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

        # Keep the first message; trim from the front of the rest
        first = messages[0]
        rest = messages[1:]

        while rest and total > budget:
            removed = rest.pop(0)
            total -= _estimate_message_tokens(removed)
            # Remove paired tool_result when we drop an assistant tool_call
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
            conversation_id, len(conv["messages"]), total,
        )
