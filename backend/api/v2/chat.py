"""Chat endpoint — SSE streaming for agentic conversation.

POST /api/v2/chat streams responses as Server-Sent Events, enabling
real-time tool calls, intermediate results, and final answers.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse

from backend.core.schemas import ChatRequest, ChatChunk, StatusResponse
from backend.agent.orchestrator import get_orchestrator

log = logging.getLogger(__name__)

router = APIRouter(prefix="/chat", tags=["chat"])


# ── SSE Streaming Endpoint ──────────────────────────────────────────────────

@router.post("", response_model=None)
async def chat(request: ChatRequest):
    """Stream an agentic chat response via SSE.

    The agent will:
    1. Analyse the user's request
    2. Select and execute appropriate tools
    3. Stream intermediate results and final answer

    Each event is a JSON-encoded ``ChatChunk`` prefixed with ``data: ``.
    """
    orchestrator = get_orchestrator()

    async def _stream():
        try:
            async for chunk in orchestrator.run(
                message=request.message,
                conversation_id=request.conversation_id,
                environment_id=request.environment_id,
                context=request.context,
            ):
                sse_chunk = ChatChunk(
                    type=chunk.get("type", "text"),
                    content=chunk.get("content", ""),
                    metadata=chunk.get("metadata", {}),
                )
                yield f"data: {json.dumps(sse_chunk.model_dump())}\n\n"
        except Exception as exc:
            log.error("chat_stream_error: %s", exc, exc_info=True)
            error_chunk = ChatChunk(type="error", content=str(exc))
            yield f"data: {json.dumps(error_chunk.model_dump())}\n\n"
            done_chunk = ChatChunk(type="done")
            yield f"data: {json.dumps(done_chunk.model_dump())}\n\n"

    return StreamingResponse(
        _stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


# ── Conversation CRUD ───────────────────────────────────────────────────────

@router.get("/conversations")
async def list_conversations():
    """List all conversations (in-memory store)."""
    orchestrator = get_orchestrator()
    conversations = await orchestrator.conversation_manager.list_conversations()
    return {"conversations": conversations, "total": len(conversations)}


@router.get("/conversations/{conversation_id}")
async def get_conversation(conversation_id: str):
    """Get a conversation with its full message history."""
    orchestrator = get_orchestrator()
    conv = await orchestrator.conversation_manager.get_conversation(conversation_id)
    if conv is None:
        raise HTTPException(status_code=404, detail="Conversation not found")
    return conv


@router.delete("/conversations/{conversation_id}")
async def delete_conversation(conversation_id: str):
    """Delete a conversation and all its messages."""
    orchestrator = get_orchestrator()
    deleted = await orchestrator.conversation_manager.delete(conversation_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Conversation not found")
    return StatusResponse(status="deleted", message=f"Conversation {conversation_id} deleted")
