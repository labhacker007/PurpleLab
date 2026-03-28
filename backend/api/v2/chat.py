"""Chat endpoint — SSE streaming for agentic conversation.

POST /api/v2/chat streams responses as Server-Sent Events, enabling
real-time tool calls, intermediate results, and final answers.
"""
from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import StreamingResponse

from backend.core.schemas import ChatRequest, ChatChunk, StatusResponse

router = APIRouter(prefix="/chat", tags=["chat"])


@router.post("", response_model=None)
async def chat(request: ChatRequest):
    """Stream an agentic chat response via SSE.

    The agent will:
    1. Analyze the user's request
    2. Select and execute appropriate tools
    3. Stream intermediate results and final answer

    TODO: Wire up AgentOrchestrator for actual LLM calls and tool execution.
    TODO: Implement SSE streaming with proper event format.
    TODO: Add conversation history persistence via ConversationManager.
    """
    # TODO: Replace placeholder with actual agent orchestration
    async def _placeholder_stream():
        import json
        chunk = ChatChunk(
            type="text",
            content="Agent chat is not yet implemented. This is a placeholder response.",
        )
        yield f"data: {json.dumps(chunk.model_dump())}\n\n"
        done = ChatChunk(type="done")
        yield f"data: {json.dumps(done.model_dump())}\n\n"

    return StreamingResponse(
        _placeholder_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/conversations")
async def list_conversations():
    """List all conversations.

    TODO: Query database for conversation list with pagination.
    """
    return {"conversations": [], "total": 0}


@router.get("/conversations/{conversation_id}")
async def get_conversation(conversation_id: str):
    """Get a conversation with its full message history.

    TODO: Fetch from database with message ordering.
    """
    return {"conversation_id": conversation_id, "messages": [], "title": ""}


@router.delete("/conversations/{conversation_id}")
async def delete_conversation(conversation_id: str):
    """Delete a conversation and all its messages.

    TODO: Cascade delete via database.
    """
    return StatusResponse(status="deleted")
