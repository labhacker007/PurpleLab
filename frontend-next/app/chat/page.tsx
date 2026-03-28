"use client"

import { useState, useRef, useEffect } from "react"
import { Send, Plus, Bot, User, ChevronDown, ChevronRight, Loader2 } from "lucide-react"
import { Button } from "@/components/ui/button"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Card } from "@/components/ui/card"
import { cn } from "@/lib/utils"
import { useChatStore } from "@/stores/chat"
import type { Message, ToolCall, Conversation } from "@/types"

function generateId(): string {
  return Math.random().toString(36).slice(2, 14)
}

function newConversation(): Conversation {
  const now = new Date().toISOString()
  return {
    id: generateId(),
    title: "New Conversation",
    messages: [],
    created_at: now,
    updated_at: now,
  }
}

export default function ChatPage() {
  const {
    conversations,
    activeConversationId,
    isStreaming,
    setActiveConversation,
    addConversation,
    addMessage,
    setStreaming,
  } = useChatStore()

  const [input, setInput] = useState("")
  const messagesEndRef = useRef<HTMLDivElement>(null)

  const activeConv = conversations.find((c) => c.id === activeConversationId)

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" })
  }, [activeConv?.messages])

  function handleNewChat() {
    const conv = newConversation()
    addConversation(conv)
  }

  async function handleSend() {
    if (!input.trim() || isStreaming) return
    let conv = activeConv
    if (!conv) {
      conv = newConversation()
      addConversation(conv)
    }

    const userMsg: Message = {
      id: generateId(),
      role: "user",
      content: input.trim(),
      created_at: new Date().toISOString(),
    }
    addMessage(conv.id, userMsg)
    setInput("")

    // Placeholder: assistant response
    setStreaming(true)
    setTimeout(() => {
      const assistantMsg: Message = {
        id: generateId(),
        role: "assistant",
        content:
          "I'm the PurpleLab assistant. This is a placeholder response. Once the backend chat API is connected, I'll be able to help you build environments, import rules, and test detection coverage.",
        created_at: new Date().toISOString(),
      }
      addMessage(conv!.id, assistantMsg)
      setStreaming(false)
    }, 1000)
  }

  function handleKeyDown(e: React.KeyboardEvent) {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault()
      handleSend()
    }
  }

  return (
    <div className="flex h-full -m-6">
      {/* Conversation list */}
      <div className="w-64 border-r border-border bg-card flex flex-col">
        <div className="p-3 border-b border-border">
          <Button variant="outline" size="sm" className="w-full" onClick={handleNewChat}>
            <Plus className="h-4 w-4" />
            New Chat
          </Button>
        </div>
        <ScrollArea className="flex-1 p-2">
          {conversations.length === 0 ? (
            <p className="text-xs text-muted text-center py-8">No conversations yet</p>
          ) : (
            conversations.map((conv) => (
              <button
                key={conv.id}
                onClick={() => setActiveConversation(conv.id)}
                className={cn(
                  "w-full text-left rounded-lg px-3 py-2.5 text-sm mb-1 transition-colors",
                  conv.id === activeConversationId
                    ? "bg-primary/10 text-primary"
                    : "text-muted hover:text-text hover:bg-bg"
                )}
              >
                <div className="truncate font-medium">{conv.title}</div>
                <div className="text-[10px] text-muted mt-0.5">
                  {conv.messages.length} messages
                </div>
              </button>
            ))
          )}
        </ScrollArea>
      </div>

      {/* Message area */}
      <div className="flex-1 flex flex-col">
        {!activeConv ? (
          <div className="flex-1 flex items-center justify-center">
            <div className="text-center">
              <Bot className="h-12 w-12 text-muted mx-auto mb-4" />
              <h2 className="text-lg font-semibold text-text">PurpleLab Assistant</h2>
              <p className="text-sm text-muted mt-1 max-w-md">
                Ask me to build security environments, import detection rules, simulate threat
                actors, or analyze coverage gaps.
              </p>
              <Button className="mt-4" onClick={handleNewChat}>
                Start a conversation
              </Button>
            </div>
          </div>
        ) : (
          <>
            {/* Messages */}
            <ScrollArea className="flex-1 p-6">
              <div className="max-w-3xl mx-auto space-y-6">
                {activeConv.messages.map((msg) => (
                  <MessageBubble key={msg.id} message={msg} />
                ))}
                {isStreaming && (
                  <div className="flex items-center gap-2 text-muted text-sm">
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Thinking...
                  </div>
                )}
                <div ref={messagesEndRef} />
              </div>
            </ScrollArea>

            {/* Input */}
            <div className="border-t border-border bg-card p-4">
              <div className="max-w-3xl mx-auto flex gap-3">
                <textarea
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  onKeyDown={handleKeyDown}
                  placeholder="Describe what you want to build or test..."
                  rows={1}
                  className="flex-1 resize-none rounded-lg border border-border bg-bg px-4 py-3 text-sm text-text placeholder:text-muted focus:outline-none focus:ring-2 focus:ring-primary"
                />
                <Button
                  onClick={handleSend}
                  disabled={!input.trim() || isStreaming}
                  className="self-end"
                >
                  <Send className="h-4 w-4" />
                </Button>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  )
}

function MessageBubble({ message }: { message: Message }) {
  const isUser = message.role === "user"
  return (
    <div className={cn("flex gap-3", isUser && "justify-end")}>
      {!isUser && (
        <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-primary/10">
          <Bot className="h-4 w-4 text-primary" />
        </div>
      )}
      <div
        className={cn(
          "rounded-xl px-4 py-3 text-sm max-w-[80%]",
          isUser ? "bg-primary text-white" : "bg-card border border-border"
        )}
      >
        <p className="whitespace-pre-wrap">{message.content}</p>
        {message.tool_calls && message.tool_calls.length > 0 && (
          <div className="mt-3 space-y-2">
            {message.tool_calls.map((tc) => (
              <ToolCallCard key={tc.id} toolCall={tc} />
            ))}
          </div>
        )}
      </div>
      {isUser && (
        <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-muted/20">
          <User className="h-4 w-4 text-muted" />
        </div>
      )}
    </div>
  )
}

function ToolCallCard({ toolCall }: { toolCall: ToolCall }) {
  const [expanded, setExpanded] = useState(false)
  return (
    <Card className="bg-bg border-border">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center gap-2 px-3 py-2 text-xs text-muted"
      >
        {expanded ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
        <span className="font-mono font-medium">{toolCall.name}</span>
        <span
          className={cn(
            "ml-auto text-[10px]",
            toolCall.status === "completed" ? "text-green" : "text-amber"
          )}
        >
          {toolCall.status}
        </span>
      </button>
      {expanded && (
        <div className="px-3 pb-2 text-xs">
          <pre className="bg-bg rounded p-2 overflow-auto text-muted">
            {JSON.stringify(toolCall.arguments, null, 2)}
          </pre>
          {toolCall.result && (
            <pre className="bg-bg rounded p-2 mt-1 overflow-auto text-green">
              {toolCall.result}
            </pre>
          )}
        </div>
      )}
    </Card>
  )
}
