"use client"

import { create } from "zustand"
import type { Conversation, Message } from "@/types"

interface ChatState {
  conversations: Conversation[]
  activeConversationId: string | null
  isStreaming: boolean

  setConversations: (conversations: Conversation[]) => void
  setActiveConversation: (id: string | null) => void
  addConversation: (conversation: Conversation) => void
  addMessage: (conversationId: string, message: Message) => void
  appendToLastMessage: (conversationId: string, token: string) => void
  setStreaming: (streaming: boolean) => void
}

export const useChatStore = create<ChatState>((set) => ({
  conversations: [],
  activeConversationId: null,
  isStreaming: false,

  setConversations: (conversations) => set({ conversations }),
  setActiveConversation: (id) => set({ activeConversationId: id }),

  addConversation: (conversation) =>
    set((state) => ({
      conversations: [conversation, ...state.conversations],
      activeConversationId: conversation.id,
    })),

  addMessage: (conversationId, message) =>
    set((state) => ({
      conversations: state.conversations.map((c) =>
        c.id === conversationId
          ? { ...c, messages: [...c.messages, message] }
          : c
      ),
    })),

  appendToLastMessage: (conversationId, token) =>
    set((state) => ({
      conversations: state.conversations.map((c) => {
        if (c.id !== conversationId) return c
        const msgs = [...c.messages]
        const last = msgs[msgs.length - 1]
        if (last && last.role === "assistant") {
          msgs[msgs.length - 1] = { ...last, content: last.content + token }
        }
        return { ...c, messages: msgs }
      }),
    })),

  setStreaming: (streaming) => set({ isStreaming: streaming }),
}))
