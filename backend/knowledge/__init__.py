"""Knowledge base — vector store, embeddings, and semantic search for security knowledge."""

from backend.knowledge.embeddings import EmbeddingProvider, EmbeddingService
from backend.knowledge.vector_store import VectorStore
from backend.knowledge.store import KnowledgeStore

__all__ = ["EmbeddingProvider", "EmbeddingService", "VectorStore", "KnowledgeStore"]
