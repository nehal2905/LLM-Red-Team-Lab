"""Top-k retrieval over the Chroma collection.

Returns :class:`Chunk` objects carrying the all-important ``sensitivity`` tag so
downstream layers (the L3 Context Guard) can make trust decisions. The retriever
deliberately returns *everything* it finds — filtering by sensitivity is the
guard's job, not the retriever's. This keeps the security control in one place.
"""

from __future__ import annotations

import logging

from config.settings import settings
from src.common.types import Chunk
from src.rag.embeddings import Embedder

log = logging.getLogger(__name__)


class Retriever:
    def __init__(self, embedder: Embedder | None = None) -> None:
        self._embedder = embedder
        self._collection = None

    @property
    def embedder(self) -> Embedder:
        if self._embedder is None:
            self._embedder = Embedder()
        return self._embedder

    def _get_collection(self):
        if self._collection is None:
            import chromadb  # deferred

            client = chromadb.PersistentClient(path=str(settings.chroma_dir))
            self._collection = client.get_collection(settings.chroma_collection)
        return self._collection

    def retrieve(self, query: str, top_k: int | None = None) -> list[Chunk]:
        top_k = top_k or settings.retriever_top_k
        collection = self._get_collection()
        q_emb = self.embedder.embed_query(query)
        res = collection.query(
            query_embeddings=[q_emb],
            n_results=top_k,
            include=["documents", "metadatas", "distances"],
        )
        docs = res.get("documents", [[]])[0]
        metas = res.get("metadatas", [[]])[0]
        dists = res.get("distances", [[]])[0]

        chunks: list[Chunk] = []
        for text, meta, dist in zip(docs, metas, dists):
            meta = meta or {}
            # cosine distance -> similarity score in [0, 1]
            score = max(0.0, 1.0 - float(dist))
            chunks.append(
                Chunk(
                    text=text,
                    source=meta.get("source", "unknown"),
                    sensitivity=meta.get("sensitivity", "public"),
                    score=round(score, 4),
                )
            )
        return chunks
