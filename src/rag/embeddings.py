"""Embedding backend with an Ollama-first, sentence-transformers-fallback design.

Heavy imports (``ollama``, ``sentence_transformers``) are deferred to call time
so that importing the rest of the lab (types, detection, defense) never requires
them. This keeps unit tests fast and dependency-light.
"""

from __future__ import annotations

import logging

from config.settings import settings

log = logging.getLogger(__name__)


class Embedder:
    """Embeds text via Ollama, transparently falling back to a local
    sentence-transformers model if Ollama is unavailable."""

    def __init__(
        self,
        backend: str | None = None,
        model: str | None = None,
        fallback_model: str | None = None,
    ) -> None:
        self.backend = backend or settings.embedding_backend
        self.model = model or settings.embedding_model
        self.fallback_model = fallback_model or settings.embedding_fallback_model
        self._st_model = None  # lazily loaded sentence-transformers model
        self._using_fallback = self.backend != "ollama"

    # --- public API ---
    def embed_texts(self, texts: list[str]) -> list[list[float]]:
        if not self._using_fallback:
            try:
                return [self._ollama_embed(t) for t in texts]
            except Exception as exc:  # noqa: BLE001 - any failure -> fallback
                log.warning("Ollama embeddings failed (%s); using local fallback", exc)
                self._using_fallback = True
        return self._st_embed(texts)

    def embed_query(self, text: str) -> list[float]:
        return self.embed_texts([text])[0]

    @property
    def active_backend(self) -> str:
        return "sentence_transformers" if self._using_fallback else "ollama"

    # --- backends ---
    def _ollama_embed(self, text: str) -> list[float]:
        import ollama  # deferred

        client = ollama.Client(host=settings.llm_ollama_host)
        resp = client.embeddings(model=self.model, prompt=text)
        return list(resp["embedding"])

    def _st_embed(self, texts: list[str]) -> list[list[float]]:
        if self._st_model is None:
            from sentence_transformers import SentenceTransformer  # deferred

            model_name = self.fallback_model.replace("sentence-transformers/", "")
            self._st_model = SentenceTransformer(
                self.fallback_model
                if "/" in self.fallback_model
                else f"sentence-transformers/{model_name}"
            )
        vectors = self._st_model.encode(texts, normalize_embeddings=True)
        return [v.tolist() for v in vectors]
