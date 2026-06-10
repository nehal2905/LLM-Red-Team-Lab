"""Optional semantic detector: similarity to a labeled payload library.

Catches novel phrasings that are *meaning*-close to known attacks but dodge both
signatures and structural heuristics. Gated behind
``settings.enable_semantic_detection`` so the lab runs fully without it (and
without paying the embedding cost on every request).
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass
from pathlib import Path

import yaml

from config.settings import settings
from src.common.types import AttackType

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class SemanticMatch:
    similarity: float
    attack_type: AttackType
    payload_id: str


def _cosine(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


class SemanticDetector:
    """Lazily embeds the attack payload library and scores inputs against it."""

    def __init__(self, payload_dir: Path | None = None) -> None:
        self.payload_dir = Path(payload_dir or settings.payload_dir)
        self._library: list[tuple[str, AttackType, list[float]]] | None = None
        self._embedder = None

    @property
    def enabled(self) -> bool:
        return settings.enable_semantic_detection

    def _load_library(self) -> None:
        from src.rag.embeddings import Embedder  # deferred

        self._embedder = Embedder()
        raw_texts: list[str] = []
        ids_types: list[tuple[str, AttackType]] = []
        for path in sorted(self.payload_dir.glob("*.yaml")):
            try:
                data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            except yaml.YAMLError:
                continue
            atk_name = data.get("attack_type", "none")
            try:
                atk = AttackType(atk_name)
            except ValueError:
                atk = AttackType.NONE
            if atk is AttackType.NONE:
                continue
            for p in data.get("payloads", []):
                text = p.get("text", "")
                if text:
                    raw_texts.append(text)
                    ids_types.append((p.get("id", "?"), atk))

        vectors = self._embedder.embed_texts(raw_texts) if raw_texts else []
        self._library = [
            (pid, atk, vec) for (pid, atk), vec in zip(ids_types, vectors)
        ]
        log.info("Semantic library loaded: %d payloads", len(self._library))

    def score(self, text: str) -> SemanticMatch | None:
        if not self.enabled:
            return None
        if self._library is None:
            try:
                self._load_library()
            except Exception as exc:  # noqa: BLE001
                log.warning("Semantic detector disabled (load failed: %s)", exc)
                self._library = []
        if not self._library:
            return None
        q = self._embedder.embed_query(text)
        best: SemanticMatch | None = None
        for pid, atk, vec in self._library:
            sim = _cosine(q, vec)
            if best is None or sim > best.similarity:
                best = SemanticMatch(round(sim, 4), atk, pid)
        if best and best.similarity >= settings.semantic_similarity_threshold:
            return best
        return None
