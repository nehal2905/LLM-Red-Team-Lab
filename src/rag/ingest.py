"""Corpus -> chunks -> embeddings -> ChromaDB.

Each chunk is tagged with the *sensitivity* of its source document. The
sensitivity drives the L3 Context Guard at query time, so getting it right at
ingest is a security control, not just metadata.

Run as a script:
    python -m src.rag.ingest
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from config.settings import settings
from src.rag.embeddings import Embedder

log = logging.getLogger(__name__)

_SENSITIVITY_RE = re.compile(r"<!--\s*sensitivity:\s*(\w+)\s*-->", re.IGNORECASE)


def detect_sensitivity(path: Path, content: str) -> str:
    """Determine a document's sensitivity from its header comment, with a
    filename-based fallback ("CONFIDENTIAL" in the name -> confidential)."""
    m = _SENSITIVITY_RE.search(content)
    if m:
        return m.group(1).lower()
    name = path.name.upper()
    if "CONFIDENTIAL" in name:
        return "confidential"
    if "INTERNAL" in name:
        return "internal"
    return "public"


def chunk_text(text: str, size: int, overlap: int) -> list[str]:
    """Lightweight paragraph-aware splitter (keeps LangChain coupling thin).

    Splits on blank lines, then packs paragraphs into ~``size``-char windows
    with ``overlap`` characters of trailing context carried forward.
    """
    paras = [p.strip() for p in re.split(r"\n\s*\n", text) if p.strip()]
    chunks: list[str] = []
    buf = ""
    for para in paras:
        if buf and len(buf) + len(para) + 2 > size:
            chunks.append(buf.strip())
            tail = buf[-overlap:] if overlap > 0 else ""
            buf = (tail + "\n\n" + para).strip()
        else:
            buf = (buf + "\n\n" + para).strip() if buf else para
    if buf.strip():
        chunks.append(buf.strip())
    return chunks or ([text.strip()] if text.strip() else [])


def load_corpus(corpus_dir: Path | None = None) -> list[dict]:
    """Return a list of {text, source, sensitivity, chunk_id} records."""
    corpus_dir = Path(corpus_dir or settings.corpus_dir)
    records: list[dict] = []
    for path in sorted(corpus_dir.glob("*.md")):
        content = path.read_text(encoding="utf-8")
        sensitivity = detect_sensitivity(path, content)
        for i, chunk in enumerate(
            chunk_text(content, settings.chunk_size, settings.chunk_overlap)
        ):
            records.append(
                {
                    "text": chunk,
                    "source": path.name,
                    "sensitivity": sensitivity,
                    "chunk_id": f"{path.stem}:{i}",
                }
            )
    return records


def ingest(corpus_dir: Path | None = None, reset: bool = True) -> int:
    """Embed the corpus and (re)build the Chroma collection. Returns chunk count."""
    import chromadb  # deferred heavy import

    settings.ensure_dirs()
    records = load_corpus(corpus_dir)
    if not records:
        log.warning("No corpus documents found in %s", corpus_dir or settings.corpus_dir)
        return 0

    embedder = Embedder()
    embeddings = embedder.embed_texts([r["text"] for r in records])

    client = chromadb.PersistentClient(path=str(settings.chroma_dir))
    if reset:
        try:
            client.delete_collection(settings.chroma_collection)
        except Exception:  # noqa: BLE001 - collection may not exist yet
            pass
    collection = client.get_or_create_collection(
        name=settings.chroma_collection, metadata={"hnsw:space": "cosine"}
    )

    collection.add(
        ids=[r["chunk_id"] for r in records],
        documents=[r["text"] for r in records],
        embeddings=embeddings,
        metadatas=[
            {"source": r["source"], "sensitivity": r["sensitivity"]} for r in records
        ],
    )
    log.info(
        "Ingested %d chunks from %d docs (backend=%s)",
        len(records),
        len({r["source"] for r in records}),
        embedder.active_backend,
    )
    return len(records)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    n = ingest()
    print(f"Ingested {n} chunks into collection '{settings.chroma_collection}'.")


if __name__ == "__main__":
    main()
