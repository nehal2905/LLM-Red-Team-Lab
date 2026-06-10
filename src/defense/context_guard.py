"""L3 — Context Guard (post-retrieval).

Drops chunks tagged ``confidential`` before they ever reach the LLM, unless the
caller holds an authorized role. This is the layer that defeats "print the
salary document" even when the prompt looks benign: the model simply never sees
the data, so it cannot leak it.

Authorization is intentionally a simple role check (a ``--role`` flag / UI
toggle) to demonstrate the control without building a real IAM system.
"""

from __future__ import annotations

from dataclasses import dataclass

from config.settings import settings
from src.common.types import Chunk, Sensitivity


@dataclass
class GuardResult:
    allowed: list[Chunk]
    withheld: list[Chunk]

    @property
    def withheld_sources(self) -> list[str]:
        # Deduped, order-preserving list of source names withheld.
        seen: dict[str, None] = {}
        for c in self.withheld:
            seen.setdefault(c.source, None)
        return list(seen.keys())


class ContextGuard:
    def __init__(self, authorized_roles: set[str] | None = None) -> None:
        self.authorized_roles = (
            authorized_roles
            if authorized_roles is not None
            else settings.authorized_role_set
        )

    def is_authorized(self, role: str | None) -> bool:
        return bool(role) and role.strip().lower() in self.authorized_roles

    def filter(self, chunks: list[Chunk], role: str | None) -> GuardResult:
        if self.is_authorized(role):
            return GuardResult(allowed=list(chunks), withheld=[])
        allowed, withheld = [], []
        for c in chunks:
            if c.sensitivity.lower() == Sensitivity.CONFIDENTIAL.value:
                withheld.append(c)
            else:
                allowed.append(c)
        return GuardResult(allowed=allowed, withheld=withheld)
