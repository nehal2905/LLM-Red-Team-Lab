"""Structural heuristics — catch paraphrases that dodge exact signatures.

These look at *shape* rather than specific wording: role-swap framing,
source-enumeration intent, encoded blobs, an unusually high ratio of imperative
override verbs, and excessive length. Each fired heuristic contributes weight to
the risk score and helps attribute an attack class.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from src.common.types import AttackType


@dataclass(frozen=True)
class HeuristicMatch:
    heuristic_id: str
    attack_type: AttackType
    weight: int
    detail: str


# Precompiled cues
_ROLE_SWAP = re.compile(
    r"\b(you are|act|behave|respond|talk|reply)\b.{0,30}\b(as|like|now)\b", re.IGNORECASE
)
_OVERRIDE_VERBS = re.compile(
    r"\b(ignore|disregard|forget|override|bypass|skip|abandon)\b", re.IGNORECASE
)
_SOURCE_ENUM = re.compile(
    r"\b(all|every|each|complete|entire|full)\b.{0,20}\b(documents?|files?|sources?|records?|data)\b",
    re.IGNORECASE,
)
_BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_HEX_BLOB = re.compile(r"(?:[0-9a-fA-F]{2}\s*){16,}")
_SYSTEM_REF = re.compile(r"\b(system prompt|initial instructions|your (rules|instructions))\b", re.IGNORECASE)


def scan_heuristics(raw_text: str, normalized_text: str) -> list[HeuristicMatch]:
    matches: list[HeuristicMatch] = []
    text = normalized_text

    if _ROLE_SWAP.search(text):
        matches.append(
            HeuristicMatch("HEU-roleswap", AttackType.JAILBREAK, 25, "role-swap framing")
        )

    override_hits = len(_OVERRIDE_VERBS.findall(text))
    if override_hits >= 1:
        weight = min(15 + 10 * override_hits, 40)
        matches.append(
            HeuristicMatch(
                "HEU-override",
                AttackType.PROMPT_INJECTION,
                weight,
                f"{override_hits} instruction-override verb(s)",
            )
        )

    if _SOURCE_ENUM.search(text):
        matches.append(
            HeuristicMatch(
                "HEU-source-enum",
                AttackType.DATA_EXFILTRATION,
                30,
                "source-enumeration intent",
            )
        )

    if _SYSTEM_REF.search(text):
        matches.append(
            HeuristicMatch(
                "HEU-sysref",
                AttackType.PROMPT_INJECTION,
                25,
                "references system prompt/instructions",
            )
        )

    if _BASE64_BLOB.search(raw_text) or _HEX_BLOB.search(raw_text):
        matches.append(
            HeuristicMatch(
                "HEU-encoded",
                AttackType.PROMPT_INJECTION,
                25,
                "encoded blob (base64/hex) present",
            )
        )

    # Excessive length is a weak smuggling signal.
    if len(raw_text) > 1200:
        matches.append(
            HeuristicMatch(
                "HEU-length",
                AttackType.PROMPT_INJECTION,
                10,
                f"unusually long input ({len(raw_text)} chars)",
            )
        )

    return matches
