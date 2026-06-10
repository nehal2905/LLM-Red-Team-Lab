"""L1 — Input Filter (pre-retrieval).

Normalizes user input so obfuscated injections can't slip past on formatting
alone, and runs a fast signature pre-screen. The heavy lifting (scoring,
attribution) is the Detection Engine's job; L1 just produces the normalized text
and a quick "did any signature fire" signal that the pipeline uses for logging
and early-exit decisions.
"""

from __future__ import annotations

from dataclasses import dataclass

from src.common.normalize import normalize_text
from src.detection.signatures import SignatureMatch, scan_signatures


@dataclass
class InputScreen:
    raw: str
    normalized: str
    prescreen_matches: list[SignatureMatch]

    @property
    def tripped(self) -> bool:
        return bool(self.prescreen_matches)


class InputFilter:
    def process(self, text: str) -> InputScreen:
        normalized = normalize_text(text)
        matches = scan_signatures(normalized)
        return InputScreen(raw=text, normalized=normalized, prescreen_matches=matches)
