"""Text normalization shared by the L1 Input Filter and the Detection Engine.

Obfuscated injections often rely on formatting tricks (zero-width characters,
homoglyph spacing, weird casing). Normalizing before matching means a single
signature catches "ignore previous instructions", "Ignore  Previous Instructions",
and "ignore\u200bprevious instructions" alike.
"""

from __future__ import annotations

import re
import unicodedata

# Zero-width and other invisible/format characters frequently used to evade.
_ZERO_WIDTH = dict.fromkeys(
    [
        0x200B,  # zero width space
        0x200C,  # zero width non-joiner
        0x200D,  # zero width joiner
        0x2060,  # word joiner
        0xFEFF,  # zero width no-break space
        0x00AD,  # soft hyphen
    ]
)

_WS_RE = re.compile(r"\s+")


def normalize_text(text: str) -> str:
    """Return a canonical, lowercase form suitable for signature matching.

    Steps: unicode NFKC fold -> strip zero-width chars -> collapse whitespace ->
    lowercase. The original text is never mutated in place; callers keep the raw
    string for logging and pass the normalized copy to matchers.
    """
    if not text:
        return ""
    folded = unicodedata.normalize("NFKC", text)
    folded = folded.translate(_ZERO_WIDTH)
    folded = _WS_RE.sub(" ", folded).strip()
    return folded.lower()
