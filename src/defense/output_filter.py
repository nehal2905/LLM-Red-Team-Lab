"""L4 — Output Filter (post-generation).

Scans the model's answer for:
  * embedded canary tokens   -> proven leak; BLOCK outright.
  * verbatim system-prompt leakage (the sentinel / distinctive prompt phrases)
        -> BLOCK outright.
  * PII / secrets (emails, phones, SSN-shaped, salary figures, fake bank refs)
        -> REDACT in place and tag.

Canary or prompt leakage is treated as block-worthy because it means a control
upstream already failed; redaction is for softer PII exposure.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from src.common import canary
from src.rag.llm import SYSTEM_PROMPT_SENTINEL

# Distinctive phrases from the hardened system prompt; appearance == leak.
_PROMPT_LEAK_PHRASES = (
    SYSTEM_PROMPT_SENTINEL.lower(),
    "security rules (non-negotiable",
    "you are acme dynamics' internal documentation assistant",
)

_PII_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("EMAIL", re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")),
    ("SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("PHONE", re.compile(r"\b(?:\+?\d{1,2}[\s.\-]?)?(?:\(?\d{3}\)?[\s.\-]?)?\d{3}[\s.\-]\d{4}\b")),
    ("SALARY", re.compile(r"\$\s?\d{1,3}(?:,\d{3})+(?:\.\d+)?")),
    ("BANK_REF", re.compile(r"\bACME-PAYROLL-\d+\b")),
]


@dataclass
class OutputScan:
    text: str
    redactions: list[str] = field(default_factory=list)
    leaked_canaries: list[str] = field(default_factory=list)
    system_prompt_leak: bool = False

    @property
    def block(self) -> bool:
        return bool(self.leaked_canaries) or self.system_prompt_leak

    @property
    def redacted(self) -> bool:
        return bool(self.redactions)


class OutputFilter:
    def scan(self, answer: str) -> OutputScan:
        leaked = canary.scan(answer)

        low = answer.lower()
        prompt_leak = any(p in low for p in _PROMPT_LEAK_PHRASES)

        redacted_text = answer
        redactions: list[str] = []
        for label, pattern in _PII_PATTERNS:
            if pattern.search(redacted_text):
                redactions.append(label)
                redacted_text = pattern.sub(f"[REDACTED:{label}]", redacted_text)

        return OutputScan(
            text=redacted_text,
            redactions=redactions,
            leaked_canaries=leaked,
            system_prompt_leak=prompt_leak,
        )
