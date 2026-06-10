"""Versioned signature rules — the first detection layer.

Each signature has a stable ID, an attack class, a compiled regex, and a weight
(how much it contributes to the risk score). Signatures are deliberately broad
regexes over *normalized* text; paraphrase evasion is the heuristic layer's job.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from src.common.types import AttackType


@dataclass(frozen=True)
class Signature:
    id: str
    attack_type: AttackType
    pattern: re.Pattern
    weight: int
    description: str


@dataclass(frozen=True)
class SignatureMatch:
    signature_id: str
    attack_type: AttackType
    weight: int
    description: str


def _sig(id_: str, atk: AttackType, regex: str, weight: int, desc: str) -> Signature:
    return Signature(id_, atk, re.compile(regex, re.IGNORECASE), weight, desc)


# Rule set version — bump when rules change so logs are comparable across runs.
SIGNATURE_SET_VERSION = "2026.06.1"

SIGNATURES: list[Signature] = [
    # --- Prompt injection ---
    _sig("INJ-001", AttackType.PROMPT_INJECTION,
         r"ignore (all |any )?(the )?(previous|prior|above|earlier) (instructions|prompts|messages)",
         40, "ignore previous instructions"),
    _sig("INJ-002", AttackType.PROMPT_INJECTION,
         r"disregard (all |any )?(the )?(previous|prior|above) (instructions|rules)",
         40, "disregard previous instructions"),
    _sig("INJ-003", AttackType.PROMPT_INJECTION,
         r"(reveal|show|print|repeat|display|output) (me )?(your |the )?(system |initial |original )?(prompt|instructions|rules)",
         45, "reveal system prompt"),
    _sig("INJ-004", AttackType.PROMPT_INJECTION,
         r"developer (mode|message|override)",
         35, "developer mode"),
    _sig("INJ-005", AttackType.PROMPT_INJECTION,
         r"you are now\b",
         30, "role reassignment 'you are now'"),
    _sig("INJ-006", AttackType.PROMPT_INJECTION,
         r"new instructions?\s*[:\-]",
         30, "injected new instructions"),
    _sig("INJ-007", AttackType.PROMPT_INJECTION,
         r"\bsystem\s*prompt\b",
         25, "mentions system prompt"),

    # --- Data exfiltration ---
    _sig("EXF-001", AttackType.DATA_EXFILTRATION,
         r"list (all |every )?(the )?(documents|files|sources|chunks)",
         40, "enumerate documents/sources"),
    _sig("EXF-002", AttackType.DATA_EXFILTRATION,
         r"\bdump\b|\bexfiltrate\b",
         40, "dump/exfiltrate keyword"),
    _sig("EXF-003", AttackType.DATA_EXFILTRATION,
         r"print (out )?(the )?(contents|content|everything|all data)",
         40, "print the contents"),
    _sig("EXF-004", AttackType.DATA_EXFILTRATION,
         r"what (data|documents|files|sources) do you have (access to)?",
         35, "what data do you have"),
    _sig("EXF-005", AttackType.DATA_EXFILTRATION,
         r"\b(salary|salaries|compensation|payroll)\b",
         45, "asks about confidential compensation"),
    _sig("EXF-006", AttackType.DATA_EXFILTRATION,
         r"\b(confidential|canary|watermark token)\b",
         40, "references confidential/canary material"),
    _sig("EXF-007", AttackType.DATA_EXFILTRATION,
         r"\bssn\b|social security",
         40, "asks for SSN/PII"),

    # --- Jailbreak ---
    _sig("JBK-001", AttackType.JAILBREAK,
         r"\bact as\b|\bpretend (to be|you are|that you are)\b|\broleplay\b",
         35, "act as / pretend persona"),
    _sig("JBK-002", AttackType.JAILBREAK,
         r"ignore (your |all )?(safety|guidelines|guardrails|restrictions|policies)",
         45, "ignore safety/guardrails"),
    _sig("JBK-003", AttackType.JAILBREAK,
         r"no longer (a |an )?(company |internal )?(assistant|ai)",
         40, "abandon assistant role"),
    _sig("JBK-004", AttackType.JAILBREAK,
         r"\bdan\b|do anything now|jailbreak",
         45, "DAN / jailbreak persona"),
    _sig("JBK-005", AttackType.JAILBREAK,
         r"without (any )?(restrictions|filters|limitations|rules)",
         35, "operate without restrictions"),
    _sig("JBK-006", AttackType.JAILBREAK,
         r"\bunfiltered\b|\bunrestricted\b|\bunlocked\b mode",
         35, "unfiltered/unrestricted mode"),
]


def scan_signatures(normalized_text: str) -> list[SignatureMatch]:
    """Return all signatures that match the normalized text."""
    matches: list[SignatureMatch] = []
    for sig in SIGNATURES:
        if sig.pattern.search(normalized_text):
            matches.append(
                SignatureMatch(sig.id, sig.attack_type, sig.weight, sig.description)
            )
    return matches
