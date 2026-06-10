"""Core data contracts for the whole lab.

Everything else depends on these types, so they are defined first. They are
intentionally plain dataclasses/enums (no pydantic) to keep them cheap to
construct in hot loops and trivial to serialize for the audit log.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum


class AttackType(str, Enum):
    NONE = "none"
    PROMPT_INJECTION = "prompt_injection"
    DATA_EXFILTRATION = "data_exfiltration"
    JAILBREAK = "jailbreak"


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}[self.value]


class Action(str, Enum):
    ALLOW = "allow"
    FLAG = "flag"
    BLOCK = "block"
    REDACT = "redact"


class Sensitivity(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"


@dataclass
class DetectionResult:
    attack_type: AttackType
    risk_score: int  # 0-100
    severity: Severity
    matched: list[str] = field(default_factory=list)  # signature/heuristic IDs
    rationale: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["attack_type"] = self.attack_type.value
        d["severity"] = self.severity.value
        return d


@dataclass
class Chunk:
    text: str
    source: str
    sensitivity: str  # "public" | "internal" | "confidential"
    score: float = 0.0

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Response:
    answer: str
    action: Action  # final disposition
    detection: DetectionResult
    retrieved: list[Chunk] = field(default_factory=list)
    leaked_canaries: list[str] = field(default_factory=list)
    redactions: list[str] = field(default_factory=list)
    withheld_sources: list[str] = field(default_factory=list)
    latency_ms: float = 0.0

    def to_dict(self) -> dict:
        return {
            "answer": self.answer,
            "action": self.action.value,
            "detection": self.detection.to_dict(),
            "retrieved": [c.to_dict() for c in self.retrieved],
            "leaked_canaries": list(self.leaked_canaries),
            "redactions": list(self.redactions),
            "withheld_sources": list(self.withheld_sources),
            "latency_ms": self.latency_ms,
        }
