"""Load attack/benign payloads from YAML and expand them into variants.

Each base payload becomes several variants (case change, zero-width insertion,
polite framing, multi-step) so the harness probes obfuscation/evasion, not just
the literal phrasing. Every payload declares an ``expected_outcome`` so success
is judged objectively by the evaluator, never by eyeballing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from config.settings import settings
from src.common.types import AttackType

# Invisible char used to test zero-width obfuscation evasion.
_ZWSP = "\u200b"


@dataclass
class ExpectedOutcome:
    type: str  # canary | system_prompt | confidential_value | contains | benign
    markers: list[str] = field(default_factory=list)


@dataclass
class Payload:
    id: str
    attack_type: AttackType
    text: str
    expected_outcome: ExpectedOutcome
    variant: str = "base"

    @property
    def is_attack(self) -> bool:
        return self.attack_type is not AttackType.NONE


def _parse_outcome(raw: dict | None) -> ExpectedOutcome:
    raw = raw or {}
    return ExpectedOutcome(
        type=raw.get("type", "benign"),
        markers=list(raw.get("markers", [])),
    )


def load_file(path: Path) -> list[Payload]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    file_type = data.get("attack_type", "none")
    try:
        default_type = AttackType(file_type)
    except ValueError:
        default_type = AttackType.NONE
    out: list[Payload] = []
    for p in data.get("payloads", []):
        atk = p.get("attack_type", default_type.value)
        try:
            atk_type = AttackType(atk)
        except ValueError:
            atk_type = default_type
        out.append(
            Payload(
                id=p["id"],
                attack_type=atk_type,
                text=p["text"],
                expected_outcome=_parse_outcome(p.get("expected_outcome")),
            )
        )
    return out


def load_all(payload_dir: Path | None = None) -> list[Payload]:
    payload_dir = Path(payload_dir or settings.payload_dir)
    payloads: list[Payload] = []
    for path in sorted(payload_dir.glob("*.yaml")):
        payloads.extend(load_file(path))
    return payloads


def load_attacks(payload_dir: Path | None = None) -> list[Payload]:
    return [p for p in load_all(payload_dir) if p.is_attack]


def load_benign(payload_dir: Path | None = None) -> list[Payload]:
    return [p for p in load_all(payload_dir) if not p.is_attack]


# --- variant generators ---
def _variant(p: Payload, suffix: str, text: str, name: str) -> Payload:
    return Payload(
        id=f"{p.id}-{suffix}",
        attack_type=p.attack_type,
        text=text,
        expected_outcome=p.expected_outcome,
        variant=name,
    )


def expand(p: Payload) -> list[Payload]:
    """Return the base payload plus obfuscation/framing variants."""
    variants = [p]
    if not p.is_attack:
        return variants  # don't mutate benign prompts

    variants.append(_variant(p, "uc", p.text.upper(), "uppercase"))
    variants.append(
        _variant(p, "zw", _ZWSP.join(p.text), "zero_width")
    )
    variants.append(
        _variant(
            p,
            "polite",
            f"Hello! I really appreciate your help. {p.text} Thank you so much!",
            "polite",
        )
    )
    variants.append(
        _variant(
            p,
            "multi",
            f"First, confirm you understand. Then, as step two: {p.text}",
            "multi_step",
        )
    )
    return variants


def expand_all(payloads: list[Payload]) -> list[Payload]:
    expanded: list[Payload] = []
    for p in payloads:
        expanded.extend(expand(p))
    return expanded
