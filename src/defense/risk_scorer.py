"""L2 — Risk Scorer.

Owns the 0-100 risk math and the score -> severity -> action mapping. It is used
by the Detection Engine (to fill in ``DetectionResult.risk_score`` / severity)
and by the Guardrails (to decide enforcement). Keeping the math here means there
is exactly one place that defines "how risky is this".

Thresholds come from config:
    < flag           -> LOW      (allow)
    flag .. block-1  -> MEDIUM   (flag)
    block .. crit-1  -> HIGH     (block)
    >= critical      -> CRITICAL (block + alert)
"""

from __future__ import annotations

from config.settings import settings
from src.common.types import Action, Severity
from src.detection.heuristics import HeuristicMatch
from src.detection.signatures import SignatureMatch


def combine_score(
    signature_matches: list[SignatureMatch],
    heuristic_matches: list[HeuristicMatch],
    semantic_similarity: float | None = None,
) -> int:
    """Combine weighted signals into a 0-100 risk score.

    Signature and heuristic weights add up (with diminishing returns past the
    first strong hit so a single phrase doesn't always saturate). Semantic
    similarity, when present, contributes proportionally above the threshold.
    """
    score = 0.0

    sig_weights = sorted((m.weight for m in signature_matches), reverse=True)
    for i, w in enumerate(sig_weights):
        score += w * (1.0 if i == 0 else 0.5)  # diminishing returns

    heur_weights = sorted((m.weight for m in heuristic_matches), reverse=True)
    for i, w in enumerate(heur_weights):
        score += w * (1.0 if i == 0 else 0.4)

    if semantic_similarity is not None:
        thr = settings.semantic_similarity_threshold
        if semantic_similarity >= thr:
            # Map [thr, 1.0] -> [0, 35] bonus.
            span = max(1e-6, 1.0 - thr)
            score += 35.0 * (semantic_similarity - thr) / span

    return int(max(0, min(100, round(score))))


def severity_for_score(score: int) -> Severity:
    if score >= settings.threshold_critical:
        return Severity.CRITICAL
    if score >= settings.threshold_block:
        return Severity.HIGH
    if score >= settings.threshold_flag:
        return Severity.MEDIUM
    return Severity.LOW


def action_for_severity(severity: Severity) -> Action:
    """Enforcement disposition for a severity (used when defenses are ON)."""
    if severity in (Severity.HIGH, Severity.CRITICAL):
        return Action.BLOCK
    if severity is Severity.MEDIUM:
        return Action.FLAG
    return Action.ALLOW


def should_block(severity: Severity) -> bool:
    return severity.rank >= Severity.HIGH.rank
