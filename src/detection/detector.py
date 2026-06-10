"""Detection Engine — ensembles three detectors into one DetectionResult.

The detector is the heart of the "detection engineering" framing: it runs on
*every* request and response regardless of enforcement mode. It normalizes the
text, fires signatures + heuristics (+ optional semantic), delegates the 0-100
scoring to the Risk Scorer, attributes an attack class, and returns a single
:class:`DetectionResult`.
"""

from __future__ import annotations

from collections import defaultdict

from src.common.normalize import normalize_text
from src.common.types import AttackType, DetectionResult, Severity
from src.defense.risk_scorer import combine_score, severity_for_score
from src.detection.heuristics import scan_heuristics
from src.detection.semantic import SemanticDetector
from src.detection.signatures import scan_signatures


class Detector:
    def __init__(self, semantic: SemanticDetector | None = None) -> None:
        self._semantic = semantic if semantic is not None else SemanticDetector()

    def analyze(self, text: str) -> DetectionResult:
        normalized = normalize_text(text)

        sig_matches = scan_signatures(normalized)
        heur_matches = scan_heuristics(text, normalized)
        semantic_match = self._semantic.score(normalized) if text else None

        semantic_sim = semantic_match.similarity if semantic_match else None
        score = combine_score(sig_matches, heur_matches, semantic_sim)
        severity = severity_for_score(score)

        matched_ids: list[str] = [m.signature_id for m in sig_matches]
        matched_ids += [m.heuristic_id for m in heur_matches]
        if semantic_match:
            matched_ids.append(f"SEM-{semantic_match.payload_id}")

        attack_type = self._attribute_class(
            sig_matches, heur_matches, semantic_match, score
        )
        rationale = self._build_rationale(
            sig_matches, heur_matches, semantic_match, score, severity
        )

        return DetectionResult(
            attack_type=attack_type,
            risk_score=score,
            severity=severity,
            matched=matched_ids,
            rationale=rationale,
        )

    @staticmethod
    def _attribute_class(sig_matches, heur_matches, semantic_match, score) -> AttackType:
        if score < 1:
            return AttackType.NONE
        weights: dict[AttackType, int] = defaultdict(int)
        for m in sig_matches:
            weights[m.attack_type] += m.weight
        for m in heur_matches:
            weights[m.attack_type] += m.weight
        if semantic_match:
            weights[semantic_match.attack_type] += 20
        if not weights:
            return AttackType.NONE
        return max(weights.items(), key=lambda kv: kv[1])[0]

    @staticmethod
    def _build_rationale(sig_matches, heur_matches, semantic_match, score, severity) -> str:
        parts: list[str] = []
        if sig_matches:
            parts.append(
                "signatures: " + ", ".join(f"{m.signature_id}({m.description})" for m in sig_matches)
            )
        if heur_matches:
            parts.append(
                "heuristics: " + ", ".join(f"{m.heuristic_id}({m.detail})" for m in heur_matches)
            )
        if semantic_match:
            parts.append(
                f"semantic: near {semantic_match.payload_id} (sim={semantic_match.similarity})"
            )
        if not parts:
            return f"no detection signals; score={score} ({severity.value})"
        return f"score={score} ({severity.value}); " + "; ".join(parts)
