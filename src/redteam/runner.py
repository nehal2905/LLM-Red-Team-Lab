"""Red-team runner — fires every payload across both modes and records results.

For each payload it calls ``pipeline.run`` once with defenses OFF and once with
defenses ON, judges success against the payload's ``expected_outcome``, and
writes one JSONL row per (payload, mode). Benign prompts are included so the
evaluator can measure how often defenses wrongly block legitimate questions.

Run as a script:
    python -m src.redteam.runner            # full run + report + charts
    python -m src.redteam.runner --no-expand # base payloads only
"""

from __future__ import annotations

import argparse
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from config.settings import settings
from src.common.types import Response
from src.defense.guardrails import DEFENSE_OFF, DEFENSE_ON
from src.rag.pipeline import RAGPipeline
from src.redteam import evaluator
from src.redteam.payloads import Payload, expand_all, load_all

log = logging.getLogger(__name__)


def _row(payload: Payload, mode: str, resp: Response) -> dict:
    return {
        "payload_id": payload.id,
        "attack_type": payload.attack_type.value,
        "is_attack": payload.is_attack,
        "variant": payload.variant,
        "mode": mode,
        "expected_type": payload.expected_outcome.type,
        "action": resp.action.value,
        "severity": resp.detection.severity.value,
        "risk_score": resp.detection.risk_score,
        "matched": resp.detection.matched,
        "flagged": evaluator.flagged_high_plus(resp),
        "blocked": evaluator.was_blocked(resp),
        "success": evaluator.attack_succeeded(payload, resp),
        "leaked_canaries": resp.leaked_canaries,
        "withheld_sources": resp.withheld_sources,
        "retrieved_sources": [c.source for c in resp.retrieved],
        "latency_ms": resp.latency_ms,
        "answer_preview": (resp.answer or "")[:240],
    }


def run_all(
    pipeline: RAGPipeline | None = None,
    *,
    payload_dir: Path | None = None,
    expand_variants: bool = True,
    role: str | None = None,
    out_path: Path | None = None,
) -> list[dict]:
    pipeline = pipeline or RAGPipeline()
    payloads = load_all(payload_dir)
    if expand_variants:
        payloads = expand_all(payloads)

    rows: list[dict] = []
    for p in payloads:
        for mode in (DEFENSE_OFF, DEFENSE_ON):
            resp = pipeline.run(p.text, mode=mode, role=role, session=f"{p.id}:{mode}")
            rows.append(_row(p, mode, resp))

    settings.ensure_dirs()
    if out_path is None:
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        out_path = settings.runs_dir / f"run_{ts}.jsonl"
    with Path(out_path).open("w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, default=str) + "\n")
    log.info("Wrote %d rows to %s", len(rows), out_path)
    return rows


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    parser = argparse.ArgumentParser(description="Run the red-team harness.")
    parser.add_argument("--no-expand", action="store_true", help="Base payloads only.")
    parser.add_argument("--role", default=None, help="Caller role for L3 demo.")
    args = parser.parse_args()

    rows = run_all(expand_variants=not args.no_expand, role=args.role)
    metrics = evaluator.compute_metrics(rows)
    report = evaluator.save_report(metrics)
    charts = evaluator.render_charts(metrics)

    print("\n=== Results ===")
    print(metrics.to_string(index=False))
    print(f"\nReport: {report}")
    for c in charts:
        print(f"Chart:  {c}")


if __name__ == "__main__":
    main()
