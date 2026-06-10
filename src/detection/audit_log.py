"""Structured JSONL audit log — one line per analyzed event.

This is the raw material for the dashboard and the README charts. Logging is
**always on**, independent of whether defenses enforce, which is what lets the
lab run in monitor-only mode and still measure detection quality.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path

import structlog

from config.settings import settings
from src.common.types import DetectionResult, Response

_LOCK = threading.Lock()

# Configure structlog once for nice console rendering during interactive runs.
structlog.configure(
    processors=[
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ],
)
_console = structlog.get_logger("redteam.audit")


class AuditLogger:
    def __init__(self, path: Path | None = None, echo: bool = False) -> None:
        self.path = Path(path or settings.audit_log_path)
        self.echo = echo
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def log_event(self, event: dict) -> dict:
        event.setdefault("ts", datetime.now(timezone.utc).isoformat())
        line = json.dumps(event, default=str)
        with _LOCK:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        if self.echo:
            _console.info("audit_event", **event)
        return event

    def log_request(
        self,
        *,
        session: str,
        mode: str,
        raw_input: str,
        normalized: str,
        detection: DetectionResult,
        stage: str = "input",
    ) -> dict:
        return self.log_event(
            {
                "stage": stage,
                "session": session,
                "mode": mode,
                "raw_input": raw_input,
                "normalized": normalized,
                "attack_type": detection.attack_type.value,
                "risk_score": detection.risk_score,
                "severity": detection.severity.value,
                "matched": detection.matched,
                "rationale": detection.rationale,
            }
        )

    def log_response(
        self,
        *,
        session: str,
        mode: str,
        detection: DetectionResult,
        response: Response,
        stage: str = "output",
    ) -> dict:
        return self.log_event(
            {
                "stage": stage,
                "session": session,
                "mode": mode,
                "attack_type": detection.attack_type.value,
                "risk_score": detection.risk_score,
                "severity": detection.severity.value,
                "matched": detection.matched,
                "action": response.action.value,
                "retrieved_sources": [c.source for c in response.retrieved],
                "withheld_sources": response.withheld_sources,
                "leaked_canaries": response.leaked_canaries,
                "redactions": response.redactions,
                "latency_ms": response.latency_ms,
            }
        )
