"""Guardrails — chains L1 -> L4 and returns the final Response.

Enforcement is governed solely by ``mode``:
  * ``defense_off`` — the Detection Engine still analyzes and logs every request
    and response, but nothing is ever blocked, withheld, or redacted. This is
    "monitor mode" and produces the vulnerable baseline.
  * ``defense_on``  — full L1-L4 enforcement.

Decoupling detection from enforcement this way is what lets the harness measure
detection quality independently of mitigation, and produce honest before/after
numbers.
"""

from __future__ import annotations

import time

from config.settings import settings
from src.common.types import Action, DetectionResult, Response
from src.defense.context_guard import ContextGuard
from src.defense.input_filter import InputFilter
from src.defense.output_filter import OutputFilter
from src.defense.risk_scorer import should_block
from src.detection.audit_log import AuditLogger
from src.detection.detector import Detector
from src.rag.llm import REFUSAL_MESSAGE, OllamaLLM
from src.rag.retriever import Retriever

DEFENSE_OFF = "defense_off"
DEFENSE_ON = "defense_on"


class Guardrails:
    def __init__(
        self,
        *,
        detector: Detector | None = None,
        retriever: Retriever | None = None,
        llm: OllamaLLM | None = None,
        input_filter: InputFilter | None = None,
        context_guard: ContextGuard | None = None,
        output_filter: OutputFilter | None = None,
        audit: AuditLogger | None = None,
    ) -> None:
        self.detector = detector or Detector()
        self.retriever = retriever or Retriever()
        self.llm = llm or OllamaLLM()
        self.input_filter = input_filter or InputFilter()
        self.context_guard = context_guard or ContextGuard()
        self.output_filter = output_filter or OutputFilter()
        self.audit = audit or AuditLogger()

    def process(
        self,
        query: str,
        *,
        mode: str = DEFENSE_ON,
        role: str | None = None,
        session: str = "cli",
    ) -> Response:
        t0 = time.perf_counter()
        enforce = mode == DEFENSE_ON

        # --- L1: normalize + pre-screen, then full detection (always logged) ---
        screen = self.input_filter.process(query)
        detection: DetectionResult = self.detector.analyze(query)
        self.audit.log_request(
            session=session,
            mode=mode,
            raw_input=query,
            normalized=screen.normalized,
            detection=detection,
        )

        # --- L2: block early on HIGH+ when enforcing ---
        if enforce and should_block(detection.severity):
            resp = Response(
                answer=REFUSAL_MESSAGE,
                action=Action.BLOCK,
                detection=detection,
                retrieved=[],
            )
            return self._finalize(resp, t0, session, mode, detection, caught_canaries=[])

        # --- Retrieval ---
        retrieved = self.retriever.retrieve(query)

        # --- L3: context guard (enforce only) ---
        withheld_sources: list[str] = []
        used_chunks = retrieved
        if enforce:
            guard = self.context_guard.filter(retrieved, role)
            used_chunks = guard.allowed
            withheld_sources = guard.withheld_sources

        # --- LLM generation ---
        raw_answer = self.llm.generate(query, used_chunks)

        # --- L4: output scan (always scan to detect leaks; enforce conditionally) ---
        scan = self.output_filter.scan(raw_answer)

        if not enforce:
            # Monitor mode: surface the raw answer; record real leaks, no redaction.
            resp = Response(
                answer=raw_answer,
                action=Action.ALLOW,
                detection=detection,
                retrieved=retrieved,
                leaked_canaries=scan.leaked_canaries,
                redactions=[],
                withheld_sources=[],
            )
            return self._finalize(
                resp, t0, session, mode, detection, caught_canaries=scan.leaked_canaries
            )

        # Enforcing.
        if scan.block:
            resp = Response(
                answer=REFUSAL_MESSAGE,
                action=Action.BLOCK,
                detection=detection,
                retrieved=used_chunks,
                leaked_canaries=[],  # prevented from reaching the user
                redactions=scan.redactions,
                withheld_sources=withheld_sources,
            )
            return self._finalize(
                resp, t0, session, mode, detection, caught_canaries=scan.leaked_canaries
            )

        if scan.redacted:
            action = Action.REDACT
        elif detection.severity.value == "MEDIUM":
            action = Action.FLAG
        else:
            action = Action.ALLOW

        resp = Response(
            answer=scan.text,
            action=action,
            detection=detection,
            retrieved=used_chunks,
            leaked_canaries=[],
            redactions=scan.redactions,
            withheld_sources=withheld_sources,
        )
        return self._finalize(resp, t0, session, mode, detection, caught_canaries=[])

    def _finalize(
        self,
        resp: Response,
        t0: float,
        session: str,
        mode: str,
        detection: DetectionResult,
        *,
        caught_canaries: list[str],
    ) -> Response:
        resp.latency_ms = round((time.perf_counter() - t0) * 1000, 2)
        self.audit.log_event(
            {
                "stage": "output",
                "session": session,
                "mode": mode,
                "attack_type": detection.attack_type.value,
                "risk_score": detection.risk_score,
                "severity": detection.severity.value,
                "matched": detection.matched,
                "action": resp.action.value,
                "retrieved_sources": [c.source for c in resp.retrieved],
                "withheld_sources": resp.withheld_sources,
                "leaked_canaries": resp.leaked_canaries,
                "caught_canaries": caught_canaries,
                "redactions": resp.redactions,
                "latency_ms": resp.latency_ms,
            }
        )
        return resp
