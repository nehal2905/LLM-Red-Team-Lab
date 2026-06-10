"""RAGPipeline — the single orchestration entry point.

``run(query, mode=...)`` is what the Streamlit app, the CLI, and the red-team
runner all call. The pipeline owns wiring and the public contract; it delegates
the L1-L4 chain to :class:`Guardrails`, which keeps the control flow in one
readable, testable place.

    mode = "defense_off"  -> detection still logs, but never blocks/redacts
    mode = "defense_on"   -> full L1-L4 enforcement
"""

from __future__ import annotations

import argparse
import uuid

from src.common.types import Response
from src.defense.guardrails import DEFENSE_OFF, DEFENSE_ON, Guardrails
from src.detection.detector import Detector
from src.rag.llm import OllamaLLM
from src.rag.retriever import Retriever


class RAGPipeline:
    def __init__(
        self,
        *,
        guardrails: Guardrails | None = None,
        retriever: Retriever | None = None,
        llm: OllamaLLM | None = None,
        detector: Detector | None = None,
    ) -> None:
        if guardrails is not None:
            self.guardrails = guardrails
        else:
            self.guardrails = Guardrails(
                detector=detector,
                retriever=retriever,
                llm=llm,
            )

    def run(
        self,
        query: str,
        *,
        mode: str = DEFENSE_ON,
        role: str | None = None,
        session: str | None = None,
    ) -> Response:
        session = session or uuid.uuid4().hex[:12]
        return self.guardrails.process(query, mode=mode, role=role, session=session)


def main() -> None:
    parser = argparse.ArgumentParser(description="Query the RAG pipeline once.")
    parser.add_argument("query", help="The question / payload to send.")
    parser.add_argument(
        "--mode",
        choices=[DEFENSE_OFF, DEFENSE_ON],
        default=DEFENSE_ON,
    )
    parser.add_argument("--role", default=None, help="Caller role (e.g. admin).")
    args = parser.parse_args()

    pipeline = RAGPipeline()
    resp = pipeline.run(args.query, mode=args.mode, role=args.role)
    print(f"\n[action={resp.action.value}] "
          f"[severity={resp.detection.severity.value} "
          f"score={resp.detection.risk_score}] "
          f"[latency={resp.latency_ms}ms]")
    if resp.withheld_sources:
        print(f"[withheld confidential sources: {', '.join(resp.withheld_sources)}]")
    if resp.leaked_canaries:
        print(f"[LEAKED CANARIES: {', '.join(resp.leaked_canaries)}]")
    print("\n" + resp.answer)


if __name__ == "__main__":
    main()
