"""Streamlit UI for the LLM Red-Team Lab.

Three tabs:
  1. Chat      — talk to the assistant; live risk meter, fired signatures, and
                 which sources were retrieved / withheld. Toggle defenses and
                 caller role to demonstrate the controls live.
  2. Red-Team  — fire a payload set for one attack class; watch success / blocked
                 counts update for defenses OFF vs ON.
  3. Results   — render report.csv and the before/after charts.

Run:
    streamlit run src/app/streamlit_app.py
"""

from __future__ import annotations

import sys
from pathlib import Path

# Allow `streamlit run src/app/streamlit_app.py` from the repo root.
_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import pandas as pd  # noqa: E402
import streamlit as st  # noqa: E402

from config.settings import settings  # noqa: E402
from src.common.types import Severity  # noqa: E402
from src.defense.guardrails import DEFENSE_OFF, DEFENSE_ON  # noqa: E402
from src.rag.pipeline import RAGPipeline  # noqa: E402
from src.redteam import evaluator  # noqa: E402
from src.redteam.payloads import load_all  # noqa: E402

SEVERITY_COLOR = {
    Severity.LOW: "#5cb85c",
    Severity.MEDIUM: "#f0ad4e",
    Severity.HIGH: "#d9534f",
    Severity.CRITICAL: "#8b0000",
}


@st.cache_resource(show_spinner=False)
def get_pipeline() -> RAGPipeline:
    return RAGPipeline()


def render_risk_panel(resp) -> None:
    det = resp.detection
    color = SEVERITY_COLOR.get(det.severity, "#777")
    st.sidebar.markdown("### Live Risk Meter")
    st.sidebar.markdown(
        f"<div style='font-size:1.6rem;font-weight:700;color:{color}'>"
        f"{det.risk_score}/100 · {det.severity.value}</div>",
        unsafe_allow_html=True,
    )
    st.sidebar.progress(min(det.risk_score, 100) / 100)
    st.sidebar.markdown(f"**Attack type:** `{det.attack_type.value}`")
    st.sidebar.markdown(f"**Disposition:** `{resp.action.value}`")
    if det.matched:
        st.sidebar.markdown("**Signals fired:**")
        st.sidebar.code("\n".join(det.matched))
    else:
        st.sidebar.caption("No detection signals fired.")
    if resp.retrieved:
        st.sidebar.markdown("**Sources used:**")
        st.sidebar.write([f"{c.source} ({c.sensitivity})" for c in resp.retrieved])
    if resp.withheld_sources:
        st.sidebar.warning("Withheld (confidential): " + ", ".join(resp.withheld_sources))
    if resp.leaked_canaries:
        st.sidebar.error("LEAKED CANARIES: " + ", ".join(resp.leaked_canaries))
    if resp.redactions:
        st.sidebar.info("Redacted: " + ", ".join(resp.redactions))
    st.sidebar.caption(f"latency: {resp.latency_ms} ms · rationale: {det.rationale}")


def chat_tab() -> None:
    st.subheader("Chat with the assistant")
    col1, col2 = st.columns(2)
    defenses_on = col1.toggle("Defenses ON", value=True)
    role = col2.selectbox("Caller role", ["employee", "admin", "security"], index=0)
    mode = DEFENSE_ON if defenses_on else DEFENSE_OFF

    if "history" not in st.session_state:
        st.session_state.history = []

    for turn in st.session_state.history:
        with st.chat_message(turn["role"]):
            st.markdown(turn["content"])

    query = st.chat_input("Ask a question (or try an attack)...")
    if query:
        st.session_state.history.append({"role": "user", "content": query})
        with st.chat_message("user"):
            st.markdown(query)
        try:
            resp = get_pipeline().run(query, mode=mode, role=role)
            answer = resp.answer
            render_risk_panel(resp)
        except Exception as exc:  # noqa: BLE001
            answer = (
                f"**Pipeline error:** {exc}\n\n"
                "Make sure you ran `make ingest` and that Ollama is running "
                "(`ollama serve` + `ollama pull llama3.1 nomic-embed-text`)."
            )
        st.session_state.history.append({"role": "assistant", "content": answer})
        with st.chat_message("assistant"):
            st.markdown(answer)


def redteam_tab() -> None:
    st.subheader("Red-Team: fire a payload set")
    payloads = load_all()
    classes = sorted({p.attack_type.value for p in payloads if p.is_attack})
    chosen = st.selectbox("Attack class", classes)
    role = st.selectbox("Caller role", ["employee", "admin", "security"], index=0, key="rt_role")
    subset = [p for p in payloads if p.attack_type.value == chosen]
    st.caption(f"{len(subset)} base payloads in this class.")

    if st.button("Fire payload set", type="primary"):
        pipeline = get_pipeline()
        rows = []
        prog = st.progress(0.0)
        for i, p in enumerate(subset):
            r_off = pipeline.run(p.text, mode=DEFENSE_OFF, role=role, session=f"ui:{p.id}:off")
            r_on = pipeline.run(p.text, mode=DEFENSE_ON, role=role, session=f"ui:{p.id}:on")
            rows.append(
                {
                    "id": p.id,
                    "expected": p.expected_outcome.type,
                    "success_off": evaluator.attack_succeeded(p, r_off),
                    "success_on": evaluator.attack_succeeded(p, r_on),
                    "blocked_on": r_on.action.value == "block",
                    "severity": r_on.detection.severity.value,
                    "risk": r_on.detection.risk_score,
                }
            )
            prog.progress((i + 1) / len(subset))
        df = pd.DataFrame(rows)
        c1, c2, c3 = st.columns(3)
        c1.metric("Succeeded (OFF)", int(df["success_off"].sum()))
        c2.metric("Succeeded (ON)", int(df["success_on"].sum()))
        c3.metric("Blocked (ON)", int(df["blocked_on"].sum()))
        st.dataframe(df, use_container_width=True)


def results_tab() -> None:
    st.subheader("Results")
    report = settings.report_csv
    if report.exists():
        df = pd.read_csv(report)
        st.dataframe(df, use_container_width=True)
        overall = df[df["attack_class"] == "OVERALL"]
        if not overall.empty:
            row = overall.iloc[0]
            c1, c2, c3 = st.columns(3)
            c1.metric("ASR OFF", f"{float(row['asr_off'])*100:.0f}%")
            c2.metric("ASR ON", f"{float(row['asr_on'])*100:.0f}%")
            c3.metric("Reduction", f"{float(row['asr_delta'])*100:.0f} pts")
    else:
        st.info("No report yet. Run `make attack` (or the button below).")

    for chart in ("asr_before_after.png", "detection_summary.png"):
        p = settings.charts_dir / chart
        if p.exists():
            st.image(str(p))

    if st.button("Run full harness now (slow; needs Ollama + ingest)"):
        from src.redteam.runner import run_all

        with st.spinner("Running attacks across both modes..."):
            rows = run_all()
            metrics = evaluator.compute_metrics(rows)
            evaluator.save_report(metrics)
            evaluator.render_charts(metrics)
        st.success("Done. Re-rendering results.")
        st.rerun()


def main() -> None:
    st.set_page_config(page_title="LLM Red-Team Lab", layout="wide")
    st.title("LLM Red-Team Lab")
    st.caption("Build a RAG assistant · attack it · detect the attacks · defend it — with numbers.")
    tab1, tab2, tab3 = st.tabs(["Chat", "Red-Team", "Results"])
    with tab1:
        chat_tab()
    with tab2:
        redteam_tab()
    with tab3:
        results_tab()


if __name__ == "__main__":
    main()
