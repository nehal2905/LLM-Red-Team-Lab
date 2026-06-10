# Threat Model — LLM Red-Team Lab

This is a deliberately scoped threat model for a **local RAG assistant** over
fictional company documents. It follows an assets → attacker goals → trust
boundaries → mitigations structure.

> All data in this lab is fictional. The "confidential" document is a honeypot
> seeded with canary tokens; it contains no real PII.

## 1. Assets

| # | Asset | Why it matters |
|---|---|---|
| A1 | Confidential corpus (`99_CONFIDENTIAL_salaries.md`) | Salaries, PII-shaped data, and **canary tokens**. Must never reach an unauthorized caller. |
| A2 | System prompt / instructions | Reveals control logic and the sentinel; leakage enables tailored bypasses. |
| A3 | Corpus structure / source list | Enumerating sources aids targeted exfiltration. |
| A4 | Detection logs (`results/runs/*.jsonl`) | Integrity matters: they are the evidence for all metrics. |

## 2. Actors & Trust Boundaries

```
 Untrusted: end user / attacker input  ─┐
                                        ▼
                         ┌──────── Guardrail Pipeline ────────┐
 Trusted (in-process):   │ L1 Input → L2 Score → L3 Context   │
   detector, scorer,     │           → LLM → L4 Output        │
   filters, retriever    └────────────────────────────────────┘
                                        │
 Semi-trusted: retrieved chunks (carry a sensitivity tag set at ingest)
 Trusted sink: local Ollama model (no network egress)
```

- **Trust boundary 1:** user input → pipeline. All input is untrusted; it is
  normalized and scored before anything else happens.
- **Trust boundary 2:** retrieved chunks → LLM. The L3 Context Guard enforces
  that confidential chunks only cross this boundary for authorized roles.
- **Trust boundary 3:** LLM output → user. The L4 Output Filter is the last line
  of defense (canary/PII/prompt-leak scan).

## 3. Attacker Goals (mapped to attack classes)

| Goal | Attack class | Success signal (objective) |
|---|---|---|
| Override instructions / extract system prompt | **Prompt Injection** | System-prompt sentinel or distinctive prompt phrase appears in output |
| Steal restricted data | **Data Exfiltration** | A **canary token** or known confidential value appears in output |
| Remove safety constraints to do the above | **Jailbreak** | Same as injection/exfiltration once "jailbroken" |
| Degrade trust in detection | (out of scope) | Tampering with logs — not modeled here |

## 4. Mitigations (defense layers)

| Layer | Control | Defeats |
|---|---|---|
| L1 Input Filter | Unicode/zero-width normalization + signature pre-screen | Obfuscated injections |
| L2 Risk Scorer | Weighted 0–100 score → severity → block on HIGH+ | Overt injection/exfiltration/jailbreak |
| L3 Context Guard | Drop `confidential` chunks for unauthorized roles | "Print the salary doc" — model never sees the data |
| L4 Output Filter | Canary / PII / system-prompt scan → redact or block | Residual leakage that slips through L1–L3 |
| Detection Engine | Logs **every** request/response regardless of mode | Blind spots; enables monitor-only evaluation |

## 5. Assumptions & Out of Scope

- The model runs locally via Ollama; no network exfiltration channel is modeled.
- Log integrity, multi-tenant auth, rate limiting, and supply-chain risks are out
  of scope for this lab.
- Authorization is a simplified `--role` flag, not a real IAM system.

## 6. Residual Risk

- Signature evasion via heavy paraphrase (mitigated partially by heuristics and
  the optional semantic detector).
- Semantic drift: novel attack phrasings unseen by the payload library.
- A sufficiently capable model could leak confidential data even without the
  document in context if that data appeared in training — not applicable here
  because the data is fictional and freshly generated.
