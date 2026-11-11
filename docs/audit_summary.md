# Audit & Findings Summary

Answers the brief's nine opening questions, then states what was built and the
real measured outcome. All numbers are from held-out test runs (models fit on
calibration seeds 0–1, evaluated on test seeds 10–12); see
`docs/results_summary.md` and `experiments/results/`.

## 1. Architecture of the current implementation (as inherited)
Two-environment design: `.venv` (3.12) runs the 7-feature flow model behind a
localhost HTTP API (`ddos_ml/predict_api.py`); `.venv-ryu39` (3.9) runs the Ryu
controller (`Codes/controller/controller.py`) which polls OpenFlow stats every
~10 s, aggregates bidirectional conversations (`ddos_ml/sdn_runtime.py`), queries
the API, and logs predictions. Topology: 6-switch chain, 18 hosts, victim h18.
Mitigation (`mitigation_module.py`) off by default.

## 2. Working components (verified)
Preprocessing + group-aware training (`ddos_ml/training.py`) — reproduces the
production HGB model; flow model + API — healthy; bidirectional aggregation —
unit-tested; controller multipart-reply handling; Mininet topology + traffic
scripts; 24 original tests pass. Mininet/OVS/Ryu all run in this WSL env (root
via `wsl -u root`).

## 3. Actual bugs / limitations found
- **Topology CPU cap `cpu=1/20`** throttled traffic generators to ~400 pps,
  preventing realistic attack rates (fixed: made configurable, disabled for
  campaigns).
- Controller used **lifetime-average** `bytes/duration`, not interval rates
  (addressed by the new counter-delta tracker).
- 10 s polling only; no destination-level context; no per-source attribution;
  flow model is the sole decision (false-positive prone).
- Dataset: CIC-DDoS2019 is 99.4 % attack with **1.34 M contradictory 7-feature
  signatures** — flow-level accuracy there is partly leakage.

## 4. Benign-UDP false-positive diagnosis (root cause)
At the single-flow level a large-packet benign UDP stream and one flood flow are
**statistically identical** in the 7 features. The data audit
(`docs/dataset_audit.md`) confirms **no public dataset** (CIC-DDoS2019 benign UDP
≤~300 B; CSE-CIC-IDS2018 benign UDP median 67 B / p95 124 B) contains
large-packet benign UDP. Measured: raw flow-ML has **50 % FPR on UDP windows**
and **30.7 false alerts per benign run**. Therefore the fix cannot be more flow
data or a higher threshold — it must be destination-level temporal context.

## 5. Extend vs rebuild → **extend**
The flow model, API, aggregation, topology and tests are sound and were kept
unchanged. New capability was added as modular layers, not a rewrite.

## 6. Proposed contribution
A false-positive-aware, destination-centric **temporal** detector (OpenFlow
**counter-delta** interval rates + per-source attribution) feeding a transparent
**k-of-n** state machine and **scoped, reversible** mitigation, validated under
concurrent legitimate-UDP/DDoS workloads with measured recovery and overhead.
Framed as a systems/methodology contribution (`docs/related_work.md` §4).

## 7. Related work that could threaten novelty
Hybrid RF-XGB (Mahar 2026), HSF dual-plane SVM-RF (Hirsi 2025), online ensemble
(Alashhab 2024), entropy+ML (Hassan 2024). None combine counter-delta interval
rates + large-benign-UDP handling + scoped reversible mitigation with measured
recovery (`docs/related_work.md` §3). Contribution is the combination + the
false-positive-focused evaluation, not any single ingredient.

## 8. Implementation & experiment sequence (done)
temporal_features → decision_engine → config → hybrid_controller (tests first) →
seeded scenarios A–G + campaign runner → offline replay/label → fit on
calibration → evaluate baselines/ablation on held-out test → staged mitigation →
figures/paper tables. 64 unit tests pass.

## 9. Dependencies / storage
No new heavy deps (Level-2/3 are pure Python; PyYAML already present; models are
JSON). CSE-CIC-IDS2018: 4 day-CSVs (~1.42 GB) via AWS open-data, not the 4 GB
Tuesday file or PCAPs. Disk ample (943 GB free). Each run ≈ 1–2 MB telemetry.

---

## Measured outcome (held-out test, 18 attack + benign runs)

| | flow-ML only (B1) | rule / statistical (B2) | ML+temporal (B3) | **proposed (hybrid+k-of-n)** |
|---|---:|---:|---:|---:|
| Window FPR | 7.6 % | 2.0 % | 1.2 % | **1.2 %** |
| Window recall | 0.46 | 0.64 | 0.81 | **0.81** |
| **UDP window FPR** | **50.0 %** | — | — | **3.6 %** |
| PR-AUC | 0.27 | 0.40 | 0.82 | **0.82** |
| Event detection rate | 0.56 | 0.83 | 1.00 | **0.89** |
| **False alerts / benign run** | **30.7** | 10.0 | 2.7 | **1.3** |
| Detection latency (s) | 7.9 | 5.9 | 7.7 | 12.4 |

Ablation (window F1) rises monotonically: ML 0.45 → +sources 0.72 → +rate 0.70
→ +both 0.76 → full temporal 0.79, confirming each temporal component helps.
Mitigation installs scoped, reversible drop rules at the attacker's ingress
switch and rolls them back on recovery (verified live); legitimate-probe impact
is quantified in `docs/results_summary.md`.

## Readiness (candid)
Ready as a **student research project** now. Plausible **conference/workshop**
submission after broadening seeds/attacks and adding a significance test. **Not
journal-ready** on emulation-only evidence — needs a larger/physical testbed,
reflection/amplification and app-layer attacks, and cross-environment threshold
transfer (`docs/limitations.md`).
