# IEEE-style Paper Outline (to be filled from real results)

Working title: **A False-Positive-Aware, Destination-Centric Temporal Framework
for DDoS Detection and Reversible Mitigation in Software-Defined Networks**

Numbers in `{{…}}` are placeholders filled by `experiments/scripts/build_paper_tables.py`
from `experiments/results/processed/<test>/*` — never hand-entered.

## Abstract
Flow-level ML DDoS detectors in SDN misclassify legitimate high-volume UDP as
attack. We show with a data audit that this is intrinsic to per-flow features and
to public datasets (no large-packet benign UDP). We propose a three-level
framework: the existing per-flow ML model, counter-delta destination-centric
temporal features, and a transparent k-of-n decision engine driving scoped,
reversible mitigation. On an isolated 6-switch Ryu/Mininet testbed with seven
seeded scenarios including benign/attack rate overlap, the hybrid reduces the
window-level false-positive rate from {{fpr_flow}} to {{fpr_proposed}} while
keeping attack recall at {{recall_proposed}}, detects attacks in
{{latency_proposed}} s, and preserves legitimate probe goodput under mitigation
({{goodput_mit}} vs {{goodput_nomit}} Mbit/s) with recovery in {{recovery}} s.

## Index Terms
SDN, DDoS, OpenFlow, Ryu, Mininet, machine learning, temporal features, false
positives, mitigation.

## I. Introduction — problem, the false-positive gap, contributions (list 4–5).
## II. Motivation & Problem Statement — the benign-UDP FP, with the data-audit evidence (Table: CIC benign-UDP packet-size vs testbed).
## III. Related Work — matrix from `related_work.md`; gap statement.
## IV. Research Gap — the six-point gap (`related_work.md` §3).
## V. Proposed Architecture — Fig: system (from `architecture.md`); the three levels; two-venv separation.
## VI. Detection Methodology — Level 1 recap; decision engine; state machine (Fig).
## VII. Destination-Level Temporal Feature Engineering — counter-delta formulae; the 19 + 10 features; handling table (new/reset/missing/path-dedup).
## VIII. Mitigation Mechanism — scoped rules, cookies, rollback, recovery, kill-switch, allowlist; safety defaults.
## IX. Experimental Setup — testbed, scenarios A–G, seeds, leakage control, metrics (`experimental_methodology.md`).
## X. Dataset Description & Preprocessing — `dataset_audit.md`.
## XI. Evaluation Metrics — list.
## XII. Results & Discussion
  - Table I window-level overall + per-protocol (`window_metrics.csv`).
  - Fig ROC / PR (`roc_curves.png`, `pr_curves.png`).
  - Fig confusion flow-ML vs proposed.
  - Fig time-series victim counter-delta features with attack span.
  - Table II event-level latency / false-alerts / recovery (`event_summary.csv`).
  - Fig detection latency; Fig mitigation effect on probe; Fig overhead.
## XIII. Ablation Study — ML → +sources → +rate → +both → full → +confirmation (`ablation_window.png`).
## XIV. Threats to Validity — `limitations.md`.
## XV. Limitations — `limitations.md`.
## XVI. Conclusion & Future Work — physical testbed, spoofed/reflected DDoS, online learning, cross-topology threshold transfer.
## References — verified list from `related_work.md` (do not add unverified DOIs).

## Readiness (candid)
- **Student research project:** ready now (working end-to-end system, reproducible experiments, honest analysis).
- **Workshop / conference:** plausible after the full test + mitigation campaigns and the ablation confirm the FP-reduction claim with ≥ several seeds/scenario and a significance test.
- **Journal:** not yet — needs a larger and ideally physical testbed, more attack diversity (reflection/amplification, app-layer, adaptive), and cross-environment generalisation of the temporal thresholds. Do not submit to a journal on the current emulation-only evidence.
