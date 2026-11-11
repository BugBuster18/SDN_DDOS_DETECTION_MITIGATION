# Research Plan

## Problem
A flow-level DDoS classifier (production HistGradientBoosting, 7 features)
misclassifies **legitimate high-volume UDP** as attack. Data audit
(`dataset_audit.md`) shows this is intrinsic: at the single-flow level a
large-packet benign UDP stream and one flood flow are identical, and neither
CIC-DDoS2019 nor CSE-CIC-IDS2018 contains large-packet benign UDP. The fix must
be **destination-level temporal context**, not more flow data or a higher
threshold.

## Hypothesis
Combining per-flow ML evidence with **counter-delta, destination-centric,
multi-source temporal features** and a **k-of-n confirmation** state machine
reduces false positives on legitimate UDP while retaining attack recall, and
enables **scoped, reversible** mitigation that preserves legitimate-user
performance.

## Contribution (candidate)
See `related_work.md` §4. A false-positive-aware destination-centric temporal
detection + staged reversible mitigation framework, validated under concurrent
legitimate-UDP / DDoS workloads with recovery and overhead measurement. Framed
as a systems/methodology contribution, not a new ML algorithm.

## Method summary
- **Level 1**: existing 7-feature model via localhost API (unchanged).
- **Level 2**: `FlowCounterTracker` (interval deltas, reset/missing handling) +
  `DestinationWindowAnalyzer` (19 dst features, 10 per-source features).
- **Level 3**: `LinearScorer` logistic models (JSON, explainable) + state machine
  + source attribution → scoped mitigation (off by default).

## Experimental protocol (leakage control)
| Stage | Data | Never reused for |
|---|---|---|
| Flow model fit | CIC-DDoS2019 (group-split) | — |
| Level-2 model fit + thresholds | **calibration** Mininet runs (seeds 0–3) | test |
| Final evaluation | **test** Mininet runs (disjoint seeds) | any fitting |
| Mitigation effect | separate mitigation runs | detection metrics |

Group-disjoint splits by run; thresholds chosen on a calibration validation
split; repeated polling snapshots of one flow are one record.

## Scenarios (A–G)
A benign-only (incl. large-packet UDP, rates overlapping attacks); B single-source
UDP flood; C multi-source UDP DDoS; D TCP SYN flood; E ICMP flood; F mixed
benign+attack concurrent; G low-rate / bursty / join-leave / multi-port.
Seeded, reproducible (`experiments/scripts/scenarios.py`).

## Baselines & ablation (`evaluate.py`)
B1 flow-ML-only; B2 statistical rule (no ML); B3 ML+temporal (single window);
Proposed = B3 + k-of-n + attribution. Ablation: ML → +sources → +rate →
+both → full temporal → +confirmation.

## Metrics
Window-level: precision/recall/F1/macro-F1/balanced-acc/specificity/FPR/FNR/
ROC-AUC/PR-AUC/confusion, split by protocol and scenario. Event-level: detection
latency, time-to-confirm, false alerts on benign runs, recovery time.
Operational: controller/ML CPU+RSS, OpenFlow message counts, flow-table size,
packet-in rate. Mitigation: legitimate probe goodput / loss / RTT with vs
without mitigation.

## Phase status
1 audit ✓ · 2 data audit ✓ · 3 related work ✓ · 4 detection impl ✓ (tests pass)
· 5 calibration+test campaigns (running) · 6 mitigation (dry-run → controlled)
· 7 reproducible eval + plots · 8 paper outline. See `docs/experimental_methodology.md`.
