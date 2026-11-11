# Dataset Audit

Scope: datasets considered for the **flow-level (Level-1)** classifier and the
reasoning that led to the **destination-centric temporal (Level-2)** design.
All counts below were produced by direct inspection of the raw CSVs in this
repository (scripts: `experiments/scripts/download_cic2018.sh`, ad-hoc audit in
the project log). Numbers are reproducible from the files under `data/raw/`.

## 1. CIC-DDoS2019 (already present)

- Source: Canadian Institute for Cybersecurity, <https://www.unb.ca/cic/datasets/ddos-2019.html>; the three CSVs here were obtained from the public Hugging Face mirror `baalajimaestro/CICDDoS2019`.
- Files used: `DrDoS_NTP.csv`, `Syn.csv`, `UDPLag.csv` (`data/raw/CICDDoS2019/01-12/`).
- Preprocessed: `data/processed/cicddos2019_flows.csv` (7-feature canonical schema).

| Quantity | Value |
|---|---:|
| Rows read / kept | 3,170,293 / 3,170,293 |
| Benign (label 0) | 18,462 |
| Attack (label 1) | 3,151,831 |
| Benign fraction | 0.58 % |

**Problem 1 — severe class imbalance in benign direction.** Only ~18k benign
flows exist, and they are dominated by a few families' background traffic. This
is why the production training balances the *training* partition and keeps the
test prevalence natural (see `ddos_ml/training.py`).

**Problem 2 — benign UDP is small-packet.** A prior diagnostic (recorded in the
brief) found CIC benign UDP average packet size capped around ~300 B. Our
Mininet benign UDP (iperf streams) spans 554–1512 B, overlapping the attack
packet-size range. A flow-level model trained only on CIC-DDoS2019 therefore has
no examples of *large-packet benign UDP* and misclassifies it as attack.

## 2. CSE-CIC-IDS2018 (downloaded for this work)

- Source: AWS Open Data public bucket `s3://cse-cic-ids2018` (no credentials), "Processed Traffic Data for ML Algorithms" (CICFlowMeter CSVs).
- Files downloaded (4 of 10 day-files, ~1.42 GB total; the 4 GB Tuesday file and raw PCAPs were **not** downloaded to save space):
  `Wednesday-21-02-2018`, `Friday-16-02-2018`, `Thursday-15-02-2018`, `Thursday-22-02-2018` `_TrafficForML_CICFlowMeter.csv`.
- SHA-256 sums recorded in `data/raw/cic2018/SHA256SUMS`.

Schema differs from 2019 (e.g. `Tot Fwd Pkts`, `TotLen Fwd Pkts`, numeric
`Protocol`), handled by the alias resolver in `ddos_ml/features.py`.

Protocol × class counts across the 4 files:

| Protocol | Benign | Attack |
|---|---:|---:|
| TCP (6) | 2,154,422 | 1,340,674 |
| **UDP (17)** | **647,892** | **1,730** |
| proto 0 / other | 34,629 | 1 |

So 2018 supplies **647,892 benign UDP flows** — far more than 2019. But the
critical distribution:

| avg packet size (bytes) | min | p25 | median | p75 | p95 | max |
|---|---:|---:|---:|---:|---:|---:|
| Benign UDP (2018) | 1 | 52 | 67 | 86 | 124 | 668 |
| Attack UDP (2018, LOIC-UDP) | 32 | 32 | 32 | 32 | 32 | 32 |

**Key, honest finding.** CSE-CIC-IDS2018 benign UDP is overwhelmingly
*small-packet* (median 67 B, p95 124 B) — DNS/NTP-like request/response, not
bulk transfer. It does **not** contain the large-packet, high-rate benign UDP
(iperf-style bulk streaming) that triggers the false positives in our testbed.
Adding 2018 benign UDP to the flow-level training set therefore **cannot**, on
its own, fix the Mininet large-packet benign-UDP false positives. It improves
coverage of small-packet benign UDP (worth doing) but leaves the hard case
untouched.

This is the empirical justification for the project's central design decision:
the discrimination between a legitimate high-volume UDP application and a
distributed UDP flood must come from **destination-level context over time**
(number of distinct sources, per-source rate, request/response ratio,
interval-rate change) rather than from per-flow packet statistics alone. No
realistic amount of flow-level training data makes a single large-packet UDP
flow distinguishable from one flood flow, because at the flow level they are
genuinely identical.

## 3. Data-quality handling (both datasets)

Implemented in `ddos_ml/features.py` / `ddos_ml/training.py`:

- NaN / ±Inf rate values → set missing, imputed by a training-only median inside the sklearn `Pipeline`.
- Impossible counters (negative packet/byte/duration) → missing.
- CICFlowMeter `Flow Duration` (microseconds) converted to seconds.
- **Contradictory signatures:** identical 7-feature vectors with both labels are detected and removed before fitting (1,338,471 such rows removed in the current production run — a large figure that itself warns against over-trusting flow-level separability on CIC-DDoS2019).
- **Leakage control:** bidirectional 5-tuple grouping; group-disjoint holdout; balancing applied to training only; natural test prevalence. The production metadata reports `train_test_group_overlap = 0`.

## 4. Mininet captures (independent systems-level data)

- `data/raw/mininet_benign_openflow.csv`, `data/raw/mininet_attack_openflow.csv` (legacy small captures).
- New campaigns under `experiments/results/raw/<campaign>/<scenario>_<seed>/telemetry.jsonl` provide per-poll counter-delta flow records with seeded ground truth. These are the data for Level-2 model fitting (calibration runs only) and for the final independent evaluation (test runs, never used in fitting). Repeated polling snapshots of one flow are **not** counted as independent samples: each (destination, polling window) is one record.
