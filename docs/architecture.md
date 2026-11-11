# System Architecture

## Overview

Three-level, false-positive-aware DDoS detection and staged mitigation for an
OpenFlow 1.3 SDN, built on the existing Ryu + Mininet + Open vSwitch testbed.

```
                         ┌──────────────────────────────────────────┐
                         │                Ryu controller            │
   OpenFlow 1.3          │  ┌───────────────┐   ┌──────────────────┐ │
  ┌────────┐  stats      │  │ SimpleSwitch13│   │ HybridDetector   │ │
  │ s1..s6 │◀───────────▶│  │ (L2 forward,  │──▶│  poll loop       │ │
  │  OVS   │  flow-mod   │  │  configurable │   │  (configurable)  │ │
  └────────┘             │  │  timeouts)    │   └───────┬──────────┘ │
       ▲                 │  └───────────────┘           │            │
       │ traffic                                        ▼            │
  ┌────┴─────┐           │   Level-1 flow ML   Level-2 temporal      │
  │ h1..h18  │           │   (HTTP localhost)  (counter deltas,      │
  │ Mininet  │           │        │            destination windows)  │
  └──────────┘           │        ▼                    │            │
                         │  ┌───────────┐   Level-3 decision engine  │
                         │  │ predict_api│   (linear scorers +       │
                         │  │  :8765 ML  │   k-of-n state machine +  │
                         │  │  (.venv)   │   source attribution)     │
                         │  └───────────┘           │                │
                         │                          ▼                │
                         │            scoped reversible mitigation   │
                         │            (disabled / dry-run default)   │
                         └──────────────────────────────────────────┘
```

Two Python environments are kept separate (unchanged from the original design):

- **`.venv` (3.12)** — ML stack; runs `ddos_ml.predict_api` (the seven-feature
  production model) as a localhost HTTP service.
- **`.venv-ryu39` (3.9)** — Ryu 4.34; runs the controller. The new Level-2 and
  Level-3 modules (`temporal_features.py`, `decision_engine.py`, `config.py`)
  are **pure Python** (no NumPy/Pandas/sklearn) so they import cleanly here. The
  fitted Level-2 models are plain JSON (standardisation + logistic weights), so
  no sklearn is needed at inference time inside Ryu.

## Components

### Level 1 — flow-level ML (unchanged production model)
`ddos_ml/{features,runtime,predict_api}.py`, `artifacts/production/`. Seven
features (`protocol, duration_sec, packet_count, byte_count, packet_rate,
byte_rate, avg_packet_size`), HistGradientBoosting. The controller sends
bidirectional-aggregated conversations and receives an attack probability per
conversation. This is **one evidence source**, deliberately not the decision.

### Level 2 — destination-centric temporal features (`ddos_ml/temporal_features.py`)
- **`FlowCounterTracker`** keeps previous cumulative counters per
  `(datapath, directed 5-tuple)` and emits per-interval **deltas**. It classifies
  each observation as `ok | new | reset | no_baseline` and handles new/expired
  flows, counter resets/wraps, duplicate observations in one reply, missing
  replies (state kept, no phantom deltas), and switch disconnects.
- **`merge_path_observations`** collapses the same directed flow seen on several
  switches of the chain using the **maximum** delta (never the sum).
- **`DestinationWindowAnalyzer`** produces, per destination per window, 19
  features (source count, active/new flows, interval pps/bps, avg packet size,
  top-source share, normalised source entropy, per-protocol shares,
  request/response byte ratio, log pps change vs EWMA, packet-in rate, and
  aggregate Level-1 ML statistics) and, per `(source, destination)`, 10
  attribution features (per-source interval pps, share, flow counts,
  per-source ML probability, per-source response ratio, log rate jump, activity).

### Level 3 — decision engine (`ddos_ml/decision_engine.py`)
- **`LinearScorer`** — logistic model over log1p-transformed, standardised
  features; every score decomposes into per-feature contributions (logged as
  evidence). **`RuleScorer`** — the non-ML statistical baseline.
- **State machine** per destination:
  `NORMAL → SUSPECTED → CONFIRMED → MITIGATING → RECOVERING → NORMAL`, with
  **k-of-n** window confirmation, recovery after consecutive quiet windows, and
  a cooldown that returns straight to CONFIRMED on renewed evidence.
- **Source attribution** selects the flooding sources at a confirmed victim
  (allowlist-aware), driving scoped mitigation.

### Controller (`Codes/controller/hybrid_controller.py`)
Subclasses the original `SimpleSwitch13`. Adds a configurable poll loop with
XID-correlated multipart replies, per-destination Packet-In accounting, ingress
switch learning (for scoped rules), JSONL telemetry, and the staged mitigation
actuator. The **original `controller.py` is untouched** (baseline / capture
tool). Mitigation is **off and dry-run by default** (`ddos_ml/config.py`); real
drops require `mitigation.enabled: true`, `dry_run: false`, and
`detection.mode: enforce` together, plus respect a kill-switch file.

### Mitigation (staged, reversible)
Installs `(eth_type, ipv4_src=attacker, ipv4_dst=victim, ip_proto)` drop rules
at the attacker's ingress switch only, with a hard timeout and
`OFPFF_SEND_FLOW_REM`, tagged by a reserved cookie range. Rollback deletes by
cookie on recovery, on kill-switch, or on flow-removed. Never blocks a whole
host or port; allowlist protects probes/test hosts.

## Data / experiment flow
`run_experiment.py` (root) → per-run telemetry JSONL + manifest (seeded ground
truth) + resource/flow-table samples → `replay.py` (deterministic re-derivation
of labelled feature tables) → `fit_models.py` (calibration only) → `evaluate.py`
(baselines, ablation, window + event metrics on held-out test) → `plots.py`
(figures). Model/code/config versions are recorded per run in `manifest.json`.
