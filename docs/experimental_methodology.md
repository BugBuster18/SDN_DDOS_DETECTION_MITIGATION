# Experimental Methodology (reproducible)

## Testbed
- WSL2 Ubuntu, 8 vCPU / 7 GB. Mininet 2.3.0, Open vSwitch 3.3.9, OpenFlow 1.3.
- Topology: 6 switches in a chain (s1–s6), 18 hosts (h1–h18), victim **h18 =
  10.0.0.18**. Links via `TCLink`, capacity configurable (default 100 Mbit/s for
  campaigns). Per-host CPU cap made configurable and **disabled for campaigns**
  (the original `cpu=1/20` throttled traffic generators to ~400 pps and is a
  demonstrated limitation for attack generation).
- Controller: `Codes/controller/hybrid_controller.py` (Ryu 4.34, `.venv-ryu39`).
- ML API: `ddos_ml.predict_api` (`.venv`, production model).
- **NIC offloads (TSO/GSO/GRO) are disabled on every host/switch interface** so
  OpenFlow packet counters reflect real on-wire packets, not super-segments.

## Run lifecycle (`experiments/scripts/run_experiment.py`, root)
Per run: `mn -c` **before** starting Ryu (never after — `mn -c` has killed the
Ryu manager in this environment) → start Ryu with the run's config → start
Mininet → disable offloads → start victim servers (HTTP, UDP echo, iperf3) →
ARP/forwarding warm-up (excluded from evaluation) → start a 1 Hz resource/flow-
table sampler → play the seeded schedule with per-event wall-clock scheduling →
stop. Artefacts per run:

```
<scenario>_<seed>/
  config.yaml          exact detector config used
  manifest.json        scenario, seed, epoch0, per-event epoch_start (ground truth),
                       bw, cpu, idle_timeout, model_dir, code_version
  telemetry.jsonl      per-poll: per-flow counter deltas, dst features, decisions,
                       packet-in counts, controller counters, cycle time
  resources.csv        1 Hz CPU% + RSS for ryu and ml_api
  flowtable.csv        periodic per-switch OpenFlow flow_count
  probe_iperf.json     legitimate UDP probe (goodput/loss/jitter)
  hosts/*.log          per-event stdout (traffic tools)
```

## Ground truth & labelling (`replay.py`)
Labels come **only** from the seeded schedule. A destination window is `attack`
iff the destination is the victim and the window `[ts-interval, ts]` overlaps any
attack event interval. A `(source,victim)` window is `attack` iff that source is
a scheduled attacker active in the window. Benign high-rate UDP sources during an
attack (Scenario F) are correctly labelled benign — this is the discrimination
under test. Replay re-derives features deterministically from the logged
per-flow counter deltas using the same `DestinationWindowAnalyzer` as live.

## Model fitting (`fit_models.py`, calibration only)
Logistic regression (class-balanced) on log1p-transformed, standardised
features; standardisation statistics from the calibration-train split only.
Threshold chosen on a group-disjoint calibration-validation split by maximising
F1 subject to FPR ≤ target (window 2 %, source 1 %). Exported as JSON consumed
unchanged by the Ryu-side `LinearScorer`.

## Evaluation (`evaluate.py`, test only)
Window-level and event-level metrics for every baseline/ablation (see
`research_plan.md`). Event-level replays each test run chronologically through
the `DecisionEngine` (with the calibration-fitted scorers) and records detection
latency vs the true attack start, false alerts on benign runs, and recovery.

## Statistics
≥3–4 independent seeds per scenario; report mean ± sd. Where enough paired runs
exist, methods are compared with a Wilcoxon signed-rank test on per-run FPR /
latency (reported in the results table; not over-claimed for small n).

## Reproduce
```bash
# detection campaigns (root, in WSL)
sudo python3 experiments/scripts/run_experiment.py --campaign calibration \
    --scenarios A B C D E F G --seeds 0-3 --duration 80 --cpu 0 --bw 100 \
    --config experiments/configs/observation.yaml
sudo python3 experiments/scripts/run_experiment.py --campaign test \
    --scenarios A B C D E F G --seeds 10-13 --duration 80 --cpu 0 --bw 100 \
    --config experiments/configs/observation.yaml
# analysis (ML venv)
python3 experiments/scripts/replay.py --campaign calibration
python3 experiments/scripts/replay.py --campaign test
python3 experiments/scripts/fit_models.py --campaign calibration
python3 experiments/scripts/evaluate.py --calib calibration --test test
python3 experiments/scripts/plots.py --test test
```
