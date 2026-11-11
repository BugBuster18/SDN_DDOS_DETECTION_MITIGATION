# How to Run the SDN DDoS Detection & Mitigation Experiment

End-to-end runbook: environment → datasets → detection campaigns → analysis →
mitigation → figures/paper tables. Every command below is copy-pasteable and was
used to produce the results in `docs/results_summary.md`.

- **OS:** Ubuntu (tested on WSL2 Ubuntu, kernel 6.x). 8 vCPU / 7 GB is enough.
- **Project root:** `~/projects/ddos-cicddos2019-ready` (adjust if different).
- **Two Python envs (already set up here):** `.venv` (3.12, ML stack) and
  `.venv-ryu39` (3.9, Ryu 4.34). Keep them separate — do **not** install the ML
  stack into the Ryu env.
- **Root:** Mininet needs root. On WSL use `wsl -u root` or `sudo`.
- **Golden rule:** `mn -c` is run **before** Ryu, never after (it can kill the
  running Ryu manager). The campaign runner already does this for you.

> ⚠️ All attack traffic stays inside the isolated Mininet `10.0.0.0/24` lab.
> Never point the attack tools at a real network. Real mitigation (packet drops)
> is **off by default** and only enabled by the `hybrid_enforce.yaml` config.

---

## 0. One-time setup

```bash
cd ~/projects/ddos-cicddos2019-ready

# System tools (root) — Mininet/OVS are already installed; these add the traffic generators.
sudo apt-get update
sudo apt-get install -y mininet openvswitch-switch hping3 iperf3 iperf sysstat ethtool

# Start Open vSwitch if not running
sudo service openvswitch-switch start

# ML environment (Python 3.12)
python3 -m venv .venv                     # skip if .venv already exists
source .venv/bin/activate
pip install -U pip
pip install -r requirements-dev.txt       # numpy, pandas, scikit-learn, matplotlib, joblib, scipy, pytest, pyyaml
deactivate

# Ryu environment (Python 3.9) — legacy, keep separate
# (already provided as .venv-ryu39; to recreate: python3.9 -m venv .venv-ryu39 && .venv-ryu39/bin/pip install -r requirements-ryu.txt)
```

Sanity check:

```bash
source .venv/bin/activate && pytest -q           # expect 44 passed
.venv-ryu39/bin/python -c "import ryu, eventlet; print('ryu OK')"
mn --version && ovs-vsctl --version | head -1
```

---

## 1. Datasets

CIC-DDoS2019 (flow-level model training) is already under
`data/raw/CICDDoS2019/01-12/`. To (re)download the three starter CSVs:

```bash
source .venv/bin/activate
pip install -r requirements-download.txt
python scripts/download_cicddos2019.py          # UDPLag.csv, Syn.csv, DrDoS_NTP.csv (~1.44 GB)
```

CSE-CIC-IDS2018 (benign-UDP audit, ~1.42 GB, public AWS open-data — no account):

```bash
bash experiments/scripts/download_cic2018.sh data/raw/cic2018
```

Audit the data (produces the numbers in `docs/dataset_audit.md`):

```bash
python scripts/preprocess_dataset.py \
  --input data/raw/CICDDoS2019/01-12 \
  --output data/processed/cicddos2019_flows.csv
```

---

## 2. Flow-level (Level-1) model — already trained

The production model (`artifacts/production/`, HistGradientBoosting) is already
trained and **must not be overwritten**. To reproduce it into a *separate* dir:

```bash
source .venv/bin/activate
python scripts/train.py \
  --input data/processed/cicddos2019_flows.csv \
  --output-dir artifacts/experiments/flow_rerun \
  --max-rows 60000
```

Start the ML prediction API (needed by the controller). Leave it running in its
own terminal:

```bash
source .venv/bin/activate
DDOS_MODEL_DIR=artifacts/production python -m ddos_ml.predict_api
# serves GET /health and POST /predict on http://127.0.0.1:8765
# (the campaign runner auto-starts this if it is not already up)
```

---

## 3. Detection campaigns (Mininet + Ryu, run as root)

The runner does everything per run: `mn -c` → start Ryu (`hybrid_controller.py`)
→ start the 6-switch/18-host topology → disable NIC offloads → start victim
servers → play a **seeded** traffic schedule (scenarios A–G) → sample
CPU/RSS/flow-table → stop. Artefacts land in
`experiments/results/raw/<campaign>/<scenario>_<seed>/`.

```bash
cd ~/projects/ddos-cicddos2019-ready

# CALIBRATION runs — used ONLY to fit the Level-2 models (seeds 0–3 here)
sudo python3 experiments/scripts/run_experiment.py \
  --campaign calibration \
  --scenarios A B C D E F G --seeds 0-3 \
  --duration 80 --cpu 0 --bw 100 \
  --config experiments/configs/observation.yaml

# TEST runs — held out, NEVER used for fitting (disjoint seeds 10–13)
sudo python3 experiments/scripts/run_experiment.py \
  --campaign test \
  --scenarios A B C D E F G --seeds 10-13 \
  --duration 80 --cpu 0 --bw 100 \
  --config experiments/configs/observation.yaml
```

Flags: `--cpu 0` removes the per-host CPU cap so attackers can actually flood;
`--bw 100` caps links at 100 Mbit/s; `--poll N` overrides the polling interval;
`--duration` is the run length in seconds. Each run ≈ 1.5–2 min.

Scenarios: **A** benign only (incl. large-packet UDP), **B** single-source UDP
flood, **C** multi-source UDP DDoS, **D** TCP SYN flood, **E** ICMP flood,
**F** mixed benign+attack, **G** low-rate/bursty/join-leave/multi-port.

---

## 4. Analysis (ML env — run after the campaigns finish)

```bash
source .venv/bin/activate

# 4a. Replay logged telemetry → labelled feature tables (deterministic, no Mininet)
python experiments/scripts/replay.py --campaign calibration
python experiments/scripts/replay.py --campaign test

# 4b. Fit the Level-2 window & source models on CALIBRATION only → JSON scorers
python experiments/scripts/fit_models.py --campaign calibration
#   → artifacts/experiments/temporal/{window_model,source_model}.json

# 4c. Evaluate baselines + ablation on the held-out TEST set
python experiments/scripts/evaluate.py --calib calibration --test test
#   → experiments/results/processed/test/{window_metrics,event_metrics,event_summary}.csv

# 4d. Build the results summary and the figures
python experiments/scripts/build_paper_tables.py --test test   # → docs/results_summary.md
python experiments/scripts/plots.py --test test                # → experiments/results/figures/*.png
```

---

## 5. Mitigation (Phase 6)

Mitigation is **disabled by default**. Three configs:

| Config | Blocks? | Use |
|---|---|---|
| `observation.yaml` | no | detection only (used for campaigns above) |
| `hybrid_dryrun.yaml` | no (logs "would block") | verify attribution before enabling drops |
| `hybrid_enforce.yaml` | **yes**, scoped & reversible | controlled mitigation experiment |

Real drops require all three set together in the config:
`mitigation.enabled: true`, `mitigation.dry_run: false`, `detection.mode: enforce`.

```bash
# Dry run first (no packets dropped; check the "would block" log lines)
sudo DDOS_CONFIG=experiments/configs/hybrid_dryrun.yaml \
  python3 experiments/scripts/run_experiment.py \
  --campaign mit_dryrun --scenarios C --seeds 20 --duration 80 --cpu 0 --bw 100 \
  --config experiments/configs/hybrid_dryrun.yaml

# Comparison: same attack WITHOUT vs WITH scoped mitigation
sudo python3 experiments/scripts/run_experiment.py \
  --campaign mit_nomit  --scenarios C F --seeds 20-21 --duration 80 --cpu 0 --bw 100 \
  --config experiments/configs/observation.yaml
sudo python3 experiments/scripts/run_experiment.py \
  --campaign mit_enforce --scenarios C F --seeds 20-21 --duration 80 --cpu 0 --bw 100 \
  --config experiments/configs/hybrid_enforce.yaml

# Quantify legitimate-user impact (probe goodput / loss / RTT), with vs without
source .venv/bin/activate
python experiments/scripts/mitigation_effect.py --nomit mit_nomit --enforce mit_enforce
python experiments/scripts/plots.py --test mit_enforce        # adds mitigation_effect.png
```

**Live kill-switch:** `touch experiments/MITIGATION_DISABLE` makes the running
controller roll back every installed drop rule. Delete the file to re-arm.
Probe hosts (10.0.0.7, 10.0.0.13) are allowlisted and never blocked.

What a successful enforce run logs (`.../ryu.log`):

```
dst=10.0.0.18 CONFIRMED->MITIGATING score=0.978 sources=['10.0.0.4','10.0.0.5'] actions=['block']
BLOCK 10.0.0.4 -> 10.0.0.18 proto=17 at dpids=[2] cookie=dd05000000000001
dst=10.0.0.18 MITIGATING->RECOVERING score=0.280 actions=['rollback']
UNBLOCK 10.0.0.4 -> 10.0.0.18 proto=17 (recovered)
```

---

## 6. Run the live system manually (interactive, two terminals)

Terminal 1 — controller (Ryu env, as root), detection-only:

```bash
cd ~/projects/ddos-cicddos2019-ready/Codes/controller
sudo DDOS_CONFIG=../../experiments/configs/observation.yaml \
  ../../.venv-ryu39/bin/ryu-manager --ofp-tcp-listen-port 6653 hybrid_controller.py
```

Terminal 2 — Mininet (after the controller is up):

```bash
cd ~/projects/ddos-cicddos2019-ready/Codes/mininet
sudo python3 topology.py 127.0.0.1
mininet> pingall
mininet> h1 iperf -u -c 10.0.0.18 -b 5M -t 20     # benign UDP
```

(The ML API from §2 must be running.) Use the original `controller.py` instead
for the pure flow-level baseline.

---

## 7. Expected outputs

```
artifacts/experiments/temporal/   window_model.json, source_model.json
experiments/results/raw/<camp>/<scn>_<seed>/   telemetry.jsonl, manifest.json, resources.csv, ...
experiments/results/raw/<camp>/tables/         dst_windows.csv, src_windows.csv
experiments/results/processed/test/            window_metrics.csv, event_summary.csv, predictions_*.csv
experiments/results/figures/                   roc_curves.png, ablation_window.png, timeseries_C.png, ...
docs/results_summary.md                        auto-generated headline tables
```

Reference numbers to expect (held-out test): window FPR flow-ML 7.6 % → hybrid
1.2 %; UDP-window FPR 50 % → 3.6 %; event false-alerts/benign-run 30.7 → 1.3.
Your exact numbers vary slightly with seeds/host load.

---

## 8. Troubleshooting

- **`PermissionError` writing results in the ML env:** the campaign ran as root.
  Fix ownership: `sudo chown -R $USER:$USER experiments/results artifacts/experiments docs`.
- **Ryu exits immediately / port 6653 busy:** `sudo pkill -f hybrid_controller; sudo mn -c`.
- **Switches never register:** check `.../ryu.log` for "Registered switch" (expect 6);
  ensure OVS is running and no stale namespaces (`sudo mn -c`).
- **ML API unreachable:** start it (§2); the controller logs "ML API unavailable"
  and continues on temporal evidence only.
- **Attack rates look tiny (~400 pps):** you left the host CPU cap on — pass
  `--cpu 0`.
- **Packet counts look inflated:** NIC offloads re-enabled; the runner disables
  them, but if running manually: `sudo ethtool -K <intf> tso off gso off gro off`.
- **Everything hangs after `mn -c`:** you ran `mn -c` while Ryu was up. Restart
  Ryu; always clean *before* starting the controller.
```
