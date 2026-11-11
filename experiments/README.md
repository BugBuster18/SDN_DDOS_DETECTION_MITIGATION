# Experiments

Reproducible SDN DDoS detection/mitigation campaigns on the Ryu + Mininet + OVS
testbed. All detection results are produced by **offline replay of logged
telemetry**; models are fit on **calibration** runs and evaluated on disjoint
**test** runs. Mitigation is **disabled by default**.

## Layout
```
configs/     observation.yaml (no blocking) · hybrid_dryrun.yaml · hybrid_enforce.yaml
scripts/     run_experiment.py  scenarios.py  udp_rr.py  replay.py
             fit_models.py  evaluate.py  mitigation_effect.py
             plots.py  build_paper_tables.py  download_cic2018.sh
results/
  raw/<campaign>/<scn>_<seed>/   telemetry.jsonl, manifest.json, resources.csv, ...
  raw/<campaign>/tables/         dst_windows.csv, src_windows.csv  (from replay.py)
  processed/<test>/              window_metrics.csv, event_*.csv, predictions_*.csv
  figures/                       *.png + tables for the paper
```

## Full pipeline (run from project root)
```bash
# 1. detection campaigns  (ROOT shell, Mininet needs root)
sudo python3 experiments/scripts/run_experiment.py --campaign calibration \
    --scenarios A B C D E F G --seeds 0-3 --duration 80 --cpu 0 --bw 100 \
    --config experiments/configs/observation.yaml
sudo python3 experiments/scripts/run_experiment.py --campaign test \
    --scenarios A B C D E F G --seeds 10-13 --duration 80 --cpu 0 --bw 100 \
    --config experiments/configs/observation.yaml

# 2. analysis  (ML venv: source .venv/bin/activate)
python3 experiments/scripts/replay.py --campaign calibration
python3 experiments/scripts/replay.py --campaign test
python3 experiments/scripts/fit_models.py --campaign calibration
python3 experiments/scripts/evaluate.py --calib calibration --test test
python3 experiments/scripts/build_paper_tables.py --test test
python3 experiments/scripts/plots.py --test test

# 3. mitigation campaigns  (root) — attack with vs without scoped blocking
sudo python3 experiments/scripts/run_experiment.py --campaign mit_nomit \
    --scenarios C F --seeds 20-21 --duration 80 --cpu 0 --bw 100 \
    --config experiments/configs/observation.yaml
sudo python3 experiments/scripts/run_experiment.py --campaign mit_enforce \
    --scenarios C F --seeds 20-21 --duration 80 --cpu 0 --bw 100 \
    --config experiments/configs/hybrid_enforce.yaml
python3 experiments/scripts/mitigation_effect.py --nomit mit_nomit --enforce mit_enforce
```

## Safety
- `experiments/configs/hybrid_enforce.yaml` is the only config that installs real
  drop rules; it requires `mitigation.enabled: true`, `dry_run: false`,
  `detection.mode: enforce` together. Touch `experiments/MITIGATION_DISABLE` to
  roll back all rules live. Probe hosts (10.0.0.7, 10.0.0.13) are allowlisted.
- Attack traffic targets only the isolated 10.0.0.0/24 Mininet lab.
- `mn -c` is run **before** starting Ryu, never after (it has killed the Ryu
  manager in this environment).
