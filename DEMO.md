> **Superseded:** use [`docs/DEMO_GUIDE.md`](docs/DEMO_GUIDE.md), the verified step-by-step
> end-to-end demo (scripts in `scripts/demo/`, runtime mitigation modes, REST controls,
> measured results). This older file is kept for reference only.

# Live Demo Guide (presenting tomorrow)

**No training happens in the demo.** All models are already saved:
`artifacts/production/hist_gradient_boosting.joblib` (flow model) and
`artifacts/experiments/temporal/{window,source}_model.json` (temporal + source).
You only *run* the system.

## Pre-flight (do this once before the talk)

```bash
cd ~/projects/ddos-cicddos2019-ready
sudo service openvswitch-switch start
source .venv/bin/activate && pytest -q          # expect: 44 passed
.venv-ryu39/bin/python -c "import ryu; print('ryu OK')"
ls artifacts/production/hist_gradient_boosting.joblib \
   artifacts/experiments/temporal/window_model.json      # both must exist
```

If results look off, nothing is lost — the saved numbers live in
`docs/results_summary.md` and `experiments/results/figures/`.

---

## ⚠️ READ THIS FIRST — the one thing that breaks the live demo

The attacker command **must** pin the source port with `-k -s <port>`. A flood
**without** `-k` picks a new source port per packet → thousands of new flows per
second → a packet-in storm that **starves the controller** (it goes silent and
detects nothing, even after you stop the flood). If that happens, fully reset:
`sudo mn -c`, restart the controller, restart Mininet.

Correct (verified at ~10,000 pps, full detect→block→rollback):
```
h4 hping3 --udp -d 1024 -i u250 -k -s 40001 -p 9999 -q 10.0.0.18 &
h5 hping3 --udp -d 1024 -i u250 -k -s 40002 -p 9999 -q 10.0.0.18 &
```
WRONG (storms the controller — never use for the demo):
```
h4 hping3 --udp -d 512 -i u200 -p 53 10.0.0.18 &      # no -k  ❌
```

The silence you saw = exactly this storm. Reset and use the `-k -s` form.

---

## Option 0 (BEST for a live interactive demo) — one command, verified

`demo_cli.py` starts the ML API + hybrid controller (enforce) + the topology with
**the correct setup** (hosts uncapped, NIC offloads off, victim UDP sinks) and
drops you at the Mininet prompt. This is verified end-to-end: 6 attackers get
detected, attributed, blocked at their ingress switches, then rolled back.

**Terminal 1** — launch everything and get the `mininet>` prompt:
```bash
cd ~/projects/ddos-cicddos2019-ready
sudo python3 experiments/scripts/demo_cli.py
```
**Terminal 2** — show the controller reacting live:
```bash
tail -f /tmp/demo_cli_ryu.log
```
**In the `mininet>` prompt** — benign flow, then a 6-source flood (note `-k -s`):
```text
h7 iperf -u -c 10.0.0.18 -b 2M -t 60 &
h1 hping3 --udp -d 1024 -i u300 -k -s 40001 -p 9999 -q 10.0.0.18 &
h2 hping3 --udp -d 1024 -i u300 -k -s 40002 -p 9999 -q 10.0.0.18 &
h3 hping3 --udp -d 1024 -i u300 -k -s 40003 -p 9999 -q 10.0.0.18 &
h4 hping3 --udp -d 1024 -i u300 -k -s 40004 -p 9999 -q 10.0.0.18 &
h5 hping3 --udp -d 1024 -i u300 -k -s 40005 -p 9999 -q 10.0.0.18 &
h6 hping3 --udp -d 1024 -i u300 -k -s 40006 -p 9999 -q 10.0.0.18 &
```
Within ~10–15 s Terminal 2 shows `CONFIRMED → MITIGATING`, `BLOCK 10.0.0.1..6`.
Stop the flood (`mininet> h1 pkill hping3` … or just wait) → `UNBLOCK ... (recovered)`.
The benign `h7` is never blocked. Exit with `mininet> exit` (it cleans up).

> **Use 6 attackers, not 2.** The detector keys on how *distributed* the traffic
> is; 2 sources is borderline, 6 is a clear, reliable DDoS. Always `-k -s`.

---

## Option 0b (MOST RELIABLE, non-interactive): scripted enforce run

One command does everything correctly (offloads off, victim servers, fixed-port
multi-source flood, detection, scoped mitigation, rollback) and writes a log you
can show. This is what was verified working.

```bash
cd ~/projects/ddos-cicddos2019-ready
sudo mn -c
sudo python3 experiments/scripts/run_experiment.py \
  --campaign show --scenarios C --seeds 2 --duration 75 --cpu 0 --bw 100 \
  --config experiments/configs/hybrid_enforce.yaml
# then show the decision log:
grep -iE "CONFIRMED|MITIGATING|BLOCK|UNBLOCK|RECOVERING" \
  experiments/results/raw/show/C_002/ryu.log
```
Expected (real output from this exact run):
```
dst=10.0.0.18 NORMAL->MITIGATING score=1.000 sources=['10.0.0.3','10.0.0.4'] actions=['block']
BLOCK 10.0.0.3 -> 10.0.0.18 proto=17 at dpids=[1] cookie=dd05000000000001
...
dst=10.0.0.18 MITIGATING->RECOVERING ... actions=['rollback']
UNBLOCK ...
```

---

## Option A (SAFEST for a talk): replay an existing run — no live Mininet

Already-captured runs prove everything and can't fail live.

```bash
# 1. Show the headline results table
cat docs/results_summary.md

# 2. Show the mitigation cycle (detect -> attribute -> block -> rollback) from a real run
grep -iE "CONFIRMED|MITIGATING|BLOCK|UNBLOCK" \
  experiments/results/raw/mit_enforce/C_020/ryu.log

# 3. Open the figures
xdg-open experiments/results/figures/ablation_window.png
xdg-open experiments/results/figures/timeseries_C.png
xdg-open experiments/results/figures/roc_curves.png
xdg-open experiments/results/figures/mitigation_effect.png
```

Talking points straight from the numbers:
- Flow-ML alone: **50 % false-positive rate on benign UDP**, **30.7 false alerts
  per benign run**. That is the problem.
- Our hybrid: UDP FPR **3.6 %**, false alerts **1.3/run**, recall **0.81**, and it
  catches ICMP floods the flow model misses entirely.
- Mitigation: scoped drop rules on `(attacker → victim, proto)` at the attacker's
  ingress switch, auto-rolled back on recovery; legitimate probe keeps full
  goodput (RTT p95 1.70 → 0.82 ms).

---

## Option B (LIVE): run the real controller + Mininet (3 terminals)

Do a dry-run of this once before the audience.

**Terminal 1 — ML API** (keep running):
```bash
cd ~/projects/ddos-cicddos2019-ready
source .venv/bin/activate
DDOS_MODEL_DIR=artifacts/production python -m ddos_ml.predict_api
```

**Terminal 2 — Hybrid controller** (detection + scoped mitigation):
```bash
cd ~/projects/ddos-cicddos2019-ready/Codes/controller
sudo mn -c                                   # clean BEFORE starting Ryu
sudo DDOS_CONFIG=../../experiments/configs/hybrid_enforce.yaml \
  ../../.venv-ryu39/bin/ryu-manager --ofp-tcp-listen-port 6653 hybrid_controller.py
# watch this window: it prints SUSPECTED->CONFIRMED->MITIGATING, BLOCK, UNBLOCK
```

**Terminal 3 — Mininet** (after the 6 switches register in Terminal 2):
```bash
cd ~/projects/ddos-cicddos2019-ready/Codes/mininet
sudo python3 topology.py 127.0.0.1
```
Inside the `mininet>` prompt (note `-k -s` on the attackers — see the warning
at the top of this file):
```text
pingall
h7 iperf -u -c 10.0.0.18 -b 2M -t 60 &                        # legitimate UDP (allowlisted)
h4 hping3 --udp -d 1024 -i u250 -k -s 40001 -p 9999 -q 10.0.0.18 &   # attacker 1 (lab only)
h5 hping3 --udp -d 1024 -i u250 -k -s 40002 -p 9999 -q 10.0.0.18 &   # attacker 2 (lab only)
```
Terminal 2 will show the victim move to **MITIGATING** and install **BLOCK** rules
for h4/h5 only. Stop the attackers (`mininet> ` then Ctrl-C the hping3, or wait)
and it logs **UNBLOCK ... (recovered)**. The legitimate h7 UDP is never blocked.

Panic button (rolls back all drops instantly): in any terminal
```bash
touch ~/projects/ddos-cicddos2019-ready/experiments/MITIGATION_DISABLE
```
Delete that file to re-arm.

To show the **baseline** false-positive problem instead, start Terminal 2 with
`--config experiments/configs/observation.yaml` and the original
`controller.py`: benign large-packet UDP gets flagged as attack.

---

## If something breaks live
- Switches don't register → `sudo mn -c` in Terminal 3's host, restart Ryu.
- Port 6653 busy → `sudo pkill -f hybrid_controller; sudo mn -c`.
- Fall back to **Option A** — the recorded results and figures tell the whole story.

## One-sentence summary for the panel
"A flow-level ML detector false-positives on half of legitimate UDP; we add a
destination-centric, counter-delta temporal layer and a confirm-then-act state
machine that cuts UDP false positives from 50 % to ~4 % and drives scoped,
reversible mitigation that stops the flood while legitimate traffic keeps
flowing."
