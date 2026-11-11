# DEMO GUIDE — ML-based DDoS Detection and Mitigation with SDN

This guide lets you run the **whole project live**, from a fresh WSL session:
start the services, generate normal traffic, launch DDoS attacks inside Mininet,
watch the controller detect them, install real OpenFlow blocking rules, prove that
legitimate users keep working, and restore the network.

Everything here was executed and measured on this machine. The numbers in
[Section 9](#9-what-works-and-what-does-not-measured) come from real runs. Nothing
is simulated or printed by hand.

> All attack traffic stays inside the isolated Mininet network `10.0.0.0/24`.
> Never point these tools at any other network.

---

## 0. What you are going to show (one paragraph)

Traffic flows through 6 Open vSwitch switches controlled by a Ryu controller.
Every 5 seconds the controller reads the OpenFlow flow counters from all switches.
It turns them into per-interval rates, asks the **ML model**
(HistGradientBoosting trained on CIC-DDoS2019, served by a small HTTP API) about every
flow, and combines that with **destination-level window features** (how many sources hit
the same victim, total packets/s, packet sizes, replies, …). A logistic **window model**
gives a score per victim. A state machine needs 2 of the last 3 windows above the
threshold before it says **ATTACK CONFIRMED** (one noisy window is not enough).
If mitigation is enabled, the controller picks the sources responsible and installs a
**drop rule** for exactly `attacker IP → victim IP, protocol` at the attacker's own
switch. When the attack stops, the rules are removed automatically.

```
 hosts ──► OVS switches s1..s6 ──(OpenFlow 1.3 flow stats every 5 s)──► Ryu hybrid_controller.py
                ▲                                                         │  Level 1: flow-level ML  ──► ML API :8765
                │                                                         │  Level 2: per-victim window features
                └──── OpenFlow DROP rule (attacker → victim, proto) ◄─────┘  Level 3: state machine + mitigation
                                                                             REST API :8080 (status, rules, mode)
```

Mitigation modes (the controller starts in the first one):

| mode | what happens on a confirmed attack |
|---|---|
| `DETECTION_ONLY` (default) | alert only, the network is never touched |
| `DRY_RUN` | alert + log the exact rules it *would* install (none installed) |
| `MITIGATION_ENABLED` | alert + install real OpenFlow drop rules (lab only) |

---

## 1. The network

```
 h1 h2 h3     h4 h5 h6     h7 h8 h9     h10 h11 h12    h13 h14 h15    h16 h17 h18
    \|/          \|/          \|/            \|/            \|/            \|/
    s1 ───────── s2 ───────── s3 ─────────── s4 ─────────── s5 ─────────── s6
```

* 6 switches in a chain, 18 hosts, links 100 Mbit/s. Host `hN` has IP `10.0.0.N`.
* **Victim: h18 = 10.0.0.18.** Attackers in the demo: **h1–h6** (on s1 and s2).
* Legitimate clients in the demo: h7, h8, h9, h10, h13 (and h11, h12, h14, h15 for normal traffic).
* Controller: `127.0.0.1:6653` (OpenFlow), REST API `127.0.0.1:8080`. ML API: `127.0.0.1:8765`.
* The victim runs: iperf3 servers on ports 5201–5220, iperf (v2) TCP+UDP server on 5001,
  a web server on port 80, a DNS-like UDP server on 5353, and silent UDP sinks on
  53/123/1900/8080/9999.

---

## 2. One-time check (do this first, every time you open WSL)

**Terminal 4** (any WSL terminal):

```bash
cd ~/projects/ddos-cicddos2019-ready
sudo scripts/demo/00_preflight.sh
```

What it does: checks both Python environments, the saved models, the tools
(mininet, ovs, hping3, iperf, iperf3, …), starts Open vSwitch, and runs `mn -c`
to clean old Mininet state.

Success looks like:

```
  [OK]   ML venv (.venv, Python 3.12) imports sklearn/joblib
  [OK]   Ryu venv (.venv-ryu39, Python 3.9) imports ryu
  ...
== Cleaning old Mininet state (mn -c) - safe now because Ryu is not running
== PREFLIGHT PASSED
```

If it says `[INFO] Ryu and/or ML API already running`, stop them first (Ctrl-C in
their terminals, or `sudo scripts/demo/13_cleanup.sh`) and run the preflight again.

> **Why the order matters:** `mn -c` also kills `ryu-manager`. Always clean
> *before* starting Ryu, never after. The Mininet launcher in this guide never runs
> `mn -c`, so it is safe to start after Ryu.

---

## 3. Start the system (Terminals 1, 2, 3)

Open **five** WSL terminals. In each, first type `cd ~/projects/ddos-cicddos2019-ready`.

### Terminal 1 — ML prediction API

| | |
|---|---|
| Directory | `~/projects/ddos-cicddos2019-ready` |
| Virtual env | `.venv` (Python 3.12). The script activates it for you. |
| Command | `scripts/demo/01_start_ml_api.sh` (no sudo needed) |
| Starts | the flow-level ML model (`artifacts/production/hist_gradient_boosting.joblib`) as an HTTP API on 127.0.0.1:8765 |

Equivalent manual commands (what the script runs):

```bash
cd ~/projects/ddos-cicddos2019-ready
source .venv/bin/activate
DDOS_MODEL_DIR=artifacts/production python -m ddos_ml.predict_api
```

Expected output:

```
ML prediction API listening on http://127.0.0.1:8765
Model: Hist Gradient Boosting (hist_gradient_boosting.joblib)
```

Check it (from any other terminal):

```bash
curl http://127.0.0.1:8765/health
# {"status": "ok", "selected_model": "Hist Gradient Boosting", "model_file": "hist_gradient_boosting.joblib"}
```

While the demo runs, this terminal prints one line per batch the controller sends:
`[ML API] "POST /predict HTTP/1.1" 200 -`. That is the controller asking the model.

If it fails: `Address already in use` → an old API is running (`pkill -f ddos_ml.predict_api`).
Model file errors → run the preflight; the model must exist in `artifacts/production/`.

### Terminal 2 — Ryu controller

| | |
|---|---|
| Directory | `~/projects/ddos-cicddos2019-ready` |
| Virtual env | `.venv-ryu39` (Python 3.9, Ryu 4.34). The script uses it directly. |
| Command | `sudo scripts/demo/02_start_controller.sh` |
| Starts | `Codes/controller/hybrid_controller.py` on port 6653 (OpenFlow) + REST API on 127.0.0.1:8080, mode **DETECTION_ONLY** |

Equivalent manual commands:

```bash
cd ~/projects/ddos-cicddos2019-ready/Codes/controller
sudo DDOS_CONFIG=../../experiments/configs/demo.yaml DDOS_MITIGATION_MODE=DETECTION_ONLY \
     DDOS_FLOW_IDLE_TIMEOUT=10 DDOS_TELEMETRY_JSONL=../../experiments/results/demo/logs/telemetry.jsonl \
     ../../.venv-ryu39/bin/ryu-manager --ofp-tcp-listen-port 6653 \
     --wsapi-host 127.0.0.1 --wsapi-port 8080 hybrid_controller.py
```

(Optional: `sudo scripts/demo/02_start_controller.sh DRY_RUN` or `... MITIGATION_ENABLED`
to start directly in another mode.)

Expected output:

```
Starting Ryu hybrid controller  mode=DETECTION_ONLY  config=.../experiments/configs/demo.yaml
instantiating app hybrid_controller.py of HybridDetector
HybridDetector: method=hybrid poll=5.0s confirm=2/3 MODE=DETECTION_ONLY (detection.mode=enforce)
(…) wsgi starting up on http://127.0.0.1:8080
```

After Terminal 3 starts, you will see the switches connect:

```
Registered switch 0000000000000001 (s1) - 1 switch(es) connected
...
Registered switch 0000000000000006 (s6) - 6 switch(es) connected
```

**Check that all six switches are connected** (any terminal):

```bash
scripts/demo/mitigation_ctl.sh status
# mode=DETECTION_ONLY  switches=6/6 ['s1', 's2', 's3', 's4', 's5', 's6']  poll=12  ML-API=ok  rules=0
```

If it fails: `Address already in use` on 6653/8080 → another ryu-manager is running
(`sudo pkill -f ryu-manager`). Switches stay at 0/6 → start Terminal 3 after this one; if
it still fails, `sudo scripts/demo/13_cleanup.sh` and start again from Section 2.

### Terminal 3 — Mininet

| | |
|---|---|
| Directory | `~/projects/ddos-cicddos2019-ready` |
| Virtual env | none (Mininet uses the system Python, as root) |
| Command | `sudo scripts/demo/03_start_mininet.sh` |
| Starts | the 6-switch/18-host network from `Codes/mininet/topology.py` (class `MyTopo`, unchanged) and opens the `mininet>` prompt |

What the launcher adds around the original topology (all of it was needed to make the
measurements real):

* hosts **not CPU-capped** (the topology's default 5 % CPU per host throttles all traffic);
* 100 Mbit/s links; NIC offloads off (so OpenFlow counters count real packets);
* **packet-in rate limit 500 pps per switch**, the standard OVS control-plane protection.
  Without it, a flood's first packets queue thousands of packet-ins at the Python controller.
  It then needs about a minute to drain them, and ARP and legitimate flow setup starve
  (measured; see Section 9);
* the victim services listed in Section 1;
* it writes `experiments/results/demo/run/lab_state.json` so Terminal 4 can run traffic inside the hosts.

Expected output (ends with):

```
*** Packet-in rate limit: 500 pps per switch (burst 100)
*** Controller reports 6/6 switches connected
*** Starting victim services on h18 (10.0.0.18)
========================================================================
 LAB READY: 6 switches (s1..s6 chain), 18 hosts, victim h18 = 10.0.0.18
...
mininet>
```

The lines `sch_htb: quantum of class … is big` are a harmless Linux traffic-shaping warning.

Try it:

```text
mininet> nodes
mininet> h1 ping -c 5 h18
mininet> h7 iperf -c 10.0.0.18 -t 5
mininet> h8 iperf -u -c 10.0.0.18 -b 2M -t 5
```

Measured on this machine: ping 0 % loss; TCP ≈ 94–95 Mbit/s; UDP 2 Mbit/s with 0 % loss.

Stop the lab with `mininet> exit` (it stops all traffic and services and removes the switches).

If it fails: `Run as root` → use `sudo`. "0/6 switches" → Terminal 2 is not running.
"File exists" errors → `sudo scripts/demo/13_cleanup.sh`, then restart from Section 2.

> **Mininet CLI vs Terminal 4.** You can type traffic commands at the `mininet>` prompt
> (good for showing single commands), **or** run the scenario scripts in Terminal 4. The scripts
> run the same tools *inside* the Mininet hosts (via `mnexec`). They also start many hosts at
> once, track every process, stop them reliably, measure everything and save a report.
> Use the scripts for the real demonstration.

### Terminal 5 — Monitoring

Choose one (or open two monitoring terminals):

```bash
# a) live dashboard (state per victim, per-source rates, rules, events) - refreshes every 2 s
scripts/demo/watch_status.sh

# b) the controller's own log: per-window lines, DDoS ALERT blocks, rule install/remove
tail -f experiments/results/demo/logs/ryu.log | grep -v -E 'wsgi|accepted|GET /ddos'
```

What you will see in the controller log (real lines from the verification run):

```
[poll 31] dst=10.0.0.18  NORMAL TRAFFIC     score=0.000 (thr 0.682) sources=2 flows=2 pps=255 rate=2.09Mbps avg_pkt=1024B | flow-ML max_p=0.99 flagged=50%
==============================================================================
DDoS ALERT  victim=10.0.0.18  ATTACK CONFIRMED  window score=1.000 (threshold 0.682)
  sources=8  active flows=8  aggregate=... pps / ... Mbps  avg pkt=... B
  flow-level ML (CIC-DDoS2019 model): max attack prob=..., ..% of flows flagged
  strongest evidence: n_sources +5.30, pps +3.40, ...
  top senders: 10.0.0.5(2600pps), 10.0.0.1(2100pps), ...
  mitigation mode: MITIGATION_ENABLED
==============================================================================
MITIGATION INSTALLED: DROP 10.0.0.1 -> 10.0.0.18 UDP at ['s1'] priority=200 hard_timeout=120s cookie=0xdd05000000000001
...
MITIGATION REMOVED: DROP 10.0.0.1 -> 10.0.0.18 UDP (recovered, active 31.9s, 62000 packets dropped)
dst=10.0.0.18 back to NORMAL TRAFFIC
```

---

## 4. Where every output goes

| what | where |
|---|---|
| Controller log (alerts, rules) | `experiments/results/demo/logs/ryu.log` |
| ML API log | `experiments/results/demo/logs/ml_api.log` |
| Per-window telemetry (every flow, feature, decision) | `experiments/results/demo/logs/telemetry.jsonl` |
| One folder per test | `experiments/results/demo/<date-time>_<scenario>/` |
| … human-readable report | `…/summary.md` |
| … all metrics | `…/result.json` |
| … 1-second timeline (state, score, measured rates) | `…/timeline.csv` |
| … controller events (state changes, rules) | `…/events.json` |
| … rules as the controller AND the switches reported them | `…/rules_at_peak.json`, `…/ovs_drop_rules.txt` |
| … raw output of every traffic generator | `…/hosts/*.log` |
| One row per test (all tests) | `experiments/results/demo/demo_results.csv` |
| Live state | `scripts/demo/mitigation_ctl.sh status` / `list` / `events` |

`demo_results.csv` columns include: scenario, start/end, mode, traffic type, number of
attack sources, victim IP, packet sizes, configured per-source rate, **measured** offered
attack pps, delivered attack pps before/after mitigation, reduction %, detected, max
state, max window score, flow-ML probability, detection / suspicious / mitigation
latency, rules installed, rules on legitimate hosts, legitimate TCP throughput and UDP
loss before/during/after, legitimate status, recovered, recovery time, statuses.

How things are measured (so you can explain it):

* **offered attack pps** = packets the attacker hosts pushed into their switch ports (kernel counters).
* **delivered attack pps** = packets from the attackers forwarded by the victim's switch s6
  (OpenFlow flow counters). The drop rules sit at s1/s2, so blocked packets never reach s6.
* **legitimate traffic** = iperf3 reports (TCP throughput; UDP loss from the receiver side),
  ping replies, HTTP downloads and DNS-like answers, each split into phases:
  before the attack / attack not yet mitigated / mitigated / after.
* **latencies** are measured from the moment the attack processes started.

---

## 5. Run the scenarios (Terminal 4)

All scripts: `cd ~/projects/ddos-cicddos2019-ready` first, run with `sudo`. Each attack
test takes about 95 s (15 s normal traffic, 40 s attack, 40 s recovery) and prints a live
line per controller window, then a result block ending in `STATUS:` lines. A status is
printed **only if the measurements support it**.

### 04 — connectivity

```bash
sudo scripts/demo/04_test_connectivity.sh
```

Expected: `switches=6/6`, ML API OK, `h1/h7/h13 -> h18 : OK`, `all 17 hosts -> h18 : OK`,
`RESULT: CONNECTIVITY OK`.

### 05 — Scenario A: normal traffic only

```bash
sudo scripts/demo/05_test_benign_traffic.sh
```

Six legitimate clients at the same time for ~65 s: h11 TCP (iperf3, 20 Mbit/s),
h12 UDP 200 B @ 1 Mbit/s, h14 UDP 1400 B @ 8 Mbit/s, h15 UDP 512 B @ 4 Mbit/s,
h9 HTTP downloads, h10 ping. Expected status: `NORMAL TRAFFIC` and
`LEGITIMATE TRAFFIC PRESERVED`.

Point to make: the **flow-level ML alone flags the large-packet benign UDP streams with
probability ≈ 1.00** (that is the known false-positive problem). The **hybrid decision
still says NORMAL**, because the destination-level evidence does not look like a DDoS.

### 05b — Scenario A2: flash crowd (known limitation, show only in DETECTION_ONLY)

```bash
sudo scripts/demo/05b_test_flash_crowd.sh
```

Nine legitimate clients at once (~37 Mbit/s). Measured result: **false alarm,
ATTACK CONFIRMED on benign traffic.** The window model weights "number of concurrent
sources" very heavily. See Section 9. Do **not** run this with mitigation enabled unless you
want to show that it would then block two legitimate UDP clients (measured).

### 06 — Scenario B: multi-source UDP flood

```bash
sudo scripts/demo/06_test_udp_attack.sh
```

h1–h6 flood h18 with UDP (different sizes 256–1400 B, rates 2000–4000 pps configured,
destination ports 53/123/1900/8080/9999, fixed source port each). h7 sends legitimate UDP
(2 Mbit/s) and h13 pings during the whole test. The result block shows sources, victim,
active sources/flows, aggregate rate, flow-ML probability, window score, per-source table
and the final decision. In `DETECTION_ONLY` it ends with
`DETECTION ONLY: NO MITIGATION (mode DETECTION_ONLY)`.

### 07 — Scenario C: TCP SYN flood (EXPERIMENTAL — not detected)

```bash
sudo scripts/demo/07_test_tcp_attack.sh                  # random source port per SYN (realistic)
sudo scripts/demo/07_test_tcp_attack.sh --syn-mode fixed # fixed source port per attacker
```

Measured result: **ATTACK NOT DETECTED** in both variants. See Section 9 for why. Present it
as a limitation / future work, not as a working feature.

### 08 — Scenario D: ICMP flood

```bash
sudo scripts/demo/08_test_icmp_attack.sh
```

h1–h6 send ICMP floods (128–1000 B). The flow-level ML is blind to ICMP (probability ≈ 0.002);
the detection comes from the destination-level window model and is reliable (confirmed in
10–11 s in every run). **Blocking ICMP attackers is unreliable**: in one run all six were
blocked (and h13's ordinary ping to the same victim kept working), in the final verification
run none were, because their per-source scores (0.66–0.81) stayed below the 0.911 threshold
and nothing corroborates them. See Section 9.

### 09 — Scenario E: mixed legitimate + attack

```bash
sudo scripts/demo/09_test_mixed_traffic.sh                # attack = UDP flood (default)
sudo scripts/demo/09_test_mixed_traffic.sh --attack icmp
```

Legitimate: h7 TCP transfer (10 Mbit/s), h8 UDP (2 Mbit/s), h9 HTTP downloads,
h10 DNS-like queries (20/s, new source port each), h13 ping, while h1–h6 attack.
Works in every mode: in `DETECTION_ONLY`/`DRY_RUN` it shows detection and which sources
*would* be blocked; with mitigation it is the same as step 11.

### 10 — enable mitigation (explicit, lab only)

```bash
scripts/demo/10_enable_mitigation.sh            # -> MITIGATION_ENABLED
scripts/demo/10_enable_mitigation.sh DRY_RUN    # -> log-only mode
```

Expected: `{"previous": "DETECTION_ONLY", "mode": "MITIGATION_ENABLED", ...}`.
The controller only accepts this because `experiments/configs/demo.yaml` says
`detection.mode: enforce` (a double opt-in).

### 11 — full mitigation demonstration

```bash
sudo scripts/demo/11_verify_mitigation.sh               # UDP flood + legitimate clients  (use this one)
sudo scripts/demo/11_verify_mitigation.sh --attack icmp # detected, but blocking is unreliable (Section 9)
```

Refuses to run unless the mode is `MITIGATION_ENABLED`. Expected final statuses:

```
  >>> NORMAL TRAFFIC
  >>> SUSPICIOUS TRAFFIC
  >>> ATTACK CONFIRMED
  >>> MITIGATION INSTALLED
  >>> ATTACK TRAFFIC BLOCKED
  >>> LEGITIMATE TRAFFIC PRESERVED
  >>> NETWORK RECOVERED
```

The report also prints the rules exactly as Open vSwitch holds them, e.g.

```
cookie=0xdd05000000000001, duration=13.4s, n_packets=28680, ..., priority=200,udp,nw_src=10.0.0.1,nw_dst=10.0.0.18 actions=drop
```

While it runs, in another terminal:

```bash
scripts/demo/mitigation_ctl.sh list        # rules as the controller knows them (+ packets dropped)
sudo scripts/demo/mitigation_ctl.sh ovs    # rules as the switches hold them (ground truth)
```

### 12 — disable mitigation and verify recovery

```bash
sudo scripts/demo/12_disable_mitigation.sh
```

Switches back to `DETECTION_ONLY` (removes every controller rule), deletes any leftover
drop rule directly on the switches, stops all traffic generators, then checks that
**every attacker host can reach h18 again with ICMP, UDP and TCP/HTTP**.
Expected: `RESULT: NETWORK RECOVERED`.

### 13 — stop everything

```bash
sudo scripts/demo/13_cleanup.sh
```

Stops traffic, Mininet, Ryu and the ML API, runs `mn -c`. (Or: `exit` in Terminal 3,
Ctrl-C in Terminals 1 and 2.)

### Run everything unattended (~20 min)

```bash
sudo scripts/demo/run_full_verification.sh | tee /tmp/verification.txt
```

Starts all services in the background and runs 04 → 05 → 05b → 06 → 08 → 07 → 07 fixed →
09 → 10 → 11 (UDP) → 11 (ICMP) → 12 → 13. Use it the day before the presentation to confirm
the machine behaves as below.

---

## 6. Mitigation controls (any terminal)

```bash
scripts/demo/mitigation_ctl.sh status            # mode, switches, ML API, per-victim state
scripts/demo/mitigation_ctl.sh list              # active rules: cookie, match, switch, age, packets dropped
sudo scripts/demo/mitigation_ctl.sh ovs          # the same rules read directly from the switches
scripts/demo/mitigation_ctl.sh remove 0xdd05000000000003   # remove one rule (cookie from `list`)
scripts/demo/mitigation_ctl.sh remove-all        # remove every rule
scripts/demo/mitigation_ctl.sh mode              # show mode
scripts/demo/mitigation_ctl.sh mode DRY_RUN      # change mode
scripts/demo/mitigation_ctl.sh events            # recent alerts / state changes / rule events
```

Raw REST equivalents: `curl http://127.0.0.1:8080/ddos/status`, `…/ddos/rules`,
`curl -X DELETE …/ddos/rules`, `curl -X DELETE …/ddos/rules/<cookie>`,
`curl -X POST -d '{"mode":"DRY_RUN"}' …/ddos/mode`, `…/ddos/events?since=0`.

What the rules are:

* match `eth_type=IPv4, ipv4_src=<attacker>, ipv4_dst=<victim>, ip_proto=<UDP|TCP|ICMP>`,
  action **drop**, priority 200 (forwarding rules are priority 1), installed only at the
  attacker's **ingress switch**. The attacker can still reach every other host, and the victim
  with other protocols.
* every rule has a `hard_timeout` of 120 s (it disappears by itself if forgotten), and is
  removed automatically 2 quiet windows after the attack stops.
* a source is only blocked if it (a) sends ≥ 50 pps to the victim **and** (b) is selected by
  the per-source model, or sends ≥ 800 pps **and** is corroborated by the flow-level ML or by
  heavy new-flow churn. A high rate alone never gets a host blocked.
* if you remove rules while the attack continues and the mode is still `MITIGATION_ENABLED`,
  the controller **re-blocks within 1–2 windows** (measured: 8 s). To stop blocking, change the
  mode (`12_disable_mitigation.sh`).
* emergency stop: `touch experiments/MITIGATION_DISABLE` makes the controller roll back all
  rules at the next window (delete the file to re-arm).

---

## 7. The presentation (about 15 minutes)

Before the professor arrives: Section 2 + Section 3 (Terminals 1, 2, 3 running, Terminal 5
showing `watch_status.sh`), then `sudo scripts/demo/04_test_connectivity.sh`.

**Part 1 — the network is up (1 min)**
Terminal 2: six `Registered switch` lines. Terminal 4: `04_test_connectivity.sh` →
`CONNECTIVITY OK`. Terminal 3: `mininet> h1 ping -c 3 h18`.

**Part 2 — normal traffic (2 min)**
`sudo scripts/demo/05_test_benign_traffic.sh`. Point at Terminal 5: six clients, ~4–5k pps,
flow-ML max probability ~1.00 on the UDP streams, yet the state stays **NORMAL TRAFFIC**.
Explain: "the flow model alone would raise a false alarm here; the destination-level view does not."

**Part 3 — attack, detection only (2 min)**
`sudo scripts/demo/06_test_udp_attack.sh`. Terminal 5 / Terminal 2: SUSPICIOUS after
one window, then the **DDoS ALERT** block (sources, rate, flow-ML probability, strongest
evidence, top senders). Mode is `DETECTION_ONLY`, so no rule is installed. Show
`scripts/demo/mitigation_ctl.sh list` → 0 rules.

**Part 4 — mitigation (3 min)**
`scripts/demo/10_enable_mitigation.sh`, then `sudo scripts/demo/11_verify_mitigation.sh`.
During the attack: `scripts/demo/mitigation_ctl.sh list` and
`sudo scripts/demo/mitigation_ctl.sh ovs`. That's 6 drop rules, one per attacker, at s1/s2, with
`n_packets` growing.

**Part 5 — legitimate traffic preserved (2 min)**
In the result block: h7's TCP transfer keeps ~10 Mbit/s before/during/after; h8's UDP
0 % loss; HTTP and DNS-like clients, which failed during the unmitigated part of the attack,
are back to ~0 % loss once the rules are in. `LEGITIMATE TRAFFIC PRESERVED`. No allow-list is
used: legitimate hosts are spared by the attribution policy, not by exemption.

**Part 6 — recovery (2 min)**
The rules disappear by themselves after the attack (`MITIGATION REMOVED … (recovered)`).
Then `sudo scripts/demo/12_disable_mitigation.sh` → `RESULT: NETWORK RECOVERED`.

**Part 7 — honesty slide (1 min)**
Show Section 9: UDP floods work end-to-end (detect, block, preserve, recover); ICMP floods are
detected but not reliably blocked; TCP SYN floods are not detected; a 9-client flash crowd
causes a false alarm. Then show where the evidence lives
(`experiments/results/demo/`).

If anything misbehaves live: `sudo scripts/demo/13_cleanup.sh`, then Sections 2–3 again
(about 1 minute), or show the saved reports in `experiments/results/demo/*/summary.md`.

---

## 8. Doing it by hand at the mininet> prompt (optional)

Attack commands **must** pin the source port with `-k -s <port>`. A flood without it uses
a new source port per packet. In this reactive controller every packet then becomes a new
flow and a packet-in (see SYN results).

```text
mininet> h18 ps aux | grep -c iperf3          # victim services are running
mininet> h7 iperf3 -c 10.0.0.18 -p 5210 -t 60 -b 10M &        # legitimate TCP
mininet> h1 hping3 --udp -d 1024 -i u333 -k -s 40001 -p 9999 -q 10.0.0.18 &
mininet> h2 hping3 --udp -d 512  -i u333 -k -s 40002 -p 53   -q 10.0.0.18 &
mininet> h3 hping3 --udp -d 1400 -i u500 -k -s 40003 -p 123  -q 10.0.0.18 &
mininet> h4 hping3 --udp -d 1024 -i u333 -k -s 40004 -p 1900 -q 10.0.0.18 &
mininet> h5 hping3 --udp -d 256  -i u250 -k -s 40005 -p 8080 -q 10.0.0.18 &
mininet> h6 hping3 --udp -d 768  -i u400 -k -s 40006 -p 9999 -q 10.0.0.18 &
   ... watch Terminal 2 / 5 ...
mininet> h1 pkill hping3                       # stops all hping3 (all hosts share the process table)
```

Or, from Terminal 4: `sudo python3 scripts/demo/demo_runner.py stop` stops every traffic generator.

---

## 9. What works and what does not (measured)

Final verification run, 2026-11-11, one unattended pass of
`sudo scripts/demo/run_full_verification.sh` in the order of this guide. Each row is a folder
in `experiments/results/demo/`; the full machine-generated table (all columns) is
`experiments/results/demo/SUMMARY.md`, regenerated with
`python3 scripts/demo/summarize_results.py --out experiments/results/demo/SUMMARY.md`.
Latencies are from the moment the attack processes started.

| scenario (folder) | mode | decision | confirmed after | attack pps at victim's switch | legitimate clients | recovered after attack |
|---|---|---|---:|---|---|---:|
| benign, 6 clients (`222956_benign`) | DETECTION_ONLY | 1 SUSPICIOUS window (0.928), never confirmed | – | – | all preserved | – |
| flash crowd, 9 clients (`223101_crowd`) | DETECTION_ONLY | **false alarm: CONFIRMED** (0.869) | – | – | all fine (nothing blocked) | – |
| UDP flood h1–h6 (`223207_udp`) | DETECTION_ONLY | CONFIRMED | 11.3 s | 10,719 (not blocked) | fine | 24.9 s |
| ICMP flood h1–h6 (`223401_icmp`) | DETECTION_ONLY | CONFIRMED | 11.1 s | 6,951 (not blocked) | fine | 23.9 s |
| SYN flood, random ports (`223538_syn`) | DETECTION_ONLY | **not detected** (max 0.027) | – | 3 | degraded | connectivity check failed right after |
| SYN flood, fixed ports (`223743_synfixed`) | DETECTION_ONLY | **not detected** (1 suspicious window) | – | 12,529 | fine | yes |
| mixed + UDP flood (`223920_mixed`) | DETECTION_ONLY | CONFIRMED | 8.5 s | 11,777 (not blocked) | fine | 20.9 s |
| **mixed + UDP flood (`224056_mitigation`)** | **MITIGATION_ENABLED** | **CONFIRMED, 6 rules (s1, s2)** | **11.7 s** (rules same window) | **9,334 → 0 (−100 %)** | **all 5 preserved, no rule on a legit host** | **23.9 s** |
| mixed + ICMP flood (`224233_mitigation`) | MITIGATION_ENABLED | CONFIRMED, **0 rules** | 10.4 s | 7,131 (not blocked) | HTTP + ping degraded | 22.9 s |
| `12_disable_mitigation.sh` | → DETECTION_ONLY | 0 rules in controller and OVS | | | all 6 attackers reach h18 by ICMP, UDP, HTTP | **NETWORK RECOVERED** |

Legitimate traffic in the UDP mitigation run (`224056_mitigation`), per phase:

| client | before attack | attack, not yet mitigated | mitigated | after |
|---|---|---|---|---|
| h7 TCP 10 Mbit/s | 10.0 Mbit/s | 9.96 | 10.0 | 9.96 |
| h8 UDP 2 Mbit/s | 0 % loss | 0 % | 0 % | 0 % |
| h9 HTTP downloads | 0 % failed | **100 % failed** | 0 % | 0 % |
| h10 DNS-like 20 q/s | 0 % loss | **48 % loss** | 0 % | 0 % |
| h13 ping | 0.34 ms | 49.5 ms | 0.38 ms | 0.47 ms |

### What works (verified)

* Startup from a clean WSL session, 6/6 switches, all hosts reach h18.
* Normal multi-protocol traffic from 6 clients stays NORMAL (flow-level ML alone flags it).
* **UDP floods: detected in ~8–12 s, attackers blocked at their ingress switches, 100 % of the
  attack removed at the victim, every legitimate client preserved, automatic rollback ~24 s
  after the attack ends.**
* ICMP floods: detected in ~10–11 s.
* DETECTION_ONLY / DRY_RUN / MITIGATION_ENABLED, list/remove rules, emergency disable,
  recovery check, automatic reports.

### What does not work (measured, not hidden)

* **ICMP blocking is unreliable.** Attackers' per-source scores were 0.66–0.81 (< 0.911) and the
  flow-level ML cannot corroborate ICMP, so the rate rule never fires. One earlier run blocked
  all six; the final run blocked none. Cause: the corroboration rule added to stop the blocking
  of a legitimate fast TCP transfer. Possible fix (not applied): accept a source score above a
  lower bar (e.g. 0.6) as corroboration, or add an ICMP-specific signal.
* **TCP SYN floods are not detected.** Random-port SYNs become one new flow + packet-in each in
  this reactive controller (≈20,000 short-lived rules, ~3–10 SYN/s reach the victim); the
  random-port run also left connectivity briefly broken right after the attack (it heals once
  the rules expire). Fixed-port SYNs reach the victim (~12,500 pps) but score only 0.19–0.27
  after the first window. Present as future work.
* **Flash crowd false alarm.** 9 concurrent legitimate clients → ATTACK CONFIRMED; with
  mitigation enabled (development run) two legitimate UDP clients were blocked. The window
  model weighs `n_sources` heavily; ≤ 6 clients stay normal, ≥ 8 alarm with this traffic mix.
* **Thin benign margin.** A 6-client benign run peaked at 0.59 in one run and had one
  0.93 window in another (when flows from the preceding connectivity test were still counted).

### Development findings that changed the design

Kept in `experiments/results/demo/_development/` as evidence:

* without the OVS packet-in limit, a flood's start queued ~1 min of packet-ins at the
  controller; ARP starved and attackers *and* legitimate hosts stopped sending for ~12 s;
* the original rate-only attribution (≥ 800 pps) blocked the legitimate h7 TCP transfer;
* the source model blocked a DNS-like client sending 0.1 pps (many new flows), fixed by a
  strict 50 pps floor.

---

## 10. Troubleshooting

| symptom | cause / fix |
|---|---|
| `controller REST API not reachable` | Terminal 2 not running, or crashed: check `experiments/results/demo/logs/ryu.log` for a Traceback |
| `lab_state.json not found` | Terminal 3 not running (or it was stopped with `exit`) |
| `only 0/6 switches connected` | start order: preflight → T1 → T2 → T3. Fix: `sudo scripts/demo/13_cleanup.sh`, restart |
| ryu-manager died right after `mn -c` | `mn -c` kills ryu-manager; only run it (via preflight/cleanup) before starting Ryu |
| controller silent during an attack | a flood without `-k -s` (random ports) → packet-in storm. Stop it (`demo_runner.py stop`), wait 30 s |
| `this step needs MITIGATION_ENABLED` | run `scripts/demo/10_enable_mitigation.sh` first |
| `ML API unavailable` in ryu.log | Terminal 1 stopped; detection continues without flow-level evidence (degraded) |
| a rule is left over | `sudo scripts/demo/12_disable_mitigation.sh` (removes via controller and directly in OVS) |
| `sch_htb: quantum … is big` | harmless warning from 100 Mbit/s traffic shaping |
| results folders owned by root | `sudo chown -R $USER: experiments/results/demo` |

---

## 11. Files added for the demo

| file | purpose |
|---|---|
| `Codes/controller/hybrid_controller.py` | detector + mitigation, now with modes, REST API, readable alerts (pipeline unchanged) |
| `ddos_ml/mitigation.py` | modes, drop-rule table, status labels (unit-tested) |
| `ddos_ml/config.py`, `ddos_ml/decision_engine.py` | mode resolution; runtime mode switch; attribution safeguards (unit-tested) |
| `experiments/configs/demo.yaml` | the demo configuration (DETECTION_ONLY at start, no allow-list) |
| `scripts/demo/00…13_*.sh`, `05b_*.sh` | the step scripts used above |
| `scripts/demo/mininet_lab.py` | lab launcher around the unchanged `MyTopo` |
| `scripts/demo/demo_runner.py`, `demolib.py` | traffic orchestrator, measurement and reports |
| `scripts/demo/ctl.py`, `mitigation_ctl.sh`, `watch_status.sh` | operator controls and dashboard |
| `scripts/demo/udp_sink.py`, `udp_probe.py` | victim UDP sink; measuring DNS-like client |
| `scripts/demo/run_full_verification.sh` | unattended end-to-end verification |
| `tests/test_mitigation.py` | tests for modes, rule table, runtime mode switch, attribution safeguards |

The production model in `artifacts/production/` and the topology file were not modified.
