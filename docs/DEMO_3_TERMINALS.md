# Live presentation demo: 3 terminals

This is the short version of [`DEMO_GUIDE.md`](DEMO_GUIDE.md) for presenting live. It uses
3 terminals instead of 5, runs a single scripted story, and shows two things:
**the attack gets blocked** and **legitimate users keep working**.

Verified on 2026-11-13 (run `experiments/results/demo/20261113-073853_mitigation`): attack
confirmed 8.3 s after it started, 6/6 attackers blocked at their own switch, 98.8 % of attack
traffic removed, all 5 legitimate users preserved, rules removed automatically 21 s after the attack stopped.

## Layout

Put the three windows side by side. In each one, run `cd ~/projects/ddos-cicddos2019-ready` first.

| Terminal | Command | What the audience sees |
|---|---|---|
| **1: System** | `sudo scripts/demo/T1_start_system.sh` | Starts everything (ML API, Ryu controller with protection armed, Mininet). Then prints one coloured line per controller decision: `SUSPECTED`, `ATTACK CONFIRMED`, `BLOCK h1 … at s1`, `UNBLOCK`, `NORMAL`. |
| **2: Dashboard** | `scripts/demo/T2_dashboard.sh` | Updates every 2 s: the victim's score and every host sending to it, with pps, ML probability, and `BLOCKED` when blocked. |
| **3: Demo** | `sudo scripts/demo/T3_run_demo.sh` | The guided story. It waits for Enter between steps so you can talk. |

Start Terminal 1 and wait for **SYSTEM READY** (about 30 s). Then start Terminals 2 and 3.
To stop everything, press **Ctrl-C in Terminal 1**. It cleans up Mininet, the controller and the API.

## The story (Terminal 3)

| Step | Duration | What happens | What to say |
|---|---|---|---|
| 1 | ~15 s | All 17 hosts ping the victim h18 | "The network works; protection is armed." |
| 2 | 25 s | Normal traffic only: h7 TCP, h8 UDP, h9 web, h10 DNS-like, h13 ping | "Real users, several protocols. The victim stays **NORMAL** and nothing is blocked, even with mitigation on." |
| 3 | 40 s | h1 to h6 flood h18 with UDP while the users keep going | "About 8 s later it is **CONFIRMED** (2 of 3 windows). Only h1 to h6 get a drop rule, at their own switch. h7 to h13 are not touched." |
| 4 | 40 s | The attack stops | "No manual action: after 2 quiet windows the rules are removed and the state goes back to **NORMAL**." |
| 5 | ~10 s | Recovery check | "No rules are left, and the former attackers can reach h18 again by ICMP, UDP and HTTP." |

At the end of step 4, Terminal 3 prints the measured result. The headline is the `STATUS` block:

```
>>> ATTACK CONFIRMED
>>> MITIGATION INSTALLED
>>> ATTACK TRAFFIC BLOCKED
>>> LEGITIMATE TRAFFIC PRESERVED
>>> NETWORK RECOVERED
```

Point at the **Legitimate traffic** table. During the unmitigated seconds, web and DNS-like
requests fail 100 %. Once the rules are in, they are back to 0 % loss. TCP stays at 10 Mbit/s throughout.

## Tips

* `sudo scripts/demo/T3_run_demo.sh --auto` runs the story without pauses. Run it once before the talk.
* You can run Terminal 3 again for another round. Terminal 1 keeps running.
* If Terminal 1 prints `FAILED`, read the log it names. Then run `sudo scripts/demo/13_cleanup.sh` and start Terminal 1 again.
* To start without blocking (alert only): `sudo scripts/demo/T1_start_system.sh DETECTION_ONLY`.
  Terminal 3 asks the controller to arm protection before it runs the attack.
* Backup if the live demo fails: the saved results in `experiments/results/demo/*_mitigation/summary.md`.
