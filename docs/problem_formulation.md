# Problem scenario and mathematical formulation

## 1. Scenario

An OpenFlow network G = (S ∪ H, E) has switches S, hosts H and one controller.
A server v ∈ H (the victim) is reached through an access link of capacity C_v
(50 Mbit/s in the large testbed). Legitimate clients L ⊂ H use v and other servers.
An unknown attack set A ⊂ H (bots, A ∩ L = ∅) starts at an unknown time τ_a to send
traffic to v. The controller cannot inspect packets; it only sees

* OpenFlow flow-entry counters, polled every Δ seconds (Δ = 2 s in the large testbed), and
* packet-in messages (first packet of a new flow, with ingress switch and port).

Goal: decide **quickly** that v is under attack, decide **which sources** cause it, and
install a **small number of drop rules at the attackers' ingress switches**, without
blocking legitimate clients and without raising alarms on benign surges (flash crowds,
large-packet UDP streams, bulk TCP).

## 2. Observations

Time is divided into windows t = 1, 2, … of length Δ. For a flow entry f with
cumulative packet/byte counters P_f(t), B_f(t) on the switches of its path, the
per-window deltas are

  x_f(t) = max_{switch on path} [P_f(t) − P_f(t−1)],   b_f(t) = max [B_f(t) − B_f(t−1)]

(maximum, not sum, so a flow crossing five switches is counted once). For a source s and
destination d the window rate is

  λ_{s,d}(t) = (1/Δ) Σ_{f: src(f)=s, dst(f)=d} x_f(t),    Λ_d(t) = Σ_s λ_{s,d}(t).

Level 1 (flow ML): each flow has a 7-feature lifetime vector z_f (protocol, duration,
packets, bytes, packet rate, byte rate, mean packet size) and a classifier
g_θ : R^7 → [0,1] trained on CIC-DDoS2019 + CSE-CIC-IDS2018 gives p_f(t) = g_θ(z_f(t)).

Level 2 (destination window): for every destination d the controller builds
φ_d(t) ∈ R^19 — number of sources n_d, active and new flows, Λ_d, bit rate, mean packet
size, top-source share, normalised source entropy H_d = −Σ_s q_s log q_s / log n_d with
q_s = λ_{s,d}/Λ_d, protocol shares, response ratio ρ_d = (bytes d→sources)/(bytes
sources→d), rate change, packet-in rate and four aggregates of {p_f} (max, mean,
flagged-flow fraction, flagged-packet share). Per (s, d) pair a 10-feature vector φ_{s,d}(t).

## 3. Hypotheses

For every destination and window: H0: y_d(t) = 0 (benign), H1: y_d(t) = 1 (d is the
target of an active attack episode). Attack models covered:

| model | definition |
|---|---|
| volumetric | Σ_{a∈A} λ_{a,v} ≫ C_v / packet size |
| low-rate | λ_{a,v} small for every a, but \|A\| large |
| pulsing | λ_{a,v}(t) = λ · 1{t mod T < T_on} |
| multi-vector / protocol switching | the protocol of a's flows changes over time |
| spoofed | src(packet) ≠ β(sw, port), the address bound to the ingress host port |
| re-attack | a new episode by the same A after mitigation is removed |

## 4. Detector

Window score (logistic, coefficients fitted on calibration runs only):

  s_d(t) = σ( wᵀ ψ(φ_d(t)) + b ),   ψ = log1p on heavy-tailed features + standardisation.

Confirmation rule (state machine), with threshold η, k-of-n window, fast threshold
η_f and repeat-offender set R_d(t):

  confirm_d(t) = 1 if  Σ_{i=0}^{n−1} 1{s_d(t−i) ≥ η} ≥ k
                   or  s_d(t) ≥ η_f
                   or  ( s_d(t) ≥ η  and  R_d(t) ≠ ∅ )

R_d(t) = sources blocked at d during the last M seconds that are sending to d again.

Attribution: for a confirmed d, source score r_{s,d} = σ(uᵀψ(φ_{s,d}) + c) and the block set

  B_d(t) = { s : λ_{s,d} ≥ λ_floor  and  ( r_{s,d} ≥ η_s  or  (λ_{s,d} ≥ λ_rate and corroborated(s)) ) }

where corroborated(s) means the flow model flags s's flows or s opens many new flows.
In addition s must satisfy λ_{s,d} ≥ β·μ_{s,d}, where μ_{s,d} is an EWMA of the source's rate to d
learned only in windows where d is NORMAL and below threshold (pre-attack baseline, β = 3):
a source that already sent like this before the attack (video stream, bulk transfer) is not blocked.
A heavy sender never seen in normal windows counts as corroborated, and a source enters B_d only
after qualifying in 2 consecutive windows (known repeat offenders at once). One
rule per s ∈ B_d matches (ipv4_src = s, ipv4_dst = d) for **all** protocols and is
installed at s's ingress switch. Rules are removed after Q_e quiet windows, with
Q_e = Q · 2^{min(e−1, 3)} for the e-th episode on d (exponential hold-down).

Anti-spoofing: for every host port (sw, p) with bound address β(sw,p),
N_{sw,p,d}(t) = #packet-ins from (sw,p) to d with src ≠ β(sw,p); if N ≥ κ the port is
quarantined for d (rule: in_port = p, ipv4_dst = d → drop).

## 5. Optimisation problem

Detection is a quickest-change-detection problem under a false-alarm constraint:

  minimise_{w,b,η,k,n,η_f}   E[ D ]   with  D = min{ t ≥ τ_a : confirm_v(t) = 1 } − τ_a
  subject to                 P( confirm_d(t) = 1 | H0 ) ≤ ε          (ε = 1 % of benign windows)

Mitigation chooses the block set to maximise legitimate service at the victim:

  maximise_{B_v}   Σ_{s ∈ L} G_{s,v}                                 (legitimate goodput)
  subject to       Σ_{a ∈ A \ B_v} λ_{a,v} + Σ_{s ∈ L} λ_{s,v} ≤ C_v  (attack leftover fits the link)
                   | B_v ∩ L | = 0                                     (no collateral blocking)
                   | B_v | ≤ R_max                                     (flow-table budget)

Neither A nor τ_a is known, so the controller solves a plug-in version: η is set on
calibration data to meet the ε constraint, B_v is estimated by the source scorer, and the
constraint |B_v ∩ L| = 0 is protected by the λ_floor and corroboration conditions.

## 6. Evaluation quantities (all reported)

* window recall P(ŷ=1 | y=1), FPR P(ŷ=1 | y=0), precision, F1
* detection rate per attack episode and latency D
* false-alarm episodes per hour on benign traffic
* residual attack ratio ρ_res = Σ_a λ_{a,v}(after rules) / Σ_a λ_{a,v}(before)
* collateral: legitimate sources blocked; legitimate service ratio (HTTP success,
  UDP request/response success, ping delivery, bulk TCP throughput) versus the benign baseline

## 7. Lower bound on latency

With polling period Δ, the first window that contains the attack ends at most Δ after
τ_a, so D ≥ U·Δ with U ∈ (0, 1]. k-of-n confirmation adds (k−1)·Δ. Hence

  D_min ≈ (k − 1 + U)·Δ.

The original design (Δ = 5 s, k = 2) has D ≥ 5–10 s plus processing, which explains the
12.4 s mean in the first report. With Δ = 2 s and the fast path (η_f) the bound is 1–4 s.
