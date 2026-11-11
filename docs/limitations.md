# Limitations and Threats to Validity

Stated plainly so results are not over-claimed.

## Testbed / construct validity
- **Emulation, not hardware.** Mininet + OVS in WSL2 share one kernel and CPU.
  Absolute rates, latencies and CPU numbers are environment-specific; only
  *relative* comparisons (method A vs B, attack vs no-attack) are meaningful.
- **Scale.** 6 switches, 18 hosts, ≤6 attackers. Real DDoS has far more sources;
  our "distributed" case is small. Source-count features are validated only in
  this small regime.
- **Traffic realism.** Benign traffic is synthetic (iperf/ping/curl/UDP echo),
  not captured production traffic. It intentionally includes large-packet
  high-rate UDP to stress false positives, but it is not a full workload model
  (no realistic diurnal pattern, no application mix, limited flash-crowd).
- **Attacks.** hping3-style floods and SYN/ICMP floods. No reflection/
  amplification with spoofed real sources, no application-layer DDoS, no
  adaptive adversary reacting to mitigation.

## Data / internal validity
- **Flow-level model data leakage risk remains.** CIC-DDoS2019 has 1.3M
  contradictory 7-feature signatures and 99.4 % attack prevalence. We mitigate
  with group-aware splits and signature purging, but high flow-level accuracy on
  this dataset should not be read as real-world generalisation. We therefore do
  **not** headline a flow-level accuracy figure.
- **No large-packet benign UDP in public data.** Neither CIC-DDoS2019 nor
  CSE-CIC-IDS2018 contains it (see `dataset_audit.md`); the benign large-UDP
  class exists only in our testbed. The false-positive improvement is
  demonstrated on testbed data, not cross-validated on an external dataset with
  the same phenomenon (none is known to us).
- **Level-2 models are trained and tested on the same testbed** (disjoint runs).
  This is an internal, systems-level evaluation, not cross-environment
  generalisation. Thresholds may not transfer to a different topology/link speed
  without recalibration.
- **Ground truth is schedule-based.** A benign flow that coincidentally matches
  attack statistics is still labelled benign; a stray attack packet outside its
  scheduled window is labelled benign. Edge windows at attack start/end are
  inherently ambiguous.

## Measurement
- Counter-delta rates depend on the polling interval and on NIC-offload being
  disabled; with offloads on, packet counters understate true packet counts.
- iperf3/ping probes sample one legitimate path (h7/h13 → victim); other paths
  may differ.
- CPU% is derived from `/proc` tick deltas at 1 Hz; sub-second spikes are missed.

## External validity
- Single controller (Ryu 4.34, legacy). Results may differ on ONOS/Floodlight or
  newer OpenFlow versions.
- Mitigation is evaluated only in the isolated lab, by design.

## What we explicitly do NOT claim
- Not a new ML algorithm.
- Not state-of-the-art accuracy (the metric is false-positive reduction under
  overlap + measured mitigation recovery, not peak accuracy).
- Not validated at production scale, against spoofed/reflected DDoS, or against
  an adaptive adversary.
- Not journal-ready without a larger/physical testbed and broader attack set
  (see `paper_outline.md` §Readiness).
