# Demo result: 20261111-220337_udp

- scenario: **udp**  traffic: **UDP**  mode: **DETECTION_ONLY**
- start 2026-11-11T22:03:37  end 2026-11-11T22:05:12  victim 10.0.0.18

Detection (controller view at the highest-scoring window):
  max state: CONFIRMED   max window score: 1.000 (threshold 0.682)
  sources=8  active flows=8  aggregate=6717 pps / 44.88 Mbps  avg pkt=835 B
  flow-level ML (CIC-DDoS2019 model): max attack probability=0.999, 88% of flows flagged
  per-source view at that window (pps | flow-ML max prob | source score | blocked):
    10.0.0.5       1332 pps | 0.87 | 0.90 | no
    10.0.0.2       1154 pps | 1.00 | 0.91 | no
    10.0.0.1       1116 pps | 1.00 | 0.91 | no
    10.0.0.4       1093 pps | 1.00 | 0.91 | no
    10.0.0.6        967 pps | 1.00 | 0.91 | no
    10.0.0.3        851 pps | 1.00 | 0.91 | no
    10.0.0.7        200 pps | 0.99 | 0.66 | no
    10.0.0.13         4 pps | 0.00 | 0.04 | no
  latency from attack start: suspicious=8.0 s, confirmed=11.7 s, first rule=- s

Attack traffic (measured on the switches, packets/s):
  offered by attackers: 12021.0   delivered to victim switch before mitigation: 11420.0   after mitigation: None   reduction: None%
    h1 (10.0.0.1) UDP 1024B @3000pps: sent 2049.0  delivered before 1925.0  after None  rule=no
    h2 (10.0.0.2) UDP 512B @3000pps: sent 2100.0  delivered before 1914.0  after None  rule=no
    h3 (10.0.0.3) UDP 1400B @2000pps: sent 1521.0  delivered before 1312.0  after None  rule=no
    h4 (10.0.0.4) UDP 1024B @3000pps: sent 2091.0  delivered before 2075.0  after None  rule=no
    h5 (10.0.0.5) UDP 256B @4000pps: sent 2601.0  delivered before 2550.0  after None  rule=no
    h6 (10.0.0.6) UDP 768B @2500pps: sent 1659.0  delivered before 1643.0  after None  rule=no

Mitigation: 0 rule(s) installed, 0 removed/expired, 0 dry-run would-block

Legitimate traffic (per phase):
  h7 udp_iperf3            before: 2.0Mbps/loss 0.0%  attack_unmitigated: 1.97Mbps/loss 1.37%  after: 1.96Mbps/loss 0.0%   -> preserved
  h13 icmp_ping             before: loss 0.0%/rtt 0.049ms  attack_unmitigated: loss 0.0%/rtt 0.091ms  after: loss 0.0%/rtt 0.05ms   -> preserved

Recovery: yes after 19.9s; attackers reach victim again: True

STATUS:
  >>> NORMAL TRAFFIC
  >>> SUSPICIOUS TRAFFIC
  >>> ATTACK CONFIRMED
  >>> DETECTION ONLY: NO MITIGATION (mode DETECTION_ONLY)
  >>> LEGITIMATE TRAFFIC OK (no rule touched it)
  >>> NETWORK RECOVERED
