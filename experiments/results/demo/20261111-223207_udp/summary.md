# Demo result: 20261111-223207_udp

- scenario: **udp**  traffic: **UDP**  mode: **DETECTION_ONLY**
- start 2026-11-11T22:32:25  end 2026-11-11T22:34:00  victim 10.0.0.18

Detection (controller view at the highest-scoring window):
  max state: CONFIRMED   max window score: 1.000 (threshold 0.682)
  sources=8  active flows=8  aggregate=6778 pps / 45.05 Mbps  avg pkt=831 B
  flow-level ML (CIC-DDoS2019 model): max attack probability=0.999, 88% of flows flagged
  per-source view at that window (pps | flow-ML max prob | source score | blocked):
    10.0.0.5       1378 pps | 0.87 | 0.92 | no
    10.0.0.2       1168 pps | 1.00 | 0.93 | no
    10.0.0.1       1158 pps | 1.00 | 0.93 | no
    10.0.0.4       1097 pps | 1.00 | 0.93 | no
    10.0.0.6        960 pps | 1.00 | 0.93 | no
    10.0.0.3        838 pps | 1.00 | 0.93 | no
    10.0.0.7        178 pps | 0.99 | 0.70 | no
    10.0.0.13         4 pps | 0.00 | 0.05 | no
  latency from attack start: suspicious=7.6 s, confirmed=11.3 s, first rule=- s

Attack traffic (measured on the switches, packets/s):
  offered by attackers: 11776.0   delivered to victim switch before mitigation: 10719.0   after mitigation: None   reduction: None%
    h1 (10.0.0.1) UDP 1024B @3000pps: sent 2009.0  delivered before 1678.0  after None  rule=no
    h2 (10.0.0.2) UDP 512B @3000pps: sent 2016.0  delivered before 1682.0  after None  rule=no
    h3 (10.0.0.3) UDP 1400B @2000pps: sent 1452.0  delivered before 1214.0  after None  rule=no
    h4 (10.0.0.4) UDP 1024B @3000pps: sent 2021.0  delivered before 1890.0  after None  rule=no
    h5 (10.0.0.5) UDP 256B @4000pps: sent 2523.0  delivered before 2510.0  after None  rule=no
    h6 (10.0.0.6) UDP 768B @2500pps: sent 1756.0  delivered before 1745.0  after None  rule=no

Mitigation: 0 rule(s) installed, 0 removed/expired, 0 dry-run would-block

Legitimate traffic (per phase):
  h7 udp_iperf3            before: 2.0Mbps/loss 0.0%  attack_unmitigated: 2.0Mbps/loss 0.0%  after: 1.97Mbps/loss 0.0%   -> preserved
  h13 icmp_ping             before: loss 0.0%/rtt 0.051ms  attack_unmitigated: loss 0.0%/rtt 0.078ms  after: loss 0.0%/rtt 0.05ms   -> preserved

Recovery: yes after 24.9s; attackers reach victim again: True

STATUS:
  >>> NORMAL TRAFFIC
  >>> SUSPICIOUS TRAFFIC
  >>> ATTACK CONFIRMED
  >>> DETECTION ONLY: NO MITIGATION (mode DETECTION_ONLY)
  >>> LEGITIMATE TRAFFIC OK (no rule touched it)
  >>> NETWORK RECOVERED
