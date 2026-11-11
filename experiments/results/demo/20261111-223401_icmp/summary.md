# Demo result: 20261111-223401_icmp

- scenario: **icmp**  traffic: **ICMP**  mode: **DETECTION_ONLY**
- start 2026-11-11T22:34:01  end 2026-11-11T22:35:36  victim 10.0.0.18

Detection (controller view at the highest-scoring window):
  max state: CONFIRMED   max window score: 1.000 (threshold 0.682)
  sources=8  active flows=8  aggregate=7862 pps / 33.35 Mbps  avg pkt=530 B
  flow-level ML (CIC-DDoS2019 model): max attack probability=0.992, 12% of flows flagged
  per-source view at that window (pps | flow-ML max prob | source score | blocked):
    10.0.0.2       1591 pps | 0.00 | 0.64 | no
    10.0.0.5       1573 pps | 0.00 | 0.62 | no
    10.0.0.1       1265 pps | 0.00 | 0.57 | no
    10.0.0.4       1251 pps | 0.00 | 0.58 | no
    10.0.0.6       1017 pps | 0.00 | 0.55 | no
    10.0.0.3        906 pps | 0.00 | 0.51 | no
    10.0.0.7        253 pps | 0.99 | 0.01 | no
    10.0.0.13         5 pps | 0.00 | 0.00 | no
  latency from attack start: suspicious=6.1 s, confirmed=11.1 s, first rule=- s

Attack traffic (measured on the switches, packets/s):
  offered by attackers: 7479.0   delivered to victim switch before mitigation: 6951.0   after mitigation: None   reduction: None%
    h1 (10.0.0.1) ICMP 512B @1500pps: sent 1242.0  delivered before 1019.0  after None  rule=no
    h2 (10.0.0.2) ICMP 256B @2000pps: sent 1578.0  delivered before 1578.0  after None  rule=no
    h3 (10.0.0.3) ICMP 1000B @1000pps: sent 799.0  delivered before 634.0  after None  rule=no
    h4 (10.0.0.4) ICMP 512B @1500pps: sent 1253.0  delivered before 1224.0  after None  rule=no
    h5 (10.0.0.5) ICMP 128B @2000pps: sent 1585.0  delivered before 1549.0  after None  rule=no
    h6 (10.0.0.6) ICMP 768B @1200pps: sent 1023.0  delivered before 947.0  after None  rule=no

Mitigation: 0 rule(s) installed, 0 removed/expired, 0 dry-run would-block

Legitimate traffic (per phase):
  h7 udp_iperf3            before: 2.0Mbps/loss 0.0%  attack_unmitigated: 2.0Mbps/loss 0.0%  after: 1.98Mbps/loss 0.0%   -> preserved
  h13 icmp_ping             before: loss 0.0%/rtt 0.162ms  attack_unmitigated: loss 0.0%/rtt 0.04ms  after: loss 0.0%/rtt 0.051ms   -> preserved

Recovery: yes after 23.9s; attackers reach victim again: True

STATUS:
  >>> NORMAL TRAFFIC
  >>> SUSPICIOUS TRAFFIC
  >>> ATTACK CONFIRMED
  >>> DETECTION ONLY: NO MITIGATION (mode DETECTION_ONLY)
  >>> LEGITIMATE TRAFFIC OK (no rule touched it)
  >>> NETWORK RECOVERED
