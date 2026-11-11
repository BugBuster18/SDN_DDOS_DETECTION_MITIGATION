# Demo result: 20261111-215901_udp

- scenario: **udp**  traffic: **UDP**  mode: **DETECTION_ONLY**
- start 2026-11-11T21:59:01  end 2026-11-11T22:00:37  victim 10.0.0.18

Detection (controller view at the highest-scoring window):
  max state: CONFIRMED   max window score: 1.000 (threshold 0.682)
  sources=7  active flows=7  aggregate=10845 pps / 70.49 Mbps  avg pkt=812 B
  flow-level ML (CIC-DDoS2019 model): max attack probability=0.998, 86% of flows flagged
  per-source view at that window (pps | flow-ML max prob | source score | blocked):
    10.0.0.5       2937 pps | 0.87 | 0.96 | no
    10.0.0.1       2063 pps | 1.00 | 0.89 | no
    10.0.0.2       2052 pps | 1.00 | 0.89 | no
    10.0.0.4       2033 pps | 1.00 | 0.96 | no
    10.0.0.3       1507 pps | 1.00 | 0.33 | no
    10.0.0.7        249 pps | 0.99 | 0.88 | no
    10.0.0.13         5 pps | 0.00 | 0.15 | no
  latency from attack start: suspicious=6.6 s, confirmed=11.5 s, first rule=- s

Attack traffic (measured on the switches, packets/s):
  offered by attackers: 7962.0   delivered to victim switch before mitigation: 3353.0   after mitigation: None   reduction: None%
    h1 (10.0.0.1) UDP 1024B @3000pps: sent 1361.0  delivered before 0.0  after None  rule=no
    h2 (10.0.0.2) UDP 512B @3000pps: sent 1367.0  delivered before 21.0  after None  rule=no
    h3 (10.0.0.3) UDP 1400B @2000pps: sent 995.0  delivered before 0.0  after None  rule=no
    h4 (10.0.0.4) UDP 1024B @3000pps: sent 1356.0  delivered before 1375.0  after None  rule=no
    h5 (10.0.0.5) UDP 256B @4000pps: sent 1691.0  delivered before 1629.0  after None  rule=no
    h6 (10.0.0.6) UDP 768B @2500pps: sent 1193.0  delivered before 328.0  after None  rule=no

Mitigation: 0 rule(s) installed, 0 removed/expired, 0 dry-run would-block

Legitimate traffic (per phase):
  h7 udp_iperf3            before: 2.0Mbps/loss 0.0%  attack_unmitigated: 1.74Mbps/loss 13.23%  after: 1.61Mbps/loss 18.06%   -> NOT preserved
  h13 icmp_ping             before: loss 0.0%/rtt 0.049ms  attack_unmitigated: loss 22.56%/rtt 0.06ms  after: loss 0.0%/rtt 0.876ms   -> NOT preserved

Recovery: yes after 33.9s; attackers reach victim again: True

STATUS:
  >>> NORMAL TRAFFIC
  >>> SUSPICIOUS TRAFFIC
  >>> ATTACK CONFIRMED
  >>> DETECTION ONLY: NO MITIGATION (mode DETECTION_ONLY)
  >>> LEGITIMATE TRAFFIC DEGRADED: h7(udp_iperf3),h13(icmp_ping)
  >>> NETWORK RECOVERED
