# Demo result: 20261111-223538_syn

- scenario: **syn**  traffic: **SYN**  mode: **DETECTION_ONLY**
- start 2026-11-11T22:35:38  end 2026-11-11T22:37:21  victim 10.0.0.18

Detection (controller view at the highest-scoring window):
  max state: NORMAL   max window score: 0.027 (threshold 0.682)
  sources=6  active flows=673  aggregate=447 pps / 3.59 Mbps  avg pkt=1003 B
  flow-level ML (CIC-DDoS2019 model): max attack probability=0.999, 94% of flows flagged
  per-source view at that window (pps | flow-ML max prob | source score | blocked):
    10.0.0.7        429 pps | 1.00 | 0.92 | no
    10.0.0.4          8 pps | 0.91 | 0.16 | no
    10.0.0.3          5 pps | 0.91 | 0.03 | no
    10.0.0.13         4 pps | 0.00 | 0.00 | no
    10.0.0.1          1 pps | 0.91 | 0.16 | no
    10.0.0.2          0 pps | 0.91 | 0.24 | no
  latency from attack start: suspicious=- s, confirmed=- s, first rule=- s

Attack traffic (measured on the switches, packets/s):
  offered by attackers: 288.0   delivered to victim switch before mitigation: 3.0   after mitigation: None   reduction: None%
    h1 (10.0.0.1) TCP-SYN 0B @100pps: sent 93.0  delivered before 0.0  after None  rule=no
    h2 (10.0.0.2) TCP-SYN 0B @100pps: sent 50.0  delivered before 0.0  after None  rule=no
    h3 (10.0.0.3) TCP-SYN 0B @100pps: sent 40.0  delivered before 0.0  after None  rule=no
    h4 (10.0.0.4) TCP-SYN 0B @100pps: sent 105.0  delivered before 2.0  after None  rule=no

Mitigation: 0 rule(s) installed, 0 removed/expired, 0 dry-run would-block

Legitimate traffic (per phase):
  h7 udp_iperf3               -> NOT preserved
  h13 icmp_ping             before: loss 0.0%/rtt 0.174ms  attack_unmitigated: loss 17.95%/rtt 24.139ms  after: loss 0.0%/rtt 0.06ms   -> NOT preserved

Recovery: yes after 0.9s; attackers reach victim again: False

STATUS:
  >>> NORMAL TRAFFIC
  >>> ATTACK NOT DETECTED
  >>> LEGITIMATE TRAFFIC DEGRADED: h7(udp_iperf3),h13(icmp_ping)
  >>> CONTROLLER RECOVERED BUT CONNECTIVITY CHECK FAILED
