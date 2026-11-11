# Demo result: 20261111-221631_syn

- scenario: **syn**  traffic: **SYN**  mode: **MITIGATION_ENABLED**
- start 2026-11-11T22:16:31  end 2026-11-11T22:18:14  victim 10.0.0.18

Detection (controller view at the highest-scoring window):
  max state: NORMAL   max window score: 0.015 (threshold 0.682)
  sources=6  active flows=1048  aggregate=237 pps / 1.72 Mbps  avg pkt=909 B
  flow-level ML (CIC-DDoS2019 model): max attack probability=0.992, 88% of flows flagged
  per-source view at that window (pps | flow-ML max prob | source score | blocked):
    10.0.0.7        205 pps | 0.99 | 0.74 | no
    10.0.0.4         10 pps | 0.91 | 0.95 | no
    10.0.0.3          6 pps | 0.91 | 0.98 | no
    10.0.0.1          6 pps | 0.91 | 0.98 | no
    10.0.0.2          6 pps | 0.91 | 0.98 | no
    10.0.0.13         4 pps | 0.00 | 0.04 | no
  latency from attack start: suspicious=- s, confirmed=- s, first rule=- s

Attack traffic (measured on the switches, packets/s):
  offered by attackers: 206.0   delivered to victim switch before mitigation: 10.0   after mitigation: None   reduction: None%
    h1 (10.0.0.1) TCP-SYN 0B @100pps: sent 45.0  delivered before 1.0  after None  rule=no
    h2 (10.0.0.2) TCP-SYN 0B @100pps: sent 53.0  delivered before 1.0  after None  rule=no
    h3 (10.0.0.3) TCP-SYN 0B @100pps: sent 29.0  delivered before 1.0  after None  rule=no
    h4 (10.0.0.4) TCP-SYN 0B @100pps: sent 79.0  delivered before 7.0  after None  rule=no

Mitigation: 0 rule(s) installed, 0 removed/expired, 0 dry-run would-block

Legitimate traffic (per phase):
  h7 udp_iperf3               -> NOT preserved
  h13 icmp_ping             before: loss 0.0%/rtt 0.05ms  attack_unmitigated: loss 0.0%/rtt 0.059ms  after: loss 21.33%/rtt 10.175ms   -> preserved

Recovery: yes after 0.9s; attackers reach victim again: False

STATUS:
  >>> NORMAL TRAFFIC
  >>> ATTACK NOT DETECTED
  >>> LEGITIMATE TRAFFIC DEGRADED: h7(udp_iperf3)
  >>> CONTROLLER RECOVERED BUT CONNECTIVITY CHECK FAILED
