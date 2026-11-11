# Demo result: 20261111-221946_synfixed

- scenario: **syn**  traffic: **SYNFIXED**  mode: **MITIGATION_ENABLED**
- start 2026-11-11T22:19:46  end 2026-11-11T22:21:21  victim 10.0.0.18

Detection (controller view at the highest-scoring window):
  max state: SUSPECTED   max window score: 0.977 (threshold 0.682)
  sources=6  active flows=6  aggregate=5990 pps / 4.54 Mbps  avg pkt=95 B
  flow-level ML (CIC-DDoS2019 model): max attack probability=0.992, 17% of flows flagged
  per-source view at that window (pps | flow-ML max prob | source score | blocked):
    10.0.0.4       1439 pps | 0.00 | 0.67 | no
    10.0.0.2       1438 pps | 0.00 | 0.67 | no
    10.0.0.1       1433 pps | 0.00 | 0.67 | no
    10.0.0.3       1429 pps | 0.00 | 0.67 | no
    10.0.0.7        247 pps | 0.99 | 0.58 | no
    10.0.0.13         5 pps | 0.00 | 0.03 | no
  latency from attack start: suspicious=3.7 s, confirmed=- s, first rule=- s

Attack traffic (measured on the switches, packets/s):
  offered by attackers: 12576.0   delivered to victim switch before mitigation: 12596.0   after mitigation: None   reduction: None%
    h1 (10.0.0.1) TCP-SYN 0B @2000pps: sent 3143.0  delivered before 3148.0  after None  rule=no
    h2 (10.0.0.2) TCP-SYN 0B @2000pps: sent 3143.0  delivered before 3148.0  after None  rule=no
    h3 (10.0.0.3) TCP-SYN 0B @2000pps: sent 3132.0  delivered before 3137.0  after None  rule=no
    h4 (10.0.0.4) TCP-SYN 0B @2000pps: sent 3158.0  delivered before 3163.0  after None  rule=no

Mitigation: 0 rule(s) installed, 0 removed/expired, 0 dry-run would-block

Legitimate traffic (per phase):
  h7 udp_iperf3            before: 2.0Mbps/loss 0.0%  attack_unmitigated: 2.0Mbps/loss 0.0%  after: 1.96Mbps/loss 0.0%   -> preserved
  h13 icmp_ping             before: loss 0.0%/rtt 0.047ms  attack_unmitigated: loss 0.0%/rtt 0.038ms  after: loss 0.0%/rtt 0.048ms   -> preserved

Recovery: yes after 0.9s; attackers reach victim again: True

STATUS:
  >>> NORMAL TRAFFIC
  >>> SUSPICIOUS TRAFFIC
  >>> ATTACK NOT DETECTED
  >>> LEGITIMATE TRAFFIC OK (no rule touched it)
  >>> NETWORK RECOVERED
