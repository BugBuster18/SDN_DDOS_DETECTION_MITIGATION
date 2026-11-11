# Demo result: 20261111-223743_synfixed

- scenario: **syn**  traffic: **SYNFIXED**  mode: **DETECTION_ONLY**
- start 2026-11-11T22:37:43  end 2026-11-11T22:39:19  victim 10.0.0.18

Detection (controller view at the highest-scoring window):
  max state: SUSPECTED   max window score: 0.971 (threshold 0.682)
  sources=6  active flows=6  aggregate=2828 pps / 3.00 Mbps  avg pkt=133 B
  flow-level ML (CIC-DDoS2019 model): max attack probability=0.992, 17% of flows flagged
  per-source view at that window (pps | flow-ML max prob | source score | blocked):
    10.0.0.1        655 pps | 0.00 | 0.69 | no
    10.0.0.3        650 pps | 0.00 | 0.69 | no
    10.0.0.2        649 pps | 0.00 | 0.69 | no
    10.0.0.4        644 pps | 0.00 | 0.69 | no
    10.0.0.7        225 pps | 0.99 | 0.64 | no
    10.0.0.13         4 pps | 0.00 | 0.04 | no
  latency from attack start: suspicious=3.3 s, confirmed=- s, first rule=- s

Attack traffic (measured on the switches, packets/s):
  offered by attackers: 12544.0   delivered to victim switch before mitigation: 12529.0   after mitigation: None   reduction: None%
    h1 (10.0.0.1) TCP-SYN 0B @2000pps: sent 3133.0  delivered before 3129.0  after None  rule=no
    h2 (10.0.0.2) TCP-SYN 0B @2000pps: sent 3135.0  delivered before 3132.0  after None  rule=no
    h3 (10.0.0.3) TCP-SYN 0B @2000pps: sent 3125.0  delivered before 3122.0  after None  rule=no
    h4 (10.0.0.4) TCP-SYN 0B @2000pps: sent 3151.0  delivered before 3145.0  after None  rule=no

Mitigation: 0 rule(s) installed, 0 removed/expired, 0 dry-run would-block

Legitimate traffic (per phase):
  h7 udp_iperf3            before: 2.0Mbps/loss 0.0%  attack_unmitigated: 2.0Mbps/loss 0.0%  after: 1.97Mbps/loss 0.0%   -> preserved
  h13 icmp_ping             before: loss 0.0%/rtt 0.054ms  attack_unmitigated: loss 0.0%/rtt 0.037ms  after: loss 0.0%/rtt 0.049ms   -> preserved

Recovery: yes after 0.9s; attackers reach victim again: True

STATUS:
  >>> NORMAL TRAFFIC
  >>> SUSPICIOUS TRAFFIC
  >>> ATTACK NOT DETECTED
  >>> LEGITIMATE TRAFFIC OK (no rule touched it)
  >>> NETWORK RECOVERED
