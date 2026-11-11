# Demo result: 20261111-223920_mixed

- scenario: **mixed**  traffic: **UDP**  mode: **DETECTION_ONLY**
- start 2026-11-11T22:39:20  end 2026-11-11T22:40:55  victim 10.0.0.18

Detection (controller view at the highest-scoring window):
  max state: CONFIRMED   max window score: 1.000 (threshold 0.682)
  sources=11  active flows=15  aggregate=8423 pps / 58.81 Mbps  avg pkt=873 B
  flow-level ML (CIC-DDoS2019 model): max attack probability=0.999, 80% of flows flagged
  per-source view at that window (pps | flow-ML max prob | source score | blocked):
    10.0.0.5       1643 pps | 0.87 | 0.96 | no
    10.0.0.4       1326 pps | 1.00 | 0.96 | no
    10.0.0.1       1324 pps | 1.00 | 0.96 | no
    10.0.0.2       1302 pps | 1.00 | 0.96 | no
    10.0.0.6       1151 pps | 1.00 | 0.96 | no
    10.0.0.3        935 pps | 1.00 | 0.95 | no
    10.0.0.7        572 pps | 0.00 | 0.01 | no
    10.0.0.8        166 pps | 0.99 | 0.54 | no
    10.0.0.13         3 pps | 0.00 | 0.00 | no
    10.0.0.9          0 pps | 0.89 | 0.02 | no
  latency from attack start: suspicious=2.0 s, confirmed=8.5 s, first rule=- s

Attack traffic (measured on the switches, packets/s):
  offered by attackers: 11994.0   delivered to victim switch before mitigation: 11777.0   after mitigation: None   reduction: None%
    h1 (10.0.0.1) UDP 1024B @3000pps: sent 2062.0  delivered before 1882.0  after None  rule=no
    h2 (10.0.0.2) UDP 512B @3000pps: sent 2066.0  delivered before 2079.0  after None  rule=no
    h3 (10.0.0.3) UDP 1400B @2000pps: sent 1503.0  delivered before 1451.0  after None  rule=no
    h4 (10.0.0.4) UDP 1024B @3000pps: sent 2059.0  delivered before 2060.0  after None  rule=no
    h5 (10.0.0.5) UDP 256B @4000pps: sent 2541.0  delivered before 2541.0  after None  rule=no
    h6 (10.0.0.6) UDP 768B @2500pps: sent 1764.0  delivered before 1764.0  after None  rule=no

Mitigation: 0 rule(s) installed, 0 removed/expired, 0 dry-run would-block

Legitimate traffic (per phase):
  h7 tcp_iperf3            before: 10.0Mbps  attack_unmitigated: 10.0Mbps  after: 9.99Mbps   -> preserved
  h8 udp_iperf3            before: 2.0Mbps/loss 0.0%  attack_unmitigated: 2.0Mbps/loss 0.0%  after: 1.98Mbps/loss 0.0%   -> preserved
  h9 http                  before: loss 0.0%/rtt 120.424ms  attack_unmitigated: loss 3.57%/rtt 269.898ms  after: loss 0.0%/rtt 132.23ms   -> preserved
  h10 udp_request_response  before: loss 0.88%/rtt 15.239ms  attack_unmitigated: loss 1.72%/rtt 23.076ms  after: loss 0.0%/rtt 15.345ms   -> preserved
  h13 icmp_ping             before: loss 0.0%/rtt 0.751ms  attack_unmitigated: loss 0.0%/rtt 1.241ms  after: loss 0.0%/rtt 0.326ms   -> preserved

Recovery: yes after 20.9s; attackers reach victim again: True

STATUS:
  >>> NORMAL TRAFFIC
  >>> SUSPICIOUS TRAFFIC
  >>> ATTACK CONFIRMED
  >>> DETECTION ONLY: NO MITIGATION (mode DETECTION_ONLY)
  >>> LEGITIMATE TRAFFIC OK (no rule touched it)
  >>> NETWORK RECOVERED
