# Demo result: 20261111-222345_mixed

- scenario: **mixed**  traffic: **UDP**  mode: **DRY_RUN**
- start 2026-11-11T22:23:45  end 2026-11-11T22:25:20  victim 10.0.0.18

Detection (controller view at the highest-scoring window):
  max state: CONFIRMED   max window score: 1.000 (threshold 0.682)
  sources=11  active flows=11  aggregate=13495 pps / 94.18 Mbps  avg pkt=872 B
  flow-level ML (CIC-DDoS2019 model): max attack probability=0.999, 82% of flows flagged
  per-source view at that window (pps | flow-ML max prob | source score | blocked):
    10.0.0.5       2626 pps | 0.87 | 0.93 | no
    10.0.0.4       2126 pps | 1.00 | 0.93 | no
    10.0.0.2       2111 pps | 1.00 | 0.94 | no
    10.0.0.1       2106 pps | 1.00 | 0.94 | no
    10.0.0.6       1844 pps | 1.00 | 0.92 | no
    10.0.0.3       1530 pps | 1.00 | 0.93 | no
    10.0.0.7        891 pps | 0.00 | 0.27 | no
    10.0.0.8        257 pps | 0.99 | 0.41 | no
    10.0.0.13         5 pps | 0.00 | 0.02 | no
    10.0.0.10         0 pps | 0.89 | 0.01 | no
  latency from attack start: suspicious=2.3 s, confirmed=8.6 s, first rule=- s

Attack traffic (measured on the switches, packets/s):
  offered by attackers: 11097.0   delivered to victim switch before mitigation: 10300.0   after mitigation: None   reduction: None%
    h1 (10.0.0.1) UDP 1024B @3000pps: sent 1893.0  delivered before 1911.0  after None  rule=no
    h2 (10.0.0.2) UDP 512B @3000pps: sent 1903.0  delivered before 1636.0  after None  rule=no
    h3 (10.0.0.3) UDP 1400B @2000pps: sent 1373.0  delivered before 1186.0  after None  rule=no
    h4 (10.0.0.4) UDP 1024B @3000pps: sent 1894.0  delivered before 1893.0  after None  rule=no
    h5 (10.0.0.5) UDP 256B @4000pps: sent 2385.0  delivered before 2205.0  after None  rule=no
    h6 (10.0.0.6) UDP 768B @2500pps: sent 1650.0  delivered before 1469.0  after None  rule=no

Mitigation: 0 rule(s) installed, 0 removed/expired, 6 dry-run would-block

Legitimate traffic (per phase):
  h7 tcp_iperf3            before: 10.0Mbps  attack_unmitigated: 10.0Mbps  after: 9.99Mbps   -> preserved
  h8 udp_iperf3            before: 2.0Mbps/loss 0.0%  attack_unmitigated: 2.0Mbps/loss 0.0%  after: 1.97Mbps/loss 0.0%   -> preserved
  h9 http                  before: loss 0.0%/rtt 125.603ms  attack_unmitigated: loss 3.85%/rtt 365.278ms  after: loss 0.0%/rtt 132.915ms   -> preserved
  h10 udp_request_response  before: loss 0.45%/rtt 29.959ms  attack_unmitigated: loss 2.33%/rtt 22.011ms  after: loss 0.0%/rtt 16.558ms   -> preserved
  h13 icmp_ping             before: loss 0.0%/rtt 0.471ms  attack_unmitigated: loss 0.0%/rtt 0.301ms  after: loss 0.0%/rtt 0.442ms   -> preserved

Recovery: yes after 20.9s; attackers reach victim again: True

STATUS:
  >>> NORMAL TRAFFIC
  >>> SUSPICIOUS TRAFFIC
  >>> ATTACK CONFIRMED
  >>> DRY RUN: RULES WOULD HAVE BEEN INSTALLED (none installed)
  >>> LEGITIMATE TRAFFIC OK (no rule touched it)
  >>> NETWORK RECOVERED
