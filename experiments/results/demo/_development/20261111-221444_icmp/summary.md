# Demo result: 20261111-221444_icmp

- scenario: **icmp**  traffic: **ICMP**  mode: **MITIGATION_ENABLED**
- start 2026-11-11T22:14:44  end 2026-11-11T22:16:19  victim 10.0.0.18

Detection (controller view at the highest-scoring window):
  max state: MITIGATING   max window score: 1.000 (threshold 0.682)
  sources=8  active flows=8  aggregate=5333 pps / 22.58 Mbps  avg pkt=529 B
  flow-level ML (CIC-DDoS2019 model): max attack probability=0.992, 12% of flows flagged
  per-source view at that window (pps | flow-ML max prob | source score | blocked):
    10.0.0.2       1079 pps | 0.00 | 0.74 | no
    10.0.0.5       1074 pps | 0.00 | 0.78 | no
    10.0.0.4        856 pps | 0.00 | 0.76 | no
    10.0.0.1        841 pps | 0.00 | 0.77 | no
    10.0.0.6        707 pps | 0.00 | 0.73 | no
    10.0.0.3        594 pps | 0.00 | 0.66 | no
    10.0.0.7        178 pps | 0.99 | 0.52 | no
    10.0.0.13         3 pps | 0.00 | 0.02 | no
  latency from attack start: suspicious=1.3 s, confirmed=8.3 s, first rule=17.6 s

Attack traffic (measured on the switches, packets/s):
  offered by attackers: 6631.0   delivered to victim switch before mitigation: 3021.0   after mitigation: 0.0   reduction: 100.0%
    h1 (10.0.0.1) ICMP 512B @1500pps: sent 974.0  delivered before 494.0  after 0.0  rule=yes
    h2 (10.0.0.2) ICMP 256B @2000pps: sent 1633.0  delivered before 708.0  after 0.0  rule=yes
    h3 (10.0.0.3) ICMP 1000B @1000pps: sent 677.0  delivered before 2.0  after 0.0  rule=yes
    h4 (10.0.0.4) ICMP 512B @1500pps: sent 998.0  delivered before 381.0  after 0.0  rule=yes
    h5 (10.0.0.5) ICMP 128B @2000pps: sent 1531.0  delivered before 1125.0  after 0.0  rule=yes
    h6 (10.0.0.6) ICMP 768B @1200pps: sent 817.0  delivered before 312.0  after 0.0  rule=yes

Mitigation: 6 rule(s) installed, 6 removed/expired, 0 dry-run would-block
    INSTALLED 0xdd05000000000007 DROP 10.0.0.1 -> 10.0.0.18 ICMP at ['s1']
    INSTALLED 0xdd05000000000008 DROP 10.0.0.2 -> 10.0.0.18 ICMP at ['s1']
    INSTALLED 0xdd05000000000009 DROP 10.0.0.3 -> 10.0.0.18 ICMP at ['s1']
    INSTALLED 0xdd0500000000000a DROP 10.0.0.4 -> 10.0.0.18 ICMP at ['s2']
    INSTALLED 0xdd0500000000000b DROP 10.0.0.5 -> 10.0.0.18 ICMP at ['s2']
    INSTALLED 0xdd0500000000000c DROP 10.0.0.6 -> 10.0.0.18 ICMP at ['s2']
  rules as reported by Open vSwitch (ovs-ofctl dump-flows):
    cookie=0xdd05000000000007, duration=0.467s, table=0, n_packets=0, n_bytes=0, hard_timeout=120, send_flow_rem priority=200,icmp,nw_src=10.0.0.1,nw_dst=10.0.0.18 actions=drop
    cookie=0xdd05000000000008, duration=0.467s, table=0, n_packets=42, n_bytes=12516, hard_timeout=120, send_flow_rem priority=200,icmp,nw_src=10.0.0.2,nw_dst=10.0.0.18 actions=drop
    cookie=0xdd05000000000009, duration=0.467s, table=0, n_packets=0, n_bytes=0, hard_timeout=120, send_flow_rem priority=200,icmp,nw_src=10.0.0.3,nw_dst=10.0.0.18 actions=drop
    cookie=0xdd0500000000000a, duration=0.490s, table=0, n_packets=0, n_bytes=0, hard_timeout=120, send_flow_rem priority=200,icmp,nw_src=10.0.0.4,nw_dst=10.0.0.18 actions=drop
    cookie=0xdd0500000000000b, duration=0.490s, table=0, n_packets=0, n_bytes=0, hard_timeout=120, send_flow_rem priority=200,icmp,nw_src=10.0.0.5,nw_dst=10.0.0.18 actions=drop
    cookie=0xdd0500000000000c, duration=0.490s, table=0, n_packets=0, n_bytes=0, hard_timeout=120, send_flow_rem priority=200,icmp,nw_src=10.0.0.6,nw_dst=10.0.0.18 actions=drop

Legitimate traffic (per phase):
  h7 udp_iperf3            before: 2.0Mbps/loss 0.0%  attack_unmitigated: 1.72Mbps/loss 13.82%  mitigated: 2.0Mbps/loss 0.0%  after: 1.96Mbps/loss 0.0%   -> preserved
  h13 icmp_ping             before: loss 0.0%/rtt 0.05ms  attack_unmitigated: loss 0.0%/rtt 10.345ms  mitigated: loss 0.0%/rtt 0.05ms  after: loss 0.0%/rtt 0.052ms   -> preserved

Recovery: yes after 20.9s; attackers reach victim again: True

STATUS:
  >>> NORMAL TRAFFIC
  >>> SUSPICIOUS TRAFFIC
  >>> ATTACK CONFIRMED
  >>> MITIGATION INSTALLED
  >>> ATTACK TRAFFIC BLOCKED
  >>> LEGITIMATE TRAFFIC PRESERVED
  >>> NETWORK RECOVERED
