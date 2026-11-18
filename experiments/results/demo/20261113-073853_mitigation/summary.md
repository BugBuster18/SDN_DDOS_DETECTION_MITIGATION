# Demo result: 20261113-073853_mitigation

- scenario: **mitigation**  traffic: **UDP**  mode: **MITIGATION_ENABLED**
- start 2026-11-13T07:38:53  end 2026-11-13T07:40:38  victim 10.0.0.18

Detection (controller view at the highest-scoring window):
  max state: MITIGATING   max window score: 1.000 (threshold 0.682)
  sources=10  active flows=11  aggregate=8800 pps / 61.53 Mbps  avg pkt=874 B
  flow-level ML (CIC-DDoS2019 model): max attack probability=0.999, 82% of flows flagged
  per-source view at that window (pps | flow-ML max prob | source score | blocked):
    10.0.0.5       1720 pps | 0.87 | 0.94 | no
    10.0.0.4       1384 pps | 1.00 | 0.94 | no
    10.0.0.1       1383 pps | 1.00 | 0.93 | no
    10.0.0.2       1349 pps | 1.00 | 0.95 | no
    10.0.0.6       1201 pps | 1.00 | 0.84 | no
    10.0.0.3        984 pps | 1.00 | 0.92 | no
    10.0.0.7        604 pps | 0.00 | 0.14 | no
    10.0.0.8        172 pps | 0.99 | 0.30 | no
    10.0.0.13         3 pps | 0.00 | 0.01 | no
    10.0.0.10         0 pps | 0.91 | 0.01 | no
  latency from attack start: suspicious=2.1 s, confirmed=8.3 s, first rule=8.3 s

Attack traffic (measured on the switches, packets/s):
  offered by attackers: 12008.0   delivered to victim switch before mitigation: 5537.0   after mitigation: 64.0   reduction: 98.8%
    h1 (10.0.0.1) UDP 1024B @3000pps: sent 1953.0  delivered before 0.0  after 37.0  rule=yes
    h2 (10.0.0.2) UDP 512B @3000pps: sent 1963.0  delivered before 2144.0  after 0.0  rule=yes
    h3 (10.0.0.3) UDP 1400B @2000pps: sent 1404.0  delivered before 0.0  after 26.0  rule=yes
    h4 (10.0.0.4) UDP 1024B @3000pps: sent 1968.0  delivered before 1681.0  after 0.0  rule=yes
    h5 (10.0.0.5) UDP 256B @4000pps: sent 2794.0  delivered before 1469.0  after 0.0  rule=yes
    h6 (10.0.0.6) UDP 768B @2500pps: sent 1928.0  delivered before 242.0  after 0.0  rule=yes

Mitigation: 6 rule(s) installed, 6 removed/expired, 0 dry-run would-block
    INSTALLED 0xdd05000000000001 DROP 10.0.0.1 -> 10.0.0.18 UDP at ['s1']
    INSTALLED 0xdd05000000000002 DROP 10.0.0.2 -> 10.0.0.18 UDP at ['s1']
    INSTALLED 0xdd05000000000003 DROP 10.0.0.3 -> 10.0.0.18 UDP at ['s1']
    INSTALLED 0xdd05000000000004 DROP 10.0.0.4 -> 10.0.0.18 UDP at ['s2']
    INSTALLED 0xdd05000000000005 DROP 10.0.0.5 -> 10.0.0.18 UDP at ['s2']
    INSTALLED 0xdd05000000000006 DROP 10.0.0.6 -> 10.0.0.18 UDP at ['s2']
  rules as reported by Open vSwitch (ovs-ofctl dump-flows):
    cookie=0xdd05000000000001, duration=0.778s, table=0, n_packets=0, n_bytes=0, hard_timeout=120, send_flow_rem priority=200,udp,nw_src=10.0.0.1,nw_dst=10.0.0.18 actions=drop
    cookie=0xdd05000000000002, duration=0.778s, table=0, n_packets=0, n_bytes=0, hard_timeout=120, send_flow_rem priority=200,udp,nw_src=10.0.0.2,nw_dst=10.0.0.18 actions=drop
    cookie=0xdd05000000000003, duration=0.778s, table=0, n_packets=0, n_bytes=0, hard_timeout=120, send_flow_rem priority=200,udp,nw_src=10.0.0.3,nw_dst=10.0.0.18 actions=drop
    cookie=0xdd05000000000004, duration=0.805s, table=0, n_packets=200, n_bytes=213200, hard_timeout=120, send_flow_rem priority=200,udp,nw_src=10.0.0.4,nw_dst=10.0.0.18 actions=drop
    cookie=0xdd05000000000005, duration=0.805s, table=0, n_packets=2357, n_bytes=702386, hard_timeout=120, send_flow_rem priority=200,udp,nw_src=10.0.0.5,nw_dst=10.0.0.18 actions=drop
    cookie=0xdd05000000000006, duration=0.805s, table=0, n_packets=1603, n_bytes=1298430, hard_timeout=120, send_flow_rem priority=200,udp,nw_src=10.0.0.6,nw_dst=10.0.0.18 actions=drop

Legitimate traffic (per phase):
  h7 tcp_iperf3            before: 9.98Mbps  attack_unmitigated: 10.04Mbps  mitigated: 10.02Mbps  after: 9.99Mbps   -> preserved
  h8 udp_iperf3            before: 2.0Mbps/loss 0.0%  attack_unmitigated: 2.0Mbps/loss 0.0%  mitigated: 2.0Mbps/loss 0.0%  after: 1.97Mbps/loss 0.0%   -> preserved
  h9 http                  before: loss 0.0%/rtt 115.057ms  attack_unmitigated: loss 100.0%/rtt 3003.097ms  mitigated: loss 0.0%/rtt 143.58ms  after: loss 0.0%/rtt 153.146ms   -> preserved
  h10 udp_request_response  before: loss 0.0%/rtt 14.271ms  attack_unmitigated: loss 100.0%  mitigated: loss 0.13%/rtt 24.19ms  after: loss 0.15%/rtt 15.178ms   -> preserved
  h13 icmp_ping             before: loss 0.0%/rtt 0.217ms  attack_unmitigated: loss 0.0%/rtt 0.08ms  mitigated: loss 0.0%/rtt 0.245ms  after: loss 0.0%/rtt 0.355ms   -> preserved

Recovery: yes after 20.9s; attackers reach victim again: True

STATUS:
  >>> NORMAL TRAFFIC
  >>> SUSPICIOUS TRAFFIC
  >>> ATTACK CONFIRMED
  >>> MITIGATION INSTALLED
  >>> ATTACK TRAFFIC BLOCKED
  >>> LEGITIMATE TRAFFIC PRESERVED
  >>> NETWORK RECOVERED
