# Demo result: 20261111-221250_mitigation

- scenario: **mitigation**  traffic: **UDP**  mode: **MITIGATION_ENABLED**
- start 2026-11-11T22:12:50  end 2026-11-11T22:14:25  victim 10.0.0.18

Detection (controller view at the highest-scoring window):
  max state: MITIGATING   max window score: 1.000 (threshold 0.682)
  sources=11  active flows=24  aggregate=8168 pps / 57.49 Mbps  avg pkt=880 B
  flow-level ML (CIC-DDoS2019 model): max attack probability=0.999, 79% of flows flagged
  per-source view at that window (pps | flow-ML max prob | source score | blocked):
    10.0.0.5       1513 pps | 0.87 | 0.91 | no
    10.0.0.1       1293 pps | 1.00 | 0.92 | no
    10.0.0.2       1278 pps | 1.00 | 0.92 | no
    10.0.0.4       1243 pps | 1.00 | 0.92 | no
    10.0.0.6       1047 pps | 1.00 | 0.92 | no
    10.0.0.3        924 pps | 1.00 | 0.92 | no
    10.0.0.7        631 pps | 0.00 | 0.53 | no
    10.0.0.8        181 pps | 0.99 | 0.67 | no
    10.0.0.9         54 pps | 0.01 | 0.35 | no
    10.0.0.13         4 pps | 0.00 | 0.04 | no
  latency from attack start: suspicious=8.0 s, confirmed=11.3 s, first rule=11.3 s

Attack traffic (measured on the switches, packets/s):
  offered by attackers: 12822.0   delivered to victim switch before mitigation: 9680.0   after mitigation: 0.0   reduction: 100.0%
    h1 (10.0.0.1) UDP 1024B @3000pps: sent 2197.0  delivered before 1558.0  after 0.0  rule=yes
    h2 (10.0.0.2) UDP 512B @3000pps: sent 2206.0  delivered before 1237.0  after 0.0  rule=yes
    h3 (10.0.0.3) UDP 1400B @2000pps: sent 1577.0  delivered before 628.0  after 0.0  rule=yes
    h4 (10.0.0.4) UDP 1024B @3000pps: sent 2199.0  delivered before 1995.0  after 0.0  rule=yes
    h5 (10.0.0.5) UDP 256B @4000pps: sent 2750.0  delivered before 2481.0  after 0.0  rule=yes
    h6 (10.0.0.6) UDP 768B @2500pps: sent 1893.0  delivered before 1782.0  after 0.0  rule=yes

Mitigation: 6 rule(s) installed, 6 removed/expired, 0 dry-run would-block
    INSTALLED 0xdd05000000000001 DROP 10.0.0.1 -> 10.0.0.18 UDP at ['s1']
    INSTALLED 0xdd05000000000002 DROP 10.0.0.2 -> 10.0.0.18 UDP at ['s1']
    INSTALLED 0xdd05000000000003 DROP 10.0.0.3 -> 10.0.0.18 UDP at ['s1']
    INSTALLED 0xdd05000000000004 DROP 10.0.0.4 -> 10.0.0.18 UDP at ['s2']
    INSTALLED 0xdd05000000000005 DROP 10.0.0.5 -> 10.0.0.18 UDP at ['s2']
    INSTALLED 0xdd05000000000006 DROP 10.0.0.6 -> 10.0.0.18 UDP at ['s2']
  rules as reported by Open vSwitch (ovs-ofctl dump-flows):
    cookie=0xdd05000000000001, duration=0.793s, table=0, n_packets=1795, n_bytes=1913470, hard_timeout=120, send_flow_rem priority=200,udp,nw_src=10.0.0.1,nw_dst=10.0.0.18 actions=drop
    cookie=0xdd05000000000002, duration=0.793s, table=0, n_packets=1820, n_bytes=1008280, hard_timeout=120, send_flow_rem priority=200,udp,nw_src=10.0.0.2,nw_dst=10.0.0.18 actions=drop
    cookie=0xdd05000000000003, duration=0.793s, table=0, n_packets=1300, n_bytes=1874600, hard_timeout=120, send_flow_rem priority=200,udp,nw_src=10.0.0.3,nw_dst=10.0.0.18 actions=drop
    cookie=0xdd05000000000004, duration=0.822s, table=0, n_packets=1872, n_bytes=1995552, hard_timeout=120, send_flow_rem priority=200,udp,nw_src=10.0.0.4,nw_dst=10.0.0.18 actions=drop
    cookie=0xdd05000000000005, duration=0.822s, table=0, n_packets=2311, n_bytes=688678, hard_timeout=120, send_flow_rem priority=200,udp,nw_src=10.0.0.5,nw_dst=10.0.0.18 actions=drop
    cookie=0xdd05000000000006, duration=0.822s, table=0, n_packets=1541, n_bytes=1248210, hard_timeout=120, send_flow_rem priority=200,udp,nw_src=10.0.0.6,nw_dst=10.0.0.18 actions=drop

Legitimate traffic (per phase):
  h7 tcp_iperf3            before: 10.0Mbps  attack_unmitigated: 9.96Mbps  mitigated: 10.0Mbps  after: 9.99Mbps   -> preserved
  h8 udp_iperf3            before: 2.0Mbps/loss 0.0%  attack_unmitigated: 2.0Mbps/loss 0.0%  mitigated: 2.0Mbps/loss 0.0%  after: 1.97Mbps/loss 0.0%   -> preserved
  h9 http                  before: loss 0.0%/rtt 122.342ms  attack_unmitigated: loss 50.0%/rtt 2697.96ms  mitigated: loss 0.0%/rtt 152.826ms  after: loss 0.0%/rtt 124.878ms   -> preserved
  h10 udp_request_response  before: loss 0.88%/rtt 15.258ms  attack_unmitigated: loss 33.96%/rtt 19.738ms  mitigated: loss 0.0%/rtt 19.484ms  after: loss 0.0%/rtt 14.772ms   -> preserved
  h13 icmp_ping             before: loss 0.0%/rtt 0.213ms  attack_unmitigated: loss 0.0%/rtt 6.993ms  mitigated: loss 0.0%/rtt 0.343ms  after: loss 0.0%/rtt 0.225ms   -> preserved

Recovery: yes after 24.9s; attackers reach victim again: True

STATUS:
  >>> NORMAL TRAFFIC
  >>> SUSPICIOUS TRAFFIC
  >>> ATTACK CONFIRMED
  >>> MITIGATION INSTALLED
  >>> ATTACK TRAFFIC BLOCKED
  >>> LEGITIMATE TRAFFIC PRESERVED
  >>> NETWORK RECOVERED
