# Demo result: 20261111-224056_mitigation

- scenario: **mitigation**  traffic: **UDP**  mode: **MITIGATION_ENABLED**
- start 2026-11-11T22:40:56  end 2026-11-11T22:42:32  victim 10.0.0.18

Detection (controller view at the highest-scoring window):
  max state: MITIGATING   max window score: 1.000 (threshold 0.682)
  sources=11  active flows=20  aggregate=9099 pps / 64.61 Mbps  avg pkt=888 B
  flow-level ML (CIC-DDoS2019 model): max attack probability=0.998, 78% of flows flagged
  per-source view at that window (pps | flow-ML max prob | source score | blocked):
    10.0.0.5       1795 pps | 0.54 | 0.98 | no
    10.0.0.4       1715 pps | 1.00 | 0.99 | no
    10.0.0.6       1254 pps | 1.00 | 0.99 | no
    10.0.0.1       1200 pps | 1.00 | 0.99 | no
    10.0.0.2       1103 pps | 1.00 | 0.99 | no
    10.0.0.3        868 pps | 1.00 | 0.99 | no
    10.0.0.7        865 pps | 0.00 | 0.00 | no
    10.0.0.8        251 pps | 0.99 | 0.01 | no
    10.0.0.9         45 pps | 0.89 | 0.00 | no
    10.0.0.13         2 pps | 0.00 | 0.00 | no
  latency from attack start: suspicious=7.0 s, confirmed=11.7 s, first rule=11.7 s

Attack traffic (measured on the switches, packets/s):
  offered by attackers: 12908.0   delivered to victim switch before mitigation: 9334.0   after mitigation: 0.0   reduction: 100.0%
    h1 (10.0.0.1) UDP 1024B @3000pps: sent 2205.0  delivered before 1553.0  after 0.0  rule=yes
    h2 (10.0.0.2) UDP 512B @3000pps: sent 2214.0  delivered before 655.0  after 0.0  rule=yes
    h3 (10.0.0.3) UDP 1400B @2000pps: sent 1590.0  delivered before 738.0  after 0.0  rule=yes
    h4 (10.0.0.4) UDP 1024B @3000pps: sent 2213.0  delivered before 2019.0  after 0.0  rule=yes
    h5 (10.0.0.5) UDP 256B @4000pps: sent 2782.0  delivered before 2575.0  after 0.0  rule=yes
    h6 (10.0.0.6) UDP 768B @2500pps: sent 1904.0  delivered before 1794.0  after 0.0  rule=yes

Mitigation: 6 rule(s) installed, 6 removed/expired, 0 dry-run would-block
    INSTALLED 0xdd05000000000001 DROP 10.0.0.1 -> 10.0.0.18 UDP at ['s1']
    INSTALLED 0xdd05000000000002 DROP 10.0.0.2 -> 10.0.0.18 UDP at ['s1']
    INSTALLED 0xdd05000000000003 DROP 10.0.0.3 -> 10.0.0.18 UDP at ['s1']
    INSTALLED 0xdd05000000000004 DROP 10.0.0.4 -> 10.0.0.18 UDP at ['s2']
    INSTALLED 0xdd05000000000005 DROP 10.0.0.5 -> 10.0.0.18 UDP at ['s2']
    INSTALLED 0xdd05000000000006 DROP 10.0.0.6 -> 10.0.0.18 UDP at ['s2']
  rules as reported by Open vSwitch (ovs-ofctl dump-flows):
    cookie=0xdd05000000000001, duration=0.331s, table=0, n_packets=761, n_bytes=811226, hard_timeout=120, send_flow_rem priority=200,udp,nw_src=10.0.0.1,nw_dst=10.0.0.18 actions=drop
    cookie=0xdd05000000000002, duration=0.331s, table=0, n_packets=767, n_bytes=424918, hard_timeout=120, send_flow_rem priority=200,udp,nw_src=10.0.0.2,nw_dst=10.0.0.18 actions=drop
    cookie=0xdd05000000000003, duration=0.331s, table=0, n_packets=554, n_bytes=798868, hard_timeout=120, send_flow_rem priority=200,udp,nw_src=10.0.0.3,nw_dst=10.0.0.18 actions=drop
    cookie=0xdd05000000000004, duration=0.364s, table=0, n_packets=830, n_bytes=884780, hard_timeout=120, send_flow_rem priority=200,udp,nw_src=10.0.0.4,nw_dst=10.0.0.18 actions=drop
    cookie=0xdd05000000000005, duration=0.364s, table=0, n_packets=1051, n_bytes=313198, hard_timeout=120, send_flow_rem priority=200,udp,nw_src=10.0.0.5,nw_dst=10.0.0.18 actions=drop
    cookie=0xdd05000000000006, duration=0.363s, table=0, n_packets=694, n_bytes=562140, hard_timeout=120, send_flow_rem priority=200,udp,nw_src=10.0.0.6,nw_dst=10.0.0.18 actions=drop

Legitimate traffic (per phase):
  h7 tcp_iperf3            before: 10.0Mbps  attack_unmitigated: 9.96Mbps  mitigated: 10.0Mbps  after: 9.96Mbps   -> preserved
  h8 udp_iperf3            before: 2.0Mbps/loss 0.0%  attack_unmitigated: 2.0Mbps/loss 0.0%  mitigated: 2.0Mbps/loss 0.0%  after: 1.98Mbps/loss 0.0%   -> preserved
  h9 http                  before: loss 0.0%/rtt 137.059ms  attack_unmitigated: loss 100.0%/rtt 3001.944ms  mitigated: loss 0.0%/rtt 160.063ms  after: loss 0.0%/rtt 125.611ms   -> preserved
  h10 udp_request_response  before: loss 0.0%/rtt 16.501ms  attack_unmitigated: loss 47.62%/rtt 34.515ms  mitigated: loss 0.0%/rtt 20.758ms  after: loss 0.0%/rtt 14.598ms   -> preserved
  h13 icmp_ping             before: loss 0.0%/rtt 0.338ms  attack_unmitigated: loss 0.0%/rtt 49.498ms  mitigated: loss 0.0%/rtt 0.377ms  after: loss 0.0%/rtt 0.468ms   -> preserved

Recovery: yes after 23.9s; attackers reach victim again: True

STATUS:
  >>> NORMAL TRAFFIC
  >>> SUSPICIOUS TRAFFIC
  >>> ATTACK CONFIRMED
  >>> MITIGATION INSTALLED
  >>> ATTACK TRAFFIC BLOCKED
  >>> LEGITIMATE TRAFFIC PRESERVED
  >>> NETWORK RECOVERED
