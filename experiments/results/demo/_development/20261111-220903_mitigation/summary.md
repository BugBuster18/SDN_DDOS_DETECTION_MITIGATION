# Demo result: 20261111-220903_mitigation

- scenario: **mitigation**  traffic: **UDP**  mode: **MITIGATION_ENABLED**
- start 2026-11-11T22:09:03  end 2026-11-11T22:10:39  victim 10.0.0.18

Detection (controller view at the highest-scoring window):
  max state: MITIGATING   max window score: 1.000 (threshold 0.682)
  sources=11  active flows=44  aggregate=5115 pps / 36.97 Mbps  avg pkt=904 B
  flow-level ML (CIC-DDoS2019 model): max attack probability=0.999, 91% of flows flagged
  per-source view at that window (pps | flow-ML max prob | source score | blocked):
    10.0.0.5        860 pps | 0.87 | 0.91 | no
    10.0.0.1        738 pps | 1.00 | 0.92 | no
    10.0.0.4        716 pps | 1.00 | 0.92 | no
    10.0.0.2        713 pps | 1.00 | 0.92 | no
    10.0.0.6        621 pps | 1.00 | 0.92 | no
    10.0.0.7        614 pps | 0.00 | 0.39 | no
    10.0.0.3        555 pps | 1.00 | 0.91 | no
    10.0.0.8        176 pps | 0.99 | 0.54 | no
    10.0.0.9        118 pps | 0.00 | 0.26 | no
    10.0.0.13         3 pps | 0.00 | 0.02 | no
  latency from attack start: suspicious=8.0 s, confirmed=11.6 s, first rule=11.6 s

Attack traffic (measured on the switches, packets/s):
  offered by attackers: 8839.0   delivered to victim switch before mitigation: 3213.0   after mitigation: 118.0   reduction: 96.3%
    h1 (10.0.0.1) UDP 1024B @3000pps: sent 1900.0  delivered before 1498.0  after 0.0  rule=yes
    h2 (10.0.0.2) UDP 512B @3000pps: sent 1317.0  delivered before 0.0  after 47.0  rule=yes
    h3 (10.0.0.3) UDP 1400B @2000pps: sent 975.0  delivered before 0.0  after 36.0  rule=yes
    h4 (10.0.0.4) UDP 1024B @3000pps: sent 1334.0  delivered before 924.0  after 0.0  rule=yes
    h5 (10.0.0.5) UDP 256B @4000pps: sent 1669.0  delivered before 509.0  after 0.0  rule=yes
    h6 (10.0.0.6) UDP 768B @2500pps: sent 1644.0  delivered before 281.0  after 35.0  rule=yes

Mitigation: 8 rule(s) installed, 8 removed/expired, 0 dry-run would-block
    INSTALLED 0xdd05000000000001 DROP 10.0.0.1 -> 10.0.0.18 UDP at ['s1']
    INSTALLED 0xdd05000000000002 DROP 10.0.0.2 -> 10.0.0.18 UDP at ['s1']
    INSTALLED 0xdd05000000000003 DROP 10.0.0.3 -> 10.0.0.18 UDP at ['s1']
    INSTALLED 0xdd05000000000004 DROP 10.0.0.4 -> 10.0.0.18 UDP at ['s2']
    INSTALLED 0xdd05000000000005 DROP 10.0.0.5 -> 10.0.0.18 UDP at ['s2']
    INSTALLED 0xdd05000000000006 DROP 10.0.0.6 -> 10.0.0.18 UDP at ['s2']
    INSTALLED 0xdd05000000000007 DROP 10.0.0.10 -> 10.0.0.18 ICMP at ['s4']
    INSTALLED 0xdd05000000000008 DROP 10.0.0.10 -> 10.0.0.18 UDP at ['s4']
  rules as reported by Open vSwitch (ovs-ofctl dump-flows):
    cookie=0xdd05000000000001, duration=13.455s, table=0, n_packets=28680, n_bytes=30572880, hard_timeout=120, send_flow_rem priority=200,udp,nw_src=10.0.0.1,nw_dst=10.0.0.18 actions=drop
    cookie=0xdd05000000000002, duration=13.455s, table=0, n_packets=14229, n_bytes=7882866, hard_timeout=120, send_flow_rem priority=200,udp,nw_src=10.0.0.2,nw_dst=10.0.0.18 actions=drop
    cookie=0xdd05000000000003, duration=13.455s, table=0, n_packets=10220, n_bytes=14737240, hard_timeout=120, send_flow_rem priority=200,udp,nw_src=10.0.0.3,nw_dst=10.0.0.18 actions=drop
    cookie=0xdd05000000000004, duration=13.487s, table=0, n_packets=15111, n_bytes=16108326, hard_timeout=120, send_flow_rem priority=200,udp,nw_src=10.0.0.4,nw_dst=10.0.0.18 actions=drop
    cookie=0xdd05000000000005, duration=13.487s, table=0, n_packets=19072, n_bytes=5683456, hard_timeout=120, send_flow_rem priority=200,udp,nw_src=10.0.0.5,nw_dst=10.0.0.18 actions=drop
    cookie=0xdd05000000000006, duration=13.487s, table=0, n_packets=25715, n_bytes=20829150, hard_timeout=120, send_flow_rem priority=200,udp,nw_src=10.0.0.6,nw_dst=10.0.0.18 actions=drop
    cookie=0xdd05000000000007, duration=1.054s, table=0, n_packets=0, n_bytes=0, hard_timeout=120, send_flow_rem priority=200,icmp,nw_src=10.0.0.10,nw_dst=10.0.0.18 actions=drop
    cookie=0xdd05000000000008, duration=1.054s, table=0, n_packets=2, n_bytes=340, hard_timeout=120, send_flow_rem priority=200,udp,nw_src=10.0.0.10,nw_dst=10.0.0.18 actions=drop

Legitimate traffic (per phase):
  h7 tcp_iperf3            before: 10.0Mbps  attack_unmitigated: 9.96Mbps  mitigated: 10.0Mbps  after: 9.99Mbps   -> preserved
  h8 udp_iperf3            before: 2.0Mbps/loss 0.0%  attack_unmitigated: 2.0Mbps/loss 0.0%  mitigated: 2.0Mbps/loss 0.0%  after: 1.96Mbps/loss 0.0%   -> preserved
  h9 http                  before: loss 0.0%/rtt 126.18ms  attack_unmitigated: loss 100.0%/rtt 3002.453ms  mitigated: loss 0.0%/rtt 339.168ms  after: loss 0.0%/rtt 162.901ms   -> preserved
  h10 udp_request_response  before: loss 0.42%/rtt 16.157ms  attack_unmitigated: loss 100.0%  mitigated: loss 10.67%/rtt 19.418ms  after: loss 1.46%/rtt 19.284ms   -> NOT preserved (BLOCKED BY RULE)
  h13 icmp_ping             before: loss 0.0%/rtt 0.582ms  attack_unmitigated: loss 0.0%/rtt 0.107ms   -> preserved

Recovery: yes after 24.8s; attackers reach victim again: True

STATUS:
  >>> NORMAL TRAFFIC
  >>> SUSPICIOUS TRAFFIC
  >>> ATTACK CONFIRMED
  >>> MITIGATION INSTALLED
  >>> ATTACK TRAFFIC BLOCKED
  >>> LEGITIMATE TRAFFIC BLOCKED: rule installed on 10.0.0.10
  >>> NETWORK RECOVERED
