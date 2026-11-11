# Demo result: 20261111-222521_udp

- scenario: **udp**  traffic: **UDP**  mode: **MITIGATION_ENABLED**
- start 2026-11-11T22:25:21  end 2026-11-11T22:27:06  victim 10.0.0.18

Detection (controller view at the highest-scoring window):
  max state: MITIGATING   max window score: 1.000 (threshold 0.682)
  sources=7  active flows=7  aggregate=11338 pps / 75.23 Mbps  avg pkt=829 B
  flow-level ML (CIC-DDoS2019 model): max attack probability=0.998, 100% of flows flagged
  per-source view at that window (pps | flow-ML max prob | source score | blocked):
    10.0.0.5       2342 pps | 0.54 | 0.92 | no
    10.0.0.2       1907 pps | 1.00 | 0.95 | no
    10.0.0.1       1891 pps | 1.00 | 0.95 | no
    10.0.0.4       1876 pps | 1.00 | 0.95 | no
    10.0.0.6       1666 pps | 1.00 | 0.94 | no
    10.0.0.3       1397 pps | 1.00 | 0.94 | no
    10.0.0.7        259 pps | 0.99 | 0.01 | no
  latency from attack start: suspicious=7.0 s, confirmed=11.9 s, first rule=11.9 s

Attack traffic (measured on the switches, packets/s):
  offered by attackers: 12413.0   delivered to victim switch before mitigation: 8445.0   after mitigation: 1208.0   reduction: 85.7%
    h1 (10.0.0.1) UDP 1024B @3000pps: sent 2230.0  delivered before 1952.0  after 461.0  rule=yes
    h2 (10.0.0.2) UDP 512B @3000pps: sent 1859.0  delivered before 1963.0  after 5.0  rule=yes
    h3 (10.0.0.3) UDP 1400B @2000pps: sent 1600.0  delivered before 0.0  after 75.0  rule=yes
    h4 (10.0.0.4) UDP 1024B @3000pps: sent 2131.0  delivered before 1568.0  after 219.0  rule=yes
    h5 (10.0.0.5) UDP 256B @4000pps: sent 2668.0  delivered before 2436.0  after 144.0  rule=yes
    h6 (10.0.0.6) UDP 768B @2500pps: sent 1925.0  delivered before 526.0  after 304.0  rule=yes

Mitigation: 12 rule(s) installed, 12 removed/expired, 0 dry-run would-block
    INSTALLED 0xdd05000000000011 DROP 10.0.0.1 -> 10.0.0.18 UDP at ['s1']
    INSTALLED 0xdd05000000000012 DROP 10.0.0.2 -> 10.0.0.18 UDP at ['s1']
    INSTALLED 0xdd05000000000013 DROP 10.0.0.3 -> 10.0.0.18 UDP at ['s1']
    INSTALLED 0xdd05000000000014 DROP 10.0.0.4 -> 10.0.0.18 UDP at ['s2']
    INSTALLED 0xdd05000000000015 DROP 10.0.0.5 -> 10.0.0.18 UDP at ['s2']
    INSTALLED 0xdd05000000000016 DROP 10.0.0.6 -> 10.0.0.18 UDP at ['s2']
    INSTALLED 0xdd05000000000017 DROP 10.0.0.1 -> 10.0.0.18 UDP at ['s1']
    INSTALLED 0xdd05000000000018 DROP 10.0.0.2 -> 10.0.0.18 UDP at ['s1']
    INSTALLED 0xdd05000000000019 DROP 10.0.0.3 -> 10.0.0.18 UDP at ['s1']
    INSTALLED 0xdd0500000000001a DROP 10.0.0.4 -> 10.0.0.18 UDP at ['s2']
    INSTALLED 0xdd0500000000001b DROP 10.0.0.5 -> 10.0.0.18 UDP at ['s2']
    INSTALLED 0xdd0500000000001c DROP 10.0.0.6 -> 10.0.0.18 UDP at ['s2']
  rules as reported by Open vSwitch (ovs-ofctl dump-flows):
    cookie=0xdd05000000000011, duration=0.211s, table=0, n_packets=511, n_bytes=544726, hard_timeout=120, send_flow_rem priority=200,udp,nw_src=10.0.0.1,nw_dst=10.0.0.18 actions=drop
    cookie=0xdd05000000000012, duration=0.211s, table=0, n_packets=511, n_bytes=283094, hard_timeout=120, send_flow_rem priority=200,udp,nw_src=10.0.0.2,nw_dst=10.0.0.18 actions=drop
    cookie=0xdd05000000000013, duration=0.210s, table=0, n_packets=365, n_bytes=526330, hard_timeout=120, send_flow_rem priority=200,udp,nw_src=10.0.0.3,nw_dst=10.0.0.18 actions=drop
    cookie=0xdd05000000000014, duration=0.252s, table=0, n_packets=600, n_bytes=639600, hard_timeout=120, send_flow_rem priority=200,udp,nw_src=10.0.0.4,nw_dst=10.0.0.18 actions=drop
    cookie=0xdd05000000000015, duration=0.252s, table=0, n_packets=719, n_bytes=214262, hard_timeout=120, send_flow_rem priority=200,udp,nw_src=10.0.0.5,nw_dst=10.0.0.18 actions=drop
    cookie=0xdd05000000000016, duration=0.252s, table=0, n_packets=515, n_bytes=417150, hard_timeout=120, send_flow_rem priority=200,udp,nw_src=10.0.0.6,nw_dst=10.0.0.18 actions=drop

Legitimate traffic (per phase):
  h7 udp_iperf3            before: 2.0Mbps/loss 0.0%  attack_unmitigated: 2.0Mbps/loss 0.0%  mitigated: 2.0Mbps/loss 0.0%  after: 1.96Mbps/loss 0.0%   -> preserved
  h13 icmp_ping             before: loss 0.0%/rtt 0.175ms  attack_unmitigated: loss 0.0%/rtt 0.081ms  mitigated: loss 0.0%/rtt 0.051ms  after: loss 0.0%/rtt 0.11ms   -> preserved

Recovery: yes after 23.9s; attackers reach victim again: True

STATUS:
  >>> NORMAL TRAFFIC
  >>> SUSPICIOUS TRAFFIC
  >>> ATTACK CONFIRMED
  >>> MITIGATION INSTALLED
  >>> ATTACK TRAFFIC REDUCED (86%, 6/6 sources blocked)
  >>> LEGITIMATE TRAFFIC PRESERVED
  >>> NETWORK RECOVERED
