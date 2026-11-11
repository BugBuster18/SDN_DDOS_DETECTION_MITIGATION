# Demo result: 20261111-224233_mitigation

- scenario: **mitigation**  traffic: **ICMP**  mode: **MITIGATION_ENABLED**
- start 2026-11-11T22:42:33  end 2026-11-11T22:44:08  victim 10.0.0.18

Detection (controller view at the highest-scoring window):
  max state: CONFIRMED   max window score: 1.000 (threshold 0.682)
  sources=9  active flows=10  aggregate=6870 pps / 34.65 Mbps  avg pkt=630 B
  flow-level ML (CIC-DDoS2019 model): max attack probability=0.992, 10% of flows flagged
  per-source view at that window (pps | flow-ML max prob | source score | blocked):
    10.0.0.5       1250 pps | 0.00 | 0.81 | no
    10.0.0.2       1244 pps | 0.00 | 0.81 | no
    10.0.0.4        977 pps | 0.00 | 0.78 | no
    10.0.0.1        977 pps | 0.00 | 0.78 | no
    10.0.0.6        812 pps | 0.00 | 0.77 | no
    10.0.0.7        710 pps | 0.00 | 0.00 | no
    10.0.0.3        693 pps | 0.00 | 0.75 | no
    10.0.0.8        208 pps | 0.99 | 0.00 | no
    10.0.0.9          0 pps | 0.01 | 0.00 | no
  latency from attack start: suspicious=4.3 s, confirmed=10.4 s, first rule=- s

Attack traffic (measured on the switches, packets/s):
  offered by attackers: 7156.0   delivered to victim switch before mitigation: 7131.0   after mitigation: None   reduction: None%
    h1 (10.0.0.1) ICMP 512B @1500pps: sent 1114.0  delivered before 1114.0  after None  rule=no
    h2 (10.0.0.2) ICMP 256B @2000pps: sent 1511.0  delivered before 1512.0  after None  rule=no
    h3 (10.0.0.3) ICMP 1000B @1000pps: sent 839.0  delivered before 839.0  after None  rule=no
    h4 (10.0.0.4) ICMP 512B @1500pps: sent 1190.0  delivered before 1191.0  after None  rule=no
    h5 (10.0.0.5) ICMP 128B @2000pps: sent 1508.0  delivered before 1480.0  after None  rule=no
    h6 (10.0.0.6) ICMP 768B @1200pps: sent 994.0  delivered before 995.0  after None  rule=no

Mitigation: 0 rule(s) installed, 0 removed/expired, 0 dry-run would-block

Legitimate traffic (per phase):
  h7 tcp_iperf3            before: 10.0Mbps  attack_unmitigated: 10.0Mbps  after: 9.99Mbps   -> preserved
  h8 udp_iperf3            before: 2.0Mbps/loss 0.0%  attack_unmitigated: 2.0Mbps/loss 0.0%  after: 1.99Mbps/loss 0.0%   -> preserved
  h9 http                  before: loss 0.0%/rtt 113.413ms  attack_unmitigated: loss 15.0%/rtt 736.587ms  after: loss 0.0%/rtt 125.383ms   -> NOT preserved
  h10 udp_request_response  before: loss 0.43%/rtt 14.656ms  attack_unmitigated: loss 4.7%/rtt 19.579ms  after: loss 0.0%/rtt 15.057ms   -> preserved
  h13 icmp_ping             before: loss 0.0%/rtt 0.489ms  attack_unmitigated: loss 10.26%/rtt 57.525ms  after: loss 0.0%/rtt 0.33ms   -> NOT preserved

Recovery: yes after 22.9s; attackers reach victim again: True

STATUS:
  >>> NORMAL TRAFFIC
  >>> SUSPICIOUS TRAFFIC
  >>> ATTACK CONFIRMED
  >>> LEGITIMATE TRAFFIC DEGRADED: h9(http),h13(icmp_ping)
  >>> NETWORK RECOVERED
