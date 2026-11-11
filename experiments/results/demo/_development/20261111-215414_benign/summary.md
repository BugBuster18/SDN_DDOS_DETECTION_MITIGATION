# Demo result: 20261111-215414_benign

- scenario: **benign**  traffic: **BENIGN**  mode: **DETECTION_ONLY**
- start 2026-11-11T21:54:14  end 2026-11-11T21:55:19  victim 10.0.0.18

Detection (controller view at the highest-scoring window):
  max state: CONFIRMED   max window score: 0.932 (threshold 0.682)
  sources=9  active flows=111  aggregate=4555 pps / 36.61 Mbps  avg pkt=1005 B
  flow-level ML (CIC-DDoS2019 model): max attack probability=0.999, 94% of flows flagged
  per-source view at that window (pps | flow-ML max prob | source score | blocked):
    10.0.0.11      1717 pps | 0.00 | 0.73 | no
    10.0.0.15       970 pps | 1.00 | 0.87 | no
    10.0.0.14       710 pps | 1.00 | 0.85 | no
    10.0.0.12       621 pps | 0.87 | 0.81 | no
    10.0.0.9        288 pps | 0.00 | 0.54 | no
    10.0.0.17       242 pps | 1.00 | 0.75 | no
    10.0.0.10         5 pps | 0.05 | 0.09 | no
    10.0.0.8          2 pps | 0.02 | 0.06 | no
    10.0.0.16         0 pps | 0.91 | 0.98 | no

Legitimate traffic (per phase):
  h11 tcp_iperf3            whole: 19.99Mbps   -> preserved
  h12 udp_iperf3               -> NOT preserved
  h14 udp_iperf3               -> NOT preserved
  h15 udp_iperf3               -> NOT preserved
  h17 udp_iperf3               -> NOT preserved
  h16 udp_request_response  whole: loss 0.0%/rtt 9.535ms   -> preserved
  h9 http                  whole: loss 0.0%/rtt 147.662ms   -> preserved
  h10 icmp_ping             whole: loss 0.0%/rtt 1.294ms   -> preserved
  h8 icmp_ping             whole: loss 0.0%/rtt 1.348ms   -> preserved

STATUS:
  >>> FALSE ALARM: ATTACK CONFIRMED ON BENIGN TRAFFIC
  >>> LEGITIMATE TRAFFIC DEGRADED: h12(udp_iperf3),h14(udp_iperf3),h15(udp_iperf3),h17(udp_iperf3)
