# Demo result: 20261113-073120_crowd

- scenario: **crowd**  traffic: **BENIGN**  mode: **DETECTION_ONLY**
- start 2026-11-13T07:31:20  end 2026-11-13T07:32:25  victim 10.0.0.18

Detection (controller view at the highest-scoring window):
  max state: CONFIRMED   max window score: 0.900 (threshold 0.682)
  sources=9  active flows=111  aggregate=4539 pps / 36.32 Mbps  avg pkt=1000 B
  flow-level ML (CIC-DDoS2019 model): max attack probability=0.998, 94% of flows flagged
  per-source view at that window (pps | flow-ML max prob | source score | blocked):
    10.0.0.11      1704 pps | 0.00 | 0.81 | no
    10.0.0.15       962 pps | 1.00 | 0.92 | no
    10.0.0.14       704 pps | 1.00 | 0.90 | no
    10.0.0.12       616 pps | 0.54 | 0.81 | no
    10.0.0.9        306 pps | 0.00 | 0.63 | no
    10.0.0.17       241 pps | 0.99 | 0.82 | no
    10.0.0.10         5 pps | 0.01 | 0.10 | no
    10.0.0.8          2 pps | 0.00 | 0.06 | no
    10.0.0.16         0 pps | 0.91 | 0.98 | no

Legitimate traffic (per phase):
  h11 tcp_iperf3            whole: 19.99Mbps   -> preserved
  h12 udp_iperf3            whole: 0.99Mbps/loss 0.0%   -> preserved
  h14 udp_iperf3            whole: 7.97Mbps/loss 0.0%   -> preserved
  h15 udp_iperf3            whole: 3.95Mbps/loss 0.0%   -> preserved
  h17 udp_iperf3            whole: 1.99Mbps/loss 0.0%   -> preserved
  h16 udp_request_response  whole: loss 0.0%/rtt 15.132ms   -> preserved
  h9 http                  whole: loss 0.0%/rtt 176.157ms   -> preserved
  h10 icmp_ping             whole: loss 0.0%/rtt 1.217ms   -> preserved
  h8 icmp_ping             whole: loss 0.0%/rtt 1.47ms   -> preserved

STATUS:
  >>> FALSE ALARM: ATTACK CONFIRMED ON BENIGN TRAFFIC
  >>> LEGITIMATE TRAFFIC PRESERVED
