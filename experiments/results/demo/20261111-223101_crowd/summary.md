# Demo result: 20261111-223101_crowd

- scenario: **crowd**  traffic: **BENIGN**  mode: **DETECTION_ONLY**
- start 2026-11-11T22:31:01  end 2026-11-11T22:32:06  victim 10.0.0.18

Detection (controller view at the highest-scoring window):
  max state: CONFIRMED   max window score: 0.869 (threshold 0.682)
  sources=9  active flows=111  aggregate=4507 pps / 36.15 Mbps  avg pkt=1003 B
  flow-level ML (CIC-DDoS2019 model): max attack probability=0.998, 93% of flows flagged
  per-source view at that window (pps | flow-ML max prob | source score | blocked):
    10.0.0.11      1697 pps | 0.00 | 0.02 | no
    10.0.0.15       957 pps | 1.00 | 0.05 | no
    10.0.0.14       700 pps | 1.00 | 0.04 | no
    10.0.0.12       613 pps | 0.54 | 0.02 | no
    10.0.0.9        295 pps | 0.00 | 0.01 | no
    10.0.0.17       239 pps | 0.99 | 0.44 | no
    10.0.0.10         5 pps | 0.00 | 0.00 | no
    10.0.0.8          2 pps | 0.00 | 0.01 | no
    10.0.0.16         0 pps | 0.91 | 0.82 | no

Legitimate traffic (per phase):
  h11 tcp_iperf3            whole: 19.99Mbps   -> preserved
  h12 udp_iperf3            whole: 1.0Mbps/loss 0.0%   -> preserved
  h14 udp_iperf3            whole: 7.94Mbps/loss 0.0%   -> preserved
  h15 udp_iperf3            whole: 3.97Mbps/loss 0.0%   -> preserved
  h17 udp_iperf3            whole: 1.98Mbps/loss 0.0%   -> preserved
  h16 udp_request_response  whole: loss 0.0%/rtt 11.046ms   -> preserved
  h9 http                  whole: loss 0.0%/rtt 146.141ms   -> preserved
  h10 icmp_ping             whole: loss 0.0%/rtt 1.223ms   -> preserved
  h8 icmp_ping             whole: loss 0.0%/rtt 1.461ms   -> preserved

STATUS:
  >>> FALSE ALARM: ATTACK CONFIRMED ON BENIGN TRAFFIC
  >>> LEGITIMATE TRAFFIC PRESERVED
