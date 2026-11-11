# Demo result: 20261111-222956_benign

- scenario: **benign**  traffic: **BENIGN**  mode: **DETECTION_ONLY**
- start 2026-11-11T22:29:56  end 2026-11-11T22:31:01  victim 10.0.0.18

Detection (controller view at the highest-scoring window):
  max state: SUSPECTED   max window score: 0.928 (threshold 0.682)
  sources=9  active flows=20  aggregate=3066 pps / 24.22 Mbps  avg pkt=987 B
  flow-level ML (CIC-DDoS2019 model): max attack probability=0.999, 15% of flows flagged
  per-source view at that window (pps | flow-ML max prob | source score | blocked):
    10.0.0.11      1211 pps | 0.01 | 0.24 | no
    10.0.0.15       676 pps | 1.00 | 0.16 | no
    10.0.0.14       494 pps | 1.00 | 0.14 | no
    10.0.0.12       432 pps | 0.87 | 0.17 | no
    10.0.0.9        249 pps | 0.00 | 0.17 | no
    10.0.0.10         4 pps | 0.05 | 0.07 | no
    10.0.0.13         0 pps | 0.00 | 0.03 | no
    10.0.0.16         0 pps | 0.01 | 0.12 | no
    10.0.0.17         0 pps | 0.01 | 0.12 | no

Legitimate traffic (per phase):
  h11 tcp_iperf3            whole: 19.99Mbps   -> preserved
  h12 udp_iperf3            whole: 0.99Mbps/loss 0.0%   -> preserved
  h14 udp_iperf3            whole: 7.94Mbps/loss 0.0%   -> preserved
  h15 udp_iperf3            whole: 3.97Mbps/loss 0.0%   -> preserved
  h9 http                  whole: loss 0.0%/rtt 131.502ms   -> preserved
  h10 icmp_ping             whole: loss 0.0%/rtt 1.068ms   -> preserved

STATUS:
  >>> SUSPICIOUS TRAFFIC (false alarm on benign traffic - never confirmed)
  >>> LEGITIMATE TRAFFIC PRESERVED
