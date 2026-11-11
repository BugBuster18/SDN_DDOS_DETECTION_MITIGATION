# Demo result: 20261111-215740_benign

- scenario: **benign**  traffic: **BENIGN**  mode: **DETECTION_ONLY**
- start 2026-11-11T21:57:40  end 2026-11-11T21:58:45  victim 10.0.0.18

Detection (controller view at the highest-scoring window):
  max state: NORMAL   max window score: 0.591 (threshold 0.682)
  sources=6  active flows=10  aggregate=4876 pps / 38.05 Mbps  avg pkt=975 B
  flow-level ML (CIC-DDoS2019 model): max attack probability=0.998, 30% of flows flagged
  per-source view at that window (pps | flow-ML max prob | source score | blocked):
    10.0.0.11      1891 pps | 0.00 | 0.30 | no
    10.0.0.15      1064 pps | 1.00 | 0.53 | no
    10.0.0.14       778 pps | 1.00 | 0.48 | no
    10.0.0.12       681 pps | 0.54 | 0.31 | no
    10.0.0.9        457 pps | 0.00 | 0.11 | no
    10.0.0.10         5 pps | 0.00 | 0.01 | no

Legitimate traffic (per phase):
  h11 tcp_iperf3            whole: 19.99Mbps   -> preserved
  h12 udp_iperf3            whole: 0.99Mbps/loss 0.0%   -> preserved
  h14 udp_iperf3            whole: 7.95Mbps/loss 0.0%   -> preserved
  h15 udp_iperf3            whole: 3.97Mbps/loss 0.0%   -> preserved
  h9 http                  whole: loss 0.0%/rtt 136.451ms   -> preserved
  h10 icmp_ping             whole: loss 0.0%/rtt 0.868ms   -> preserved

STATUS:
  >>> NORMAL TRAFFIC
  >>> LEGITIMATE TRAFFIC PRESERVED
