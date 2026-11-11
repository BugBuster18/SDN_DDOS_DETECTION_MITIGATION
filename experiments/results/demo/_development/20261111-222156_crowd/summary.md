# Demo result: 20261111-222156_crowd

- scenario: **crowd**  traffic: **BENIGN**  mode: **MITIGATION_ENABLED**
- start 2026-11-11T22:21:56  end 2026-11-11T22:23:16  victim 10.0.0.18

Detection (controller view at the highest-scoring window):
  max state: MITIGATING   max window score: 0.886 (threshold 0.682)
  sources=9  active flows=111  aggregate=4537 pps / 36.44 Mbps  avg pkt=1004 B
  flow-level ML (CIC-DDoS2019 model): max attack probability=0.998, 94% of flows flagged
  per-source view at that window (pps | flow-ML max prob | source score | blocked):
    10.0.0.11      1710 pps | 0.00 | 0.86 | no
    10.0.0.15       966 pps | 1.00 | 0.94 | no
    10.0.0.14       706 pps | 1.00 | 0.93 | no
    10.0.0.12       618 pps | 0.54 | 0.86 | no
    10.0.0.9        289 pps | 0.00 | 0.69 | no
    10.0.0.17       242 pps | 0.99 | 0.87 | no
    10.0.0.10         5 pps | 0.00 | 0.13 | no
    10.0.0.8          2 pps | 0.00 | 0.08 | no
    10.0.0.16         0 pps | 0.91 | 0.98 | no

Legitimate traffic (per phase):
  h11 tcp_iperf3            whole: 19.99Mbps   -> preserved
  h12 udp_iperf3            whole: 0.99Mbps/loss 0.0%   -> preserved
  h14 udp_iperf3            whole: 0.64Mbps/loss 0.0%   -> NOT preserved (BLOCKED BY RULE)
  h15 udp_iperf3            whole: 0.32Mbps/loss 0.0%   -> NOT preserved (BLOCKED BY RULE)
  h17 udp_iperf3            whole: 1.99Mbps/loss 0.0%   -> preserved
  h16 udp_request_response  whole: loss 0.0%/rtt 9.484ms   -> preserved
  h9 http                  whole: loss 0.0%/rtt 144.103ms   -> preserved
  h10 icmp_ping             whole: loss 0.0%/rtt 0.947ms   -> preserved
  h8 icmp_ping             whole: loss 0.0%/rtt 1.291ms   -> preserved

STATUS:
  >>> FALSE ALARM: ATTACK CONFIRMED ON BENIGN TRAFFIC
  >>> LEGITIMATE TRAFFIC BLOCKED: rule installed on 10.0.0.14,10.0.0.15
