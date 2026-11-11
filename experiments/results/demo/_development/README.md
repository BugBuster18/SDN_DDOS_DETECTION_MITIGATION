Development runs made while building the demo (before the final fixes: packet-in rate limit,
rate-attribution corroboration, strict per-source rate floor, ping/iperf3 parsing fixes).
They are kept because they document real failure modes (packet-in backlog, legitimate h7/h10
blocked by the earlier attribution policy). The final evidence is in the parent folder.
