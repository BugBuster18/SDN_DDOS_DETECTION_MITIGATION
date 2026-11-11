"""Optional exact-flow OpenFlow mitigation for ML-positive flows.

Mitigation is OFF by default. Set DDOS_AUTO_MITIGATE=1 only after validating
false-positive rates on your own SDN topology.
"""
from __future__ import annotations

import os
import time

from controller import SimpleMonitor13


class DDoSMitigator(SimpleMonitor13):
    def __init__(self, *args, **kwargs):
        self.auto_mitigate = os.environ.get("DDOS_AUTO_MITIGATE", "0").lower() in {"1", "true", "yes"}
        self.max_blocks_per_window = int(os.environ.get("DDOS_MAX_BLOCKS_PER_WINDOW", "20"))
        self.block_timeout = int(os.environ.get("DDOS_BLOCK_TIMEOUT", "30"))
        self._blocked_until = {}
        self._blocks_this_window = 0
        super(DDoSMitigator, self).__init__(*args, **kwargs)
        if self.auto_mitigate:
            self.logger.warning("Automatic exact-flow mitigation ENABLED; timeout=%ss", self.block_timeout)
        else:
            self.logger.info("Mitigation is in detection-only mode. Set DDOS_AUTO_MITIGATE=1 to enable exact-flow drops.")

    def _process_rows(self, rows):
        self._blocks_this_window = 0
        super(DDoSMitigator, self)._process_rows(rows)

    def _on_prediction(self, row, is_attack, probability):
        super(DDoSMitigator, self)._on_prediction(row, is_attack, probability)
        if not (is_attack and self.auto_mitigate):
            return
        self._drop_exact_flow(row)

    def _drop_exact_flow(self, row):
        datapath = row.get("datapath")
        fields = row.get("match_fields") or {}
        required = {"eth_type", "ipv4_src", "ipv4_dst", "ip_proto"}
        if datapath is None or not required.issubset(fields):
            self.logger.warning("Cannot mitigate predicted flow: exact IPv4 match fields unavailable")
            return
        if self._blocks_this_window >= self.max_blocks_per_window:
            self.logger.warning("Per-window mitigation limit reached; remaining flows are logged only")
            return
        key = (datapath.id, tuple(sorted((str(k), str(v)) for k, v in fields.items())))
        now = time.time()
        if self._blocked_until.get(key, 0) > now:
            return
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        match = parser.OFPMatch(**fields)
        # Empty instructions mean drop; the rule matches only this flow tuple.
        cookie = (int(now * 1_000_000) & 0xFFFFFFFFFFFF) | 0xDD05000000000000
        mod = parser.OFPFlowMod(
            datapath=datapath,
            cookie=cookie,
            command=ofproto.OFPFC_ADD,
            priority=200,
            match=match,
            instructions=[],
            hard_timeout=self.block_timeout,
        )
        datapath.send_msg(mod)
        self._blocked_until[key] = now + self.block_timeout
        self._blocks_this_window += 1
        self.logger.warning("Installed exact-flow drop rule on switch=%016x src=%s dst=%s proto=%s",
                            datapath.id, row.get("ip_src"), row.get("ip_dst"), row.get("ip_proto"))


# Ryu discovers this class from the module when launched with mitigation_module.py.
