from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

from ryu.lib.packet import in_proto
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet import tcp
from ryu.lib.packet import udp

import os


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    # Forwarding-rule timeouts (seconds). Defaults preserve the original 20/100 behaviour.
    FLOW_IDLE_TIMEOUT = int(os.environ.get("DDOS_FLOW_IDLE_TIMEOUT", "20"))
    FLOW_HARD_TIMEOUT = int(os.environ.get("DDOS_FLOW_HARD_TIMEOUT", "100"))

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle=0, hard=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id is not None:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    idle_timeout=idle, hard_timeout=hard,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    idle_timeout=idle, hard_timeout=hard,
                                    match=match, instructions=inst)
            
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth_headers = pkt.get_protocols(ethernet.ethernet)
        if not eth_headers:
            return
        eth = eth_headers[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:

            # check IP Protocol and create a match for IP
            if eth.ethertype == ether_types.ETH_TYPE_IP:
                ip = pkt.get_protocol(ipv4.ipv4)
                match = None
                if ip is not None:
                    srcip = ip.src
                    dstip = ip.dst
                    protocol = ip.proto

                    if protocol == in_proto.IPPROTO_ICMP:
                        t = pkt.get_protocol(icmp.icmp)
                        if t is not None:
                            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                                    ipv4_src=srcip, ipv4_dst=dstip,
                                                    ip_proto=protocol, icmpv4_code=t.code,
                                                    icmpv4_type=t.type)
                    elif protocol == in_proto.IPPROTO_TCP:
                        t = pkt.get_protocol(tcp.tcp)
                        if t is not None:
                            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                                    ipv4_src=srcip, ipv4_dst=dstip,
                                                    ip_proto=protocol, tcp_src=t.src_port, tcp_dst=t.dst_port)
                    elif protocol == in_proto.IPPROTO_UDP:
                        u = pkt.get_protocol(udp.udp)
                        if u is not None:
                            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                                    ipv4_src=srcip, ipv4_dst=dstip,
                                                    ip_proto=protocol, udp_src=u.src_port, udp_dst=u.dst_port)

                if match is not None:
                    if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                        self.add_flow(datapath, 1, match, actions, msg.buffer_id, idle=self.FLOW_IDLE_TIMEOUT, hard=self.FLOW_HARD_TIMEOUT)
                        return
                    self.add_flow(datapath, 1, match, actions, idle=self.FLOW_IDLE_TIMEOUT, hard=self.FLOW_HARD_TIMEOUT)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
