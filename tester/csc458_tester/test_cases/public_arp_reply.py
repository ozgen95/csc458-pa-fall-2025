import dpkt

from twisted.internet import reactor, defer
from csc458_tester.test_cases.test_case_base import TestCase
from csc458_tester.constants import *


class Public_ARPReply(TestCase):
    MAX_POINTS = 1
    """Send ARP request for router IP → expect ARP reply."""

    def __init__(self, config, ifacename, ip_src):
        super().__init__(config)
        self.ifacename = ifacename
        self.ip_src = ip_src
        self.timeout_secs = 2
        self.ignoreARP = False

    def start_test(self):
        pkt = dpkt.ethernet.Ethernet(
            dst=MAC_BROAD,
            src=self.config.ARP_CACHE[self.ip_src],
            type=dpkt.ethernet.ETH_TYPE_ARP,
        )
        pkt.data = dpkt.arp.ARP(
            op=dpkt.arp.ARP_OP_REQUEST,
            sha=self.config.ARP_CACHE[self.ip_src],
            spa=self.ip_src,
            tha=MAC_BROAD,
            tpa=self.config.IP_INTFS[self.ifacename],
        )
        self.send_packet(self.ifacename, pkt)
        self.timeout_fn = reactor.callLater(self.timeout_secs, self.timeout)
        self.finisher = defer.Deferred()
        return self.finisher

    def receive_packet(self, intf, raw_packet):
        pkt = dpkt.ethernet.Ethernet(raw_packet)
        if pkt.type == dpkt.ethernet.ETH_TYPE_ARP and pkt.data.op == dpkt.arp.ARP_OP_REPLY:
            self.points = 1
            self.update_text_desp("correct ARP reply", 1)
            self.finish()
