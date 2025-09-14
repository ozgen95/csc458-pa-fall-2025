import dpkt

from twisted.internet import reactor, defer
from csc458_tester.test_cases.test_case_base import TestCase
from csc458_tester.constants import *


class Public_TCPForward(TestCase):
    MAX_POINTS = 1
    """Send one TCP packet through router → expect it forwarded once."""

    def __init__(self, config, in_intf, ip_src, ip_dst):
        super().__init__(config)
        self.in_intf = in_intf
        self.ip_src = ip_src
        self.ip_dst = ip_dst
        self.timeout_secs = 2

    def start_test(self):
        tcp = dpkt.tcp.TCP(data=b"hello")
        pkt = self.get_ip_pkt(
            self.ip_src,
            self.ip_dst,
            self.config.MAC_INTFS[self.in_intf],
            proto=6,
            data=tcp,
        )
        self.send_packet(self.in_intf, pkt)
        self.timeout_fn = reactor.callLater(self.timeout_secs, self.timeout)
        self.finisher = defer.Deferred()
        return self.finisher

    def receive_packet(self, intf, raw_packet):
        pkt = dpkt.ethernet.Ethernet(raw_packet)
        if pkt.type == dpkt.ethernet.ETH_TYPE_IP and pkt.data.p == 6:
            self.points = 1
            self.update_text_desp("correct TCP forwarding", 1)
            self.finish()