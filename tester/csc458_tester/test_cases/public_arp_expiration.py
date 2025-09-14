import dpkt

from twisted.internet import reactor, defer
from csc458_tester.test_cases.test_case_base import TestCase
from csc458_tester.constants import *


class Public_ARPExpiration(TestCase):
    MAX_POINTS = 1
    """Ensure router expires ARP cache and re-ARPs after timeout."""

    def __init__(self, config, in_intf, ip_src, ip_dst, wait_time=20):
        super().__init__(config)
        self.in_intf = in_intf
        self.ip_src = ip_src
        self.ip_dst = ip_dst
        self.wait_time = wait_time
        self.seen_first_arp = False
        self.second_ping_sent = False
        self.ignoreARP = False
        self.timeout_secs = wait_time + 5  # add buffer

    def start_test(self):
        # First ICMP packet, should trigger ARP
        pkt = self.get_icmp_echo(
            self.ip_src,
            self.ip_dst,
            self.config.MAC_INTFS[self.in_intf]
        )
        self.send_packet(self.in_intf, pkt)
        self.timeout_fn = reactor.callLater(self.timeout_secs, self.timeout)
        self.finisher = defer.Deferred()
        return self.finisher

    def receive_packet(self, intf, raw_packet):
        pkt = dpkt.ethernet.Ethernet(raw_packet)

        # Detect ARP requests
        if pkt.type == dpkt.ethernet.ETH_TYPE_ARP and pkt.data.op == dpkt.arp.ARP_OP_REQUEST:
            if not self.seen_first_arp:
                self.seen_first_arp = True
                self.send_arp_reply(intf, pkt)

                # Schedule second ICMP echo after wait_time
                reactor.callLater(self.wait_time, self.send_second_ping)
            else:
                if not self.second_ping_sent:
                    return

                # Second ARP seen → success
                self.points = 1
                self.update_text_desp("router expired ARP cache and re-ARPed", 1)
                self.finish()

    def send_second_ping(self):
        self.second_ping_sent = True
        
        pkt = self.get_icmp_echo(
            self.ip_src,
            self.ip_dst,
            self.config.MAC_INTFS[self.in_intf]
        )
        self.send_packet(self.in_intf, pkt)

    def send_arp_reply(self, intf, req_pkt):
        arp = req_pkt.data
        mac = self.config.MAC_INTFS[intf]
        resp = dpkt.ethernet.Ethernet(
            src=mac, dst=req_pkt.src, type=dpkt.ethernet.ETH_TYPE_ARP
        )
        resp.data = dpkt.arp.ARP(
            op=dpkt.arp.ARP_OP_REPLY,
            sha=mac,
            spa=arp.tpa,
            tha=arp.sha,
            tpa=arp.spa,
        )
        self.send_packet(intf, resp)
