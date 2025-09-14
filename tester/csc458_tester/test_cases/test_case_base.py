import logging
import dpkt
from twisted.internet import reactor, defer
from csc458_tester.constants import *

log = logging.getLogger()


class TestCase(object):
    def __init__(self, config):
        self.points = 0
        self.finished = False
        self.ignoreARP = True
        self.config = config
        self.text_desp = "packet not received"
        self.text_desp_level = 0

    def update_text_desp(self, msg, level):
        if level > self.text_desp_level:
            self.text_desp_level = level
            self.text_desp = msg

    def finish(self):
        pass

    def send_packet(self, intf, packet):
        log.error("should be overridden")

    def receive_packet(self, intf, packet):
        log.error("should be overridden")

    def get_ip_pkt(self, ip_src, ip_dst, mac_dst, proto=1, data=""):
        # Ensure data is bytes for dpkt compatibility
        if isinstance(data, str):
            data = data.encode("utf-8")
        mac_src = self.config.ARP_CACHE[ip_src]
        pkt = dpkt.ethernet.Ethernet(
            dst=mac_dst, src=mac_src, type=dpkt.ethernet.ETH_TYPE_IP
        )
        ip = dpkt.ip.IP(dst=ip_dst, src=ip_src, p=proto, data=data, ttl=TTL_INIT)

        pkt.data = ip
        ip.len += len(data)
        return pkt

    def get_icmp_echo(
        self,
        ip_src,
        ip_dst,
        mac_dst,
        type=8,
        id=123,
        seq=1,
        data="Antonin rules so deal with it!",
    ):
        # Ensure data is bytes for dpkt compatibility
        if isinstance(data, str):
            data = data.encode("utf-8")
        icmp = dpkt.icmp.ICMP(
            type=type, data=dpkt.icmp.ICMP.Echo(id=id, seq=seq, data=data)
        )
        pkt = self.get_ip_pkt(ip_src, ip_dst, mac_dst, proto=1, data=icmp)
        return pkt

    def finish(self):
        # A signal denoting the finish...
        try:
            self.timeout_fn.cancel()
        except:
            pass
        if self.finished == False:
            self.finished = True
            reactor.callLater(0, self.finisher.callback, "")

    def timeout(self):
        self.err("Test %s timed out" % self.name)
        self.finish()
