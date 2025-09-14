import time
import logging
import json

# Required for VNS
import sys
import os

from twisted.internet import reactor, defer
from csc458_tester.utils import pack_ip, pack_mac
from csc458_tester.vns_protocol import create_vns_server
from csc458_tester.vns_protocol import (
    VNSOpen,
    VNSClose,
    VNSPacket,
    VNSOpenTemplate,
    VNSBanner,
)
from csc458_tester.vns_protocol import (
    VNSRtable,
    VNSAuthRequest,
    VNSAuthReply,
    VNSAuthStatus,
    VNSInterface,
    VNSHardwareInfo,
)
from csc458_tester.test_cases import (
    TestCase,
    Public_ARPReply,
    Public_ARPExpiration,
    Public_ICMPEcho,
    Public_ICMPForward,
    Public_TCPForward,
)
from csc458_tester.constants import *

# For testing
import dpkt
import termcolor as T
from collections import defaultdict, namedtuple, OrderedDict
import random
import subprocess

from base64 import b64encode

log = logging.getLogger()
# log.setLevel(logging.DEBUG)
log.setLevel(logging.CRITICAL)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
# create formatter
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
ch.setFormatter(formatter)
log.addHandler(ch)


def warn(s):
    log.warning(T.colored(s, "yellow"))


def mac_random():
    return os.urandom(6)


def carry_around_add(a, b):
    c = a + b
    return (c & 0xFFFF) + (c >> 16)


def checksum(msg):
    s = 0
    if len(msg) % 2 == 1:
        msg += "\00"
    for i in range(0, len(msg), 2):
        w = msg[i] + (msg[i + 1] << 8)
        s = carry_around_add(s, w)
    return ~s & 0xFFFF


# Dst prefix, gateway, netmask, intfname-out
# rtable=[ ('0.0.0.0', IP_DEFAULT_GW_STR, '0.0.0.0', 'eth1'),
#          #(IP_SERVER1_STR, IP_SERVER1_STR, '255.255.255.255', 'eth2'),
#          #(IP_SERVER2_STR, IP_SERVER2_STR, '255.255.255.255', 'eth2')]
#          ]
# for ip in IP_EXTERNAL_SAMPLE_STR:
#   rtable.append((ip, ip, '255.255.255.255', INTF_EXTERNAL))

# def print_rtable():
#   for entry in rtable:
#     print ' '.join(entry)

# print_rtable()

# ARP_CACHE = defaultdict(lambda: pack_mac('00:00:00:01:02:03'))



class SRConfig:
    # MAC_INTF1_STR = '0e:55:50:5c:b6:a6'
    # MAC_INTF2_STR = '9e:6b:6e:31:16:e3'
    # MAC_INTF3_STR = '16:bb:e2:f3:61:aa'
    MAC_INTFS_STR = {
        INTF1: "0e:55:50:5c:b6:a6",
        INTF2: "9e:6b:6e:31:16:e3",
        INTF3: "16:bb:e2:f3:61:aa",
    }

    IP_DEFAULT_GW_STR = "10.0.1.1"

    def __init__(self):
        self.MAC_INTFS = {}
        for i, mac in self.MAC_INTFS_STR.items():
            self.MAC_INTFS[i] = pack_mac(mac)
        # self.MAC_INTF1 = pack_mac(MAC_INTF1_STR)
        # self.MAC_INTF2 = pack_mac(MAC_INTF2_STR)
        # self.MAC_INTF3 = pack_mac(MAC_INTF3_STR)

        self.IP_DEFAULT_GW = pack_ip(self.IP_DEFAULT_GW_STR)

        self.parse_ips()

    def parse_ips(self):
        def read_ip(line):
            return line.strip().split(" ")[-1]

        ip_config_path = "IP_CONFIG"
        lines = open(ip_config_path).readlines()
        SERVER1_IP = read_ip(lines[0])
        SERVER2_IP = read_ip(lines[1])
        CLIENT_IP = read_ip(lines[2])
        self.IP_INTFS_STR = {
            INTF1: read_ip(lines[3]),
            INTF2: read_ip(lines[4]),
            INTF3: read_ip(lines[5]),
        }
        self.IP_INTFS = {}
        for i, ip in self.IP_INTFS_STR.items():
            self.IP_INTFS[i] = pack_ip(ip)

        self.IP_SERVER1 = pack_ip(SERVER1_IP)
        self.IP_SERVER2 = pack_ip(SERVER2_IP)
        self.IP_CLIENT = pack_ip(CLIENT_IP)

        # warn("parsed IP server1, server2, client, router1, router2, router3: %s"\
        #      % str([SERVER1_IP, SERVER2_IP, CLIENT_IP,
        #             ROUTER1_IP, ROUTER2_IP, ROUTER3_IP]))

        # self.IPS_ROUTER = [IP_INTF1, IP_INTF2, IP_INTF3]

        # self.IFACES = {INTF1: (IP_INTF1, MAC_INTF1),
        #                INTF2: (IP_INTF2, MAC_INTF2),
        #                INTF3: (IP_INTF3, MAC_INTF3)}

        self.IP_SERVERS = [self.IP_SERVER1, self.IP_SERVER2]

        self.OUT_INTFS = defaultdict(lambda: INTF3)
        self.OUT_INTFS[self.IP_SERVER1] = INTF1
        self.OUT_INTFS[self.IP_SERVER2] = INTF2

        self.ARP_CACHE = {}
        for ip in [self.IP_CLIENT, self.IP_DEFAULT_GW] + self.IP_SERVERS:
            self.ARP_CACHE[ip] = mac_random()

        return


class SRServerListener:
    """TCP Server to handle connection to SR"""

    def __init__(self, packethandler, config, address=("127.0.0.1", 8888)):
        port = address[1]
        self.config = config
        self.srclients = []
        self.listen_port = port
        self.intfname_to_port = {}
        self.port_to_intfname = {}
        self.server = create_vns_server(
            port,
            self._handle_recv_msg,
            self._handle_new_client,
            self._handle_client_disconnected,
        )
        self.packethandler = packethandler
        self.start_test = lambda *args: log.critical("Unhandled start test routine")
        packethandler.send_packet = self.send_packet
        self.populate_interfaces()
        log.info("created server")
        self.started = False
        return

    def broadcast(self, message):
        log.debug("Broadcasting message: %s", message)
        for client in self.srclients:
            client.send(message)

    def populate_interfaces(self):
        info = {}
        i = 0
        for intf in [INTF1, INTF2, INTF3]:
            i += 1
            info[intf] = (
                self.config.IP_INTFS_STR[intf],
                self.config.MAC_INTFS_STR[intf],
                "1Gbps",
                i,
            )

        interfaces = []
        for intf in info.keys():
            ip, mac, rate, port = info[intf]
            interfaces.append(VNSInterface(intf, mac, ip, "255.255.255.255"))
            # Mapping between of-port and intf-name
            self.intfname_to_port[intf] = port
            self.port_to_intfname[port] = intf
        # store the list of interfaces...
        self.interfaces = interfaces

    def send_packet(self, intfname, packet):
        self.broadcast(VNSPacket(intfname, bytes(packet)))

    def _handle_recv_msg(self, conn, vns_msg):
        # demux sr-client messages and take approriate actions
        if vns_msg is None:
            log.debug("invalid message")
            self._handle_close_msg(conn)
            return

        log.debug("recv VNS msg: %s" % vns_msg)
        if vns_msg.get_type() == VNSAuthReply.get_type():
            self._handle_auth_reply(conn)
            return
        elif vns_msg.get_type() == VNSOpen.get_type():
            self._handle_open_msg(conn, vns_msg)
        elif vns_msg.get_type() == VNSClose.get_type():
            self._handle_close_msg(conn)
        elif vns_msg.get_type() == VNSPacket.get_type():
            self._handle_packet_msg(conn, vns_msg)
        elif vns_msg.get_type() == VNSOpenTemplate.get_type():
            # TODO: see if this is needed...
            self._handle_open_template_msg(conn, vns_msg)
        else:
            log.debug("unexpected VNS message received: %s" % vns_msg)

    def _handle_auth_reply(self, conn):
        # always authenticate
        msg = "authenticated %s as %s" % (conn, "user")
        conn.send(VNSAuthStatus(True, msg))

    def _handle_new_client(self, conn):
        log.debug("Accepted client at %s" % conn.transport.getPeer().host)
        self.srclients.append(conn)
        # send auth message to drive the sr-client state machine
        salt = os.urandom(20)
        conn.send(VNSAuthRequest(salt))
        return

    def _handle_client_disconnected(self, conn):
        log.info("disconnected")
        conn.transport.loseConnection()
        return

    def _handle_open_msg(self, conn, vns_msg):
        # client wants to connect to some topology.
        log.debug("open-msg: %s, %s" % (vns_msg.topology_id, vns_msg.virtual_host_id))
        try:
            conn.send(VNSHardwareInfo(self.interfaces))
        except:
            log.debug("interfaces not populated yet")

        if self.started == False:
            self.started = True
            self.start_test()
        else:
            log.info("Not starting tests for a second connection.")
            # Signal that we can start the test
            reactor.callLater(0, self.signal_test.callback, "")
        return

    def _handle_close_msg(self, conn):
        conn.send("Goodbyte!")  # spelling mistake intended...
        conn.transport.loseConnection()
        return

    def _handle_packet_msg(self, conn, vns_msg):
        out_intf = vns_msg.interface_name
        pkt = vns_msg.ethernet_frame

        try:
            out_port = self.intfname_to_port[out_intf]
        except KeyError:
            # log.debug('packet-out through wrong port number %s' % out_port)
            return
        # log.info("packet-out %s: %r" % (out_intf, pkt))
        # log.debug('SRServerHandler raise packet out event')
        # Should override this with testing code
        # core.csc458_srhandler.raiseEvent(SRPacketOut(pkt, out_port))
        self.packethandler.receive_packet(out_intf, pkt)


TestResult = namedtuple("TestResult", "name,points,maxpoints,text_desp")

"""
The main testing class.  Instantiates tests as defined above, and runs
them.
"""

class Lab1Tester:
    config = SRConfig()
    TESTS = [
        ("Public-ARP-Reply", Public_ARPReply, (INTF1, config.IP_SERVERS[0])),
        ("Public-ARP-Expiration", Public_ARPExpiration, (INTF3, config.IP_CLIENT, config.IP_SERVERS[0])),
        ("Public-ICMP-Echo", Public_ICMPEcho, (INTF1, config.IP_SERVERS[0], config.IP_INTFS[INTF1])),
        ("Public-ICMP-Forward", Public_ICMPForward, (INTF3, config.IP_CLIENT, config.IP_SERVERS[0])),
        ("Public-TCP-Forward", Public_TCPForward, (INTF3, config.IP_CLIENT, config.IP_SERVERS[1])),
    ]

    def __init__(self, sr_path, sr_log=None, once=False):
        self.sr_log = sr_log
        self.sr_path = sr_path
        self.once = once
        self.results = OrderedDict()
        if self.sr_present():
            self.results["compile"] = TestResult("compile", 1, 1, "success")
        else:
            self.results["compile"] = TestResult("compile", 0, 1, "fail")
            self.set_results_0()
            return
        self.server = SRServerListener(packethandler=self, config=self.config)
        log.debug("SRServerListener listening on %s" % self.server.listen_port)
        self.server.start_test = self.start_tests
        self.active_test = TestCase(self.config)
        time.sleep(1)
        self.start_sr(pcap="pkt_dump.pcap")

    def sr_present(self):
        return os.path.exists(self.sr_path)

    def set_results_0(self):
        runs = ["-r1", "-r2"]
        for name, T, _ in Lab1Tester.TESTS:
            for r in runs:
                tname = name + r
                self.results[tname] = TestResult(tname, 0, T.MAX_POINTS, "")

    # expose the list of tests if needed by the client. Note that
    # parse_ips() in SRConfig will be called, which means that the
    # client basically has to be in the same directory. I don't know
    # what would be the best way to do this. This will do for now.
    @staticmethod
    def get_tests():
        tests_list = OrderedDict()
        tests_list["compile"] = 1
        runs = ["-r1", "-r2"]
        for name, T, _ in Lab1Tester.TESTS:
            for r in runs:
                tests_list[name + r] = T.MAX_POINTS
        return tests_list

    def run(self):
        if not self.sr_present():
            return
        reactor.run()

    def set_active_test(self, T):
        self.active_test = T
        T.send_packet = self.send_packet
        T.info = self.info
        T.warn = self.warn
        T.err = self.err
        return

    def start_sr(self, pcap=None):
        if pcap:
            pcap = "-l " + pcap
        else:
            pcap = ""

        if self.sr_log:
            cmd = "%s %s > %s 2>&1" % (self.sr_path, pcap, self.sr_log)
        else:
            cmd = "%s %s >/dev/null 2>&1" % (self.sr_path, pcap)

        self.sr = subprocess.Popen(cmd, shell=True)

    def sr_crashed(self):
        """Returns true if the process has terminated."""
        ret = self.sr.poll() is not None
        # print "ret => ", ret
        return ret

    def restart_sr(self):
        self.server.signal_test = defer.Deferred()  # blah
        self.err("Restarting SR")
        try:
            self.sr.terminate()
            self.sr.kill()
        except:
            # probably already dead
            pass
        subprocess.Popen("killall -9 sr >/dev/null 2>&1", shell=True).wait()
        self.start_sr()
        return self.server.signal_test

    def receive_dummy(self, intfname, packet):
        self.warn("dummy receive")
        pass

    def purge(self):
        self.active_test.receive_packet = self.receive_dummy
        purge = defer.Deferred()
        reactor.callLater(PURGE_TIME, purge.callback, "")
        return purge

    @defer.deferredGenerator
    def start_tests(self):
        # How to add two results...
        def add(ar, br):
            assert ar.name == br.name
            ret = TestResult(
                ar.name,
                ar.points + br.points,
                ar.maxpoints + br.maxpoints,
                ar.text_desp + "\n" + br.text_desp if ar.text_desp else br.text_desp,
            )
            return ret

        self.phase1_c, self.phase1_m = 0, 0
        for name, T, a in self.TESTS:
            a = (self.config,) + a
            test = T(*a)
            test.name = name

            wfd = self.restart_sr()
            yield defer.waitForDeferred(wfd)
            self.set_active_test(test)
            wfd = test.start_test()
            yield defer.waitForDeferred(wfd)
            self.show("Test %s got %s points" % (test.name, test.points))
            result = TestResult(test.name, test.points, T.MAX_POINTS, test.text_desp)
            oldresult = (
                self.results[result.name]
                if result.name in self.results
                else TestResult(test.name, 0, 0, "")
            )
            self.results[result.name] = add(result, oldresult)
            self.phase1_c += result.points
            self.phase1_m += result.maxpoints

            self.info("purging...")
            wfd = self.purge()
            yield defer.waitForDeferred(wfd)

        # Done!
        reactor.stop()

    def summary(self):
        fobj = sys.stdout
        ddump = {}
        for tname in self.results.keys():
            tresult = self.results[tname]
            ddump[tname] = (tresult.points, tresult.maxpoints, tresult.text_desp)
        # sending the pcap through stdout
        # ddump["pcap"] = ""
        # if os.path.isfile("pkt_dump.pcap"):
        #     with open("pkt_dump.pcap", "rb") as f:
        #         ddump["pcap"] = b64encode(f.read()).decode("utf-8")
        print(json.dumps(ddump), file=fobj)

    # Packet handler should have send_packet and receive_packet routines
    def send_packet(self, intfname, packet):
        self.err("send_packet should have been overridden")
        raise NotImplemented

    def handle_arp_request(self, intfname, pkt):
        self.info("Handling ARP request on %s" % (intfname))
        arp = pkt.data
        if arp.tpa not in self.config.ARP_CACHE:
            self.info("ARP request not for me")
            return
        mac = self.config.ARP_CACHE[arp.tpa]
        resp = dpkt.ethernet.Ethernet(
            src=mac, dst=pkt.src, type=dpkt.ethernet.ETH_TYPE_ARP
        )
        resp.data = dpkt.arp.ARP(
            op=dpkt.arp.ARP_OP_REPLY, sha=mac, spa=arp.tpa, tha=arp.sha, tpa=arp.spa
        )
        self.send_packet(intfname, resp)

    def receive_packet(self, intfname, packet):
        if not self.validate_packet(intfname, packet):
            self.info("could not validate")
            self.active_test.update_text_desp("invalid packet received", 0.1)
            return

        pkt = dpkt.ethernet.Ethernet(packet)

        if pkt.type == dpkt.ethernet.ETH_TYPE_ARP:
            arp = pkt.data
            if arp.op == dpkt.arp.ARP_OP_REQUEST:
                self.handle_arp_request(intfname, pkt)
            if self.active_test.ignoreARP:
                return

        self.info("Passing packet to test receive function")
        self.active_test.receive_packet(intfname, packet)

    def validate_packet(self, intfname, packet):
        pkt = dpkt.ethernet.Ethernet(packet)
        self.info("validate packet")
        if len(pkt) != len(packet):
            self.active_test.update_text_desp("invalid packet (wrong length)", 0.2)
            return False
        if pkt.type == dpkt.ethernet.ETH_TYPE_ARP:
            return self.validate_arp(intfname, pkt)
        if pkt.type == dpkt.ethernet.ETH_TYPE_IP:
            ret = self.validate_ip(intfname, pkt)
            if not ret:
                return False
            # at this point we know that pkt is a valid IP packet
            if pkt.data.p == 1:
                ip_packet = packet[pkt.__hdr_len__ :]
                return self.validate_icmp(ip_packet)
            return True
        return False

    def validate_arp(self, intfname, pkt):
        self.info("validate arp")
        arp = pkt.data
        if arp.hrd != dpkt.arp.ARP_HRD_ETH:
            self.warn("ARP packet not for Ethernet")
            return False

        if arp.pro != dpkt.arp.ARP_PRO_IP:
            self.warn("ARP packet not for IP")
            return False

        if arp.hln != 6 or arp.pln != 4:
            self.warn("HLN and PLN don't match")
            return False

        if arp.op != dpkt.arp.ARP_OP_REQUEST and arp.op != dpkt.arp.ARP_OP_REPLY:
            self.warn("wrong op code")
            return False

        return True

    def validate_ip(self, intfname, pkt):
        self.info("validate IP")
        ip = pkt.data
        if type(ip) == str:
            self.warn("malformed IP packet")
            return False

        # checksum ?
        cksum = ip.sum
        ip.sum = 0
        if dpkt.in_cksum(ip.pack_hdr() + ip.opts) != cksum:
            self.warn("Invalid IP checksum")
            return False
        ip.sum = cksum

        if ip.p != 1 and ip.p != 6 and ip.p != 17:
            self.err("Invalid IP protocol %d" % ip.p)
            return False

        return True

    def validate_icmp(self, ip_packet):
        ip = dpkt.ip.IP(ip_packet)
        self.info("validate ICMP")
        icmp = ip.data
        if type(icmp) == str:
            return False

        icmp_packet = ip_packet[ip.__hdr_len__ :]
        if checksum(icmp_packet) != 0:
            self.warn("Invalid ICMP checksum")
            self.active_test.update_text_desp("invalid packet (wrong ICMP cksum)", 0.3)
            return False

        return True

    # Handle ARP for all types of addresses
    def handle_arp(self, intfname, pkt):
        arp = pkt.data
        if arp.hrd != dpkt.arp.ARP_HRD_ETH:
            self.warn("ARP packet not for Ethernet")
            return

        if arp.pro != dpkt.arp.ARP_PRO_IP:
            self.warn("ARP packet not for IP")
            return

        if arp.hln != 6 and arp.pln != 4:
            self.warn("HLN and PLN don't match")
            return

        if arp.op == dpkt.arp.ARP_OP_REQUEST:
            self.info("Handling ARP request on %s" % (intfname))
            mac = self.config.ARP_CACHE[arp.tpa]
            resp = dpkt.ethernet.Ethernet(
                src=mac, dst=pkt.src, type=dpkt.ethernet.ETH_TYPE_ARP
            )
            resp.data = dpkt.arp.ARP(
                op=dpkt.arp.ARP_OP_REPLY, sha=mac, spa=arp.tpa, tha=arp.sha, tpa=arp.spa
            )
            self.send_packet(intfname, resp)

        return

    # Simple logging
    def info(self, str):
        log.info(T.colored(str, "green"))

    def warn(self, str):
        log.warning(T.colored(str, "yellow"))

    def err(self, str):
        log.error(T.colored(str, "red", attrs=["bold"]))

    def show(self, str):
        log.info(T.colored(str, "magenta"))
