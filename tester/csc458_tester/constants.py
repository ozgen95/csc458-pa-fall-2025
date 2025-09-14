from csc458_tester.utils import pack_ip, pack_mac


# An ICMP error message (type 3 / type 11) must inlclude the IP header
# + 64 bits of data from the original packet. But sometimes the TTL
# has already been decreased... If this flag is set to True, we still
# count the ICMP packet has valid.
ICMP_ERROR_BE_NICE = True

# time in seconds to wait between tests
PURGE_TIME = 0.3

TTL_INIT = 64

INTF1 = "eth1"
INTF2 = "eth2"
INTF3 = "eth3"

IP_BROAD_STR = "255.255.255.255"
MAC_BROAD_STR = "ff:ff:ff:ff:ff:ff"

IP_BROAD = pack_ip(IP_BROAD_STR)
MAC_BROAD = pack_mac(MAC_BROAD_STR)
