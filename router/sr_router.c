#include "sr_router.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "sr_arpcache.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_rt.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance *sr) {
  /* REQUIRES */
  assert(sr);

  /* Initialize cache and cache cleanup thread */
  sr_arpcache_init(&(sr->cache));

  pthread_attr_init(&(sr->attr));
  pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
  pthread_t thread;

  pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

  /* Add initialization code here! */ 
  


} /* -- sr_init -- */

/* someone else asks for the MAC address of one of the router's interfaces  */
void received_arp_request(struct sr_instance *sr, sr_ethernet_hdr_t *eth, sr_arp_hdr_t *arp, char *interface_name) {
  /* check if arp request's ip matches any of the interfaces of the router */
  struct sr_if * owner; 
  struct sr_if * iface; 
  for (iface = sr->if_list; iface != NULL; iface = iface->next){
    if (iface->ip == arp->ar_tip){
      owner = iface;
      break; 
    }
  }

  if (!owner) { 
    printf("Router has no interface matching arp request's IP");
    return;
  } 
  /* we found a matching interface */
  int reply_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  uint8_t *buf = (uint8_t *)malloc(reply_len);
  if (!buf) return;

  sr_ethernet_hdr_t *n_eth = (sr_ethernet_hdr_t *)buf; /* create new eth hdr */ 
  sr_arp_hdr_t * n_arp = (sr_arp_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t)); /* create new arp hdr */

  /* in the new ethernet packet, sender is the owner of the interface that received the request
  destination is the host who requested the arp */
  memcpy(n_eth->ether_shost, owner->addr, ETHER_ADDR_LEN);
  memcpy(n_eth->ether_dhost, eth->ether_shost, ETHER_ADDR_LEN);
  
  n_eth->ether_type = htons(ethertype_arp);

  /* Set new arp for the reply */
  n_arp->ar_hrd = htons(arp_hrd_ethernet);  /* format of hardware address   */
  n_arp->ar_pro = htons(ethertype_ip); /* format of protocol address   */
  n_arp->ar_hln = ETHER_ADDR_LEN; /* length of hardware address   */
  n_arp->ar_pln = 4; /* length of protocol address   */
  n_arp->ar_op  = htons(arp_op_reply); /* ARP reply opcode */

  memcpy(n_arp->ar_sha, owner->addr, ETHER_ADDR_LEN); /* owner's hardware address is set as the sender */
  n_arp->ar_sip = owner->ip;                 
  memcpy(n_arp->ar_tha, arp->ar_sha, ETHER_ADDR_LEN); /* target hardware adress is the sender's hardware address */
  n_arp->ar_tip = arp->ar_sip; /* target ip is set as the original sender's ip */

  sr_send_packet(sr, buf, reply_len, interface_name);
  free(buf); 


}

/* Longest Prefix Match */
const struct sr_rt * lpm(struct sr_instance *sr, uint32_t ip_dst) {
  
  uint32_t best_mask = 0;
  const struct sr_rt *best_match = NULL;
  const struct sr_rt * rt;
  for (rt = sr->routing_table; rt; rt = rt->next) {
    if ((ip_dst & rt->mask.s_addr) == (rt->dest.s_addr)) {
      if (ntohl(rt->mask.s_addr) >= ntohl(best_mask)) {
        best_mask = rt->mask.s_addr;
        best_match = rt; 
      }
    }
  }
  return best_match;
}

/* send ICMP error type 3 */
void send_icmp_t3(struct sr_instance *sr, const uint8_t *packet,
                         unsigned len, uint8_t type, uint8_t code,
                         const char *interface) {

  const sr_ethernet_hdr_t * n_eth = (const sr_ethernet_hdr_t*)packet;
  const sr_ip_hdr_t * n_ip = (const sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

  /* get the interface from which we will send icmp from */
  struct sr_if *out_if = sr_get_interface(sr, interface);
  if (!out_if) return;

  unsigned icmp_payload_len = sizeof(sr_icmp_t3_hdr_t);
  unsigned ip_len = sizeof(sr_ip_hdr_t) + icmp_payload_len;
  unsigned total = sizeof(sr_ethernet_hdr_t) + ip_len;

  uint8_t *buf = (uint8_t*)malloc(total);
  if (!buf) return;

  sr_ethernet_hdr_t *eth = (sr_ethernet_hdr_t*)buf;
  sr_ip_hdr_t *ip = (sr_ip_hdr_t*)(buf + sizeof(sr_ethernet_hdr_t));
  sr_icmp_t3_hdr_t *icmp = (sr_icmp_t3_hdr_t*)((uint8_t*)ip + sizeof(sr_ip_hdr_t));

  /* Ethernet setup */
  memcpy(eth->ether_shost, out_if->addr, ETHER_ADDR_LEN);
  memcpy(eth->ether_dhost, n_eth->ether_shost, ETHER_ADDR_LEN);
  eth->ether_type = htons(ethertype_ip);

  /* IP header */
   
  ip->ip_hl = 5; /* header length */
  ip->ip_v = 4; /* version */
  ip->ip_tos = 0; /* type of service */
  ip->ip_len = htons(ip_len); /* total length */
  ip->ip_id  = 0; /* identification */
  ip->ip_off = 0; /* fragment offset field */
  ip->ip_ttl = 64; /* time to live */
  ip->ip_p = ip_protocol_icmp; /* protocol */
  ip->ip_dst = n_ip->ip_src; /* source address */
  ip->ip_src = out_if->ip; /*destination address*/
  ip->ip_sum = 0;
  ip->ip_sum = cksum(ip, sizeof(sr_ip_hdr_t)); /* checksum */

  /* ICMP */
  memset(icmp, 0, sizeof(*icmp));
  icmp->icmp_type = type;
  icmp->icmp_code = code;

  unsigned copy = sizeof(sr_ip_hdr_t) + 8;
  if (len < sizeof(sr_ethernet_hdr_t) + copy){
    copy = len - sizeof(sr_ethernet_hdr_t);
  } 
  if (copy > ICMP_DATA_SIZE){
    copy = ICMP_DATA_SIZE;
  } 
  memcpy(icmp->data, packet + sizeof(sr_ethernet_hdr_t), copy);

  /* ICMP checksum */
  icmp->icmp_sum = 0;
  icmp->icmp_sum = cksum(icmp, sizeof(sr_icmp_t3_hdr_t));

  sr_send_packet(sr, buf, total, out_if->name);
  free(buf);
}

/* ICMP Echo reply */
void send_icmp_echo_reply(struct sr_instance *sr, const uint8_t *packet,
                                 unsigned len, const char *interface) {
  if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t))
    return;

  const sr_ethernet_hdr_t * n_eth = (const sr_ethernet_hdr_t*)packet;
  const sr_ip_hdr_t * n_ip = (const sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
  const sr_icmp_hdr_t * n_icmp = (const sr_icmp_hdr_t*)((const uint8_t*) n_ip + sizeof(sr_ip_hdr_t));

  struct sr_if *out_if = sr_get_interface(sr, interface);
  if (!out_if) return;

  unsigned icmp_len = ntohs(n_ip->ip_len) - sizeof(sr_ip_hdr_t);
  unsigned ip_len = sizeof(sr_ip_hdr_t) + icmp_len;
  unsigned total = sizeof(sr_ethernet_hdr_t) + ip_len;

  uint8_t *buf = (uint8_t*)malloc(total);
  if (!buf) return;

  sr_ethernet_hdr_t *eth = (sr_ethernet_hdr_t*)buf;
  sr_ip_hdr_t *ip = (sr_ip_hdr_t*)(buf + sizeof(sr_ethernet_hdr_t));
  sr_icmp_hdr_t *icmp = (sr_icmp_hdr_t*)((uint8_t*)ip + sizeof(sr_ip_hdr_t));

  /* Ethernet */
  memcpy(eth->ether_shost, out_if->addr, ETHER_ADDR_LEN);
  memcpy(eth->ether_dhost, n_eth->ether_shost, ETHER_ADDR_LEN);
  eth->ether_type = htons(ethertype_ip);

  /* IP */
  memcpy(ip, n_ip, sizeof(sr_ip_hdr_t));
  ip->ip_dst = n_ip->ip_src;  /* send back to whoever pinged */
  ip->ip_src = out_if->ip;
  ip->ip_ttl = 64;
  ip->ip_sum = 0;
  ip->ip_sum = cksum(ip, sizeof(sr_ip_hdr_t));

  /* ICMP */
  memcpy(icmp, n_icmp, icmp_len);
  icmp->icmp_code = 0;
  icmp->icmp_type = 0;  
  icmp->icmp_sum = 0;
  icmp->icmp_sum = cksum(icmp, icmp_len);

  sr_send_packet(sr, buf, total, out_if->name);
  free(buf);
}

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance *sr, uint8_t *packet /* lent */,
                     unsigned int len, char *interface /* lent */) {
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n", len);

  /* fill in code here */

  struct sr_if *iface = sr_get_interface(sr, interface);
  /* if packet came to the wrong interface ignore  */
  if (!iface) return; 

  /* if length of the packet is less than ethernet header size it's not a valid ethernet frame so discard */
  if (len < sizeof(sr_ethernet_hdr_t)) return; 
  
  sr_ethernet_hdr_t *eth = (sr_ethernet_hdr_t *)packet; 

  uint16_t ethtype = ntohs(eth->ether_type); 

  /* ethernet packet of type arp */ 
  if(ethtype == ethertype_arp){
    if (len < sizeof(sr_arp_hdr_t) + sizeof(sr_ethernet_hdr_t)) return; 

    sr_arp_hdr_t * arp = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    
    /* received arp request (someone else is asking our mac) */
    if (ntohs(arp->ar_op) == arp_op_request) { 
      /*check interfaces of the router and see if any of them matches */
      received_arp_request(sr, eth, arp, interface); 
    }
    /* someone else let us know their IP address */
    else if (ntohs(arp->ar_op) == arp_op_reply) { 
      struct sr_arpreq * arpreq = sr_arpcache_insert(&sr->cache, arp->ar_sha, arp->ar_sip); 
      /* there are waiting packets for the MAC adress that came to the router so send them */
      if (arpreq != NULL) {
        struct sr_packet *pkt = arpreq->packets;
        while (pkt) {
          sr_ethernet_hdr_t *feth = (sr_ethernet_hdr_t *)pkt->buf;
          struct sr_if *out_if = sr_get_interface(sr, pkt->iface);
          if (out_if != NULL) {
            memcpy(feth->ether_shost, out_if->addr, ETHER_ADDR_LEN);
            memcpy(feth->ether_dhost, arp->ar_sha, ETHER_ADDR_LEN);
            sr_send_packet(sr, pkt->buf, pkt->len, out_if->name);
          }
          pkt = pkt->next;
        }
        /* destroy this request since all the packets waiting for this MAC has been sent */
        sr_arpreq_destroy(&sr->cache, arpreq);
      }
      return;
    }

  }
      
  /* ethernet packet of type ip has arrived to the router*/
  else if (ethtype == ethertype_ip){
    
    if (len < sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t)) return; 
    sr_ip_hdr_t * ip = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

    /* check if the sent ip packet has the right version and has at least 20 bytes header  */
    if (ip->ip_v != 4 || ip->ip_hl < 5) return; 
    uint16_t iphdr_len = ip->ip_hl * 4;
    if (len < sizeof(sr_ethernet_hdr_t) + iphdr_len) return; 
    
    /* verify checksum (??) */
    uint16_t old_sum = ip->ip_sum; 
    ip->ip_sum = 0;
    uint16_t result = cksum(ip, iphdr_len);
    if (old_sum != result) return; 
    
    /* Check if packet is for the router*/
    struct sr_if *it;
    int pkt_for_rt = 0; 
    for (it = sr->if_list; it; it = it->next) {
      if (it->ip == ip->ip_dst) {
        pkt_for_rt = 1;
      }
    }
    if (pkt_for_rt) {
      /* check if we have received an icmp message*/
      if (ip->ip_p == ip_protocol_icmp) {

        if (len >= sizeof(sr_ethernet_hdr_t) + iphdr_len + sizeof(sr_icmp_hdr_t)) {

          sr_icmp_hdr_t *icmp = (sr_icmp_hdr_t*)((uint8_t*)ip + iphdr_len);
          
          /* check if we have received an echo request (ping) */
          if (icmp->icmp_code == 0 && icmp->icmp_type == 8) {

            send_icmp_echo_reply(sr, packet, len, interface); 
            return;
          }
        }
      /* we don't care about other types of ICMPs lol*/
      return;
    } else {
      /* we received a protocol other than icmp we don't care about them so send ICMP port unreachable */
      send_icmp_t3(sr, packet, len, 3, 3, interface);
      return;
    }
  }

  /* Packet is not for us, need to forward */
  if (ip->ip_ttl <= 1) {
    /* Packet has been around for too long, send time exceeded icmp */
    send_icmp_t3(sr, packet, len, 11, 0, interface);
    return;
  }

  /* Decrease TTL, recompute cksum */
  ip->ip_ttl -= 1;
  ip->ip_sum = 0;
  ip->ip_sum = cksum(ip, iphdr_len);

  /* Longest prefix match with router's interfaces' IPs */
  const struct sr_rt *rt = lpm(sr, ip->ip_dst);
  if (!rt) {
    /* No match was found send icmp destination net unreachable */
    send_icmp_t3(sr, packet, len, 3, 0, interface);
    return;
  }

  uint32_t next_hop;
  /* Next-hop IP is gateway if set otherwise final destination */
  if (rt->gw.s_addr != 0) {
    next_hop = rt->gw.s_addr;
  } else {
    next_hop = ip->ip_dst;
  }

  struct sr_if *out_if = sr_get_interface(sr, rt->interface);

  /* Check if there's an entry containing the MAC adress of the next hop ip in the cache */
  struct sr_arpentry *entry = sr_arpcache_lookup(&sr->cache, next_hop);
  if (entry) {
    memcpy(eth->ether_dhost, entry->mac, ETHER_ADDR_LEN);
    memcpy(eth->ether_shost, out_if->addr, ETHER_ADDR_LEN);
    sr_send_packet(sr, packet, len, out_if->name);
    free(entry);
    return;
  } else {
    struct sr_arpreq* req = sr_arpcache_queuereq(&sr->cache, next_hop, packet, len, out_if->name);
    /* broadcast arp req */
    handle_arpreq(sr, req);
    return;
    }
  }


} /* end sr_ForwardPacket */