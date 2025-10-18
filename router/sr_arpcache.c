#include "sr_arpcache.h"

#include <netinet/in.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_router.h"
#include "sr_utils.h"

/* =========================  ARP SWEEP (per spec)  ========================= */

void build_and_send_arp_request(struct sr_instance *sr,
                                       struct sr_if *out_if,
                                       uint32_t target_ip_nbo) {
  if (!out_if) return;

  unsigned len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  uint8_t *buf = (uint8_t *)malloc(len);
  if (!buf) return;

  sr_ethernet_hdr_t *eth = (sr_ethernet_hdr_t *)buf;
  sr_arp_hdr_t *arp     = (sr_arp_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t));

  /* Ethernet: broadcast */
  memset(eth->ether_dhost, 0xff, ETHER_ADDR_LEN);
  memcpy(eth->ether_shost, out_if->addr, ETHER_ADDR_LEN);
  eth->ether_type = htons(ethertype_arp);

  /* ARP request */
  arp->ar_hrd = htons(arp_hrd_ethernet);
  arp->ar_pro = htons(ethertype_ip);
  arp->ar_hln = ETHER_ADDR_LEN;
  arp->ar_pln = 4;
  arp->ar_op  = htons(arp_op_request);
  memcpy(arp->ar_sha, out_if->addr, ETHER_ADDR_LEN);
  arp->ar_sip = out_if->ip;        /* network order */
  memset(arp->ar_tha, 0x00, ETHER_ADDR_LEN);
  arp->ar_tip = target_ip_nbo;     /* network order */

  sr_send_packet(sr, buf, len, out_if->name);
  free(buf);
}

/* Build + send ICMP Type 3 Code 1 (Host Unreachable) replying to one waiting pkt */
void send_icmp_host_unreach_for_pkt(struct sr_instance *sr,
                                           const struct sr_packet *waiting_pkt) {
  if (!waiting_pkt || !waiting_pkt->buf) return;
  const uint8_t *rx = waiting_pkt->buf;
  unsigned rxlen = waiting_pkt->len;

  if (rxlen < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) return;

  const sr_ip_hdr_t *rx_ip =
      (const sr_ip_hdr_t *)(rx + sizeof(sr_ethernet_hdr_t));
  uint32_t dst_ip = rx_ip->ip_src;  /* send error back to original source */

  /* Pick an egress interface. Per spec we can reply from the interface we tried to use. */
  struct sr_if *out_if = sr_get_interface(sr, waiting_pkt->iface);
  if (!out_if) out_if = sr->if_list; /* fallback */

  /* Compose Ethernet + IP + ICMP T3(3,1) with 28B offending bytes */
  unsigned icmp_len = sizeof(sr_icmp_t3_hdr_t);
  unsigned ip_len   = sizeof(sr_ip_hdr_t) + icmp_len;
  unsigned total    = sizeof(sr_ethernet_hdr_t) + ip_len;

  uint8_t *buf = (uint8_t *)malloc(total);
  if (!buf) return;

  sr_ethernet_hdr_t *eth = (sr_ethernet_hdr_t *)buf;
  sr_ip_hdr_t       *ip  = (sr_ip_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t));
  sr_icmp_t3_hdr_t  *icmp= (sr_icmp_t3_hdr_t *)((uint8_t *)ip + sizeof(sr_ip_hdr_t));

  /* Fill L2 source now; L2 dest after ARP lookup below */
  memcpy(eth->ether_shost, out_if->addr, ETHER_ADDR_LEN);
  eth->ether_type = htons(ethertype_ip);

  /* IPv4 header */
  ip->ip_v   = 4;
  ip->ip_hl  = 5;
  ip->ip_tos = 0;
  ip->ip_len = htons(ip_len);
  ip->ip_id  = 0;
  ip->ip_off = 0;
  ip->ip_ttl = 64;
  ip->ip_p   = ip_protocol_icmp;
  ip->ip_src = out_if->ip;
  ip->ip_dst = dst_ip;   /* back to original sender */
  ip->ip_sum = 0;

  /* ICMP Type 3 Code 1 with 28 bytes of offending header+8 */
  memset(icmp, 0, sizeof(*icmp));
  icmp->icmp_type = 3;
  icmp->icmp_code = 1;
  unsigned copy_bytes = sizeof(sr_ip_hdr_t) + 8;
  if (rxlen < sizeof(sr_ethernet_hdr_t) + copy_bytes)
    copy_bytes = rxlen - sizeof(sr_ethernet_hdr_t);
  if (copy_bytes > ICMP_DATA_SIZE)
    copy_bytes = ICMP_DATA_SIZE;
  memcpy(icmp->data, rx + sizeof(sr_ethernet_hdr_t), copy_bytes);

  /* Checksums */
  ip->ip_sum    = cksum(ip, sizeof(sr_ip_hdr_t));
  icmp->icmp_sum= cksum(icmp, sizeof(sr_icmp_t3_hdr_t));

  /* Get next-hop IP for this reply: if the out_if has a gateway route, use it
     but since we’re replying to a host on the same path we attempted earlier,
     we can ARP for dst_ip directly (simple and spec-compliant). */
  uint32_t next_hop_ip = dst_ip;

  /* ARP for L2 dest (reply path) */
  struct sr_arpentry *entry = sr_arpcache_lookup(&sr->cache, next_hop_ip);
  if (entry) {
    memcpy(eth->ether_dhost, entry->mac, ETHER_ADDR_LEN);
    sr_send_packet(sr, buf, total, out_if->name);
    free(entry);
    free(buf);
  } else {
    /* Queue this ICMP for ARP resolution to the original source */
    sr_arpcache_queuereq(&sr->cache, next_hop_ip, buf, total, out_if->name);
    free(buf); /* queuereq copies */
  }
}

void handle_arpreq(struct sr_instance *sr, struct sr_arpreq *req) {
  time_t now = time(NULL);

  if (difftime(now, req->sent) > 1.0) {
    if (req->times_sent >= 5) {
      /* Send ICMP host unreachable to source addr of ALL pkts waiting on this req */
      struct sr_packet *p;
      for (p = req->packets; p; p = p->next) {
        send_icmp_host_unreach_for_pkt(sr, p);
      }
      /* Destroy request (also frees its packet list) */
      sr_arpreq_destroy(&sr->cache, req);
    } else {
      /* Send ARP request out the interface we intended for these packets */
      struct sr_if *out_if = NULL;
      if (req->packets && req->packets->iface) {
        out_if = sr_get_interface(sr, req->packets->iface);
      }
      if (!out_if) out_if = sr->if_list;  /* safe fallback */

      build_and_send_arp_request(sr, out_if, req->ip);
      req->sent = now;
      req->times_sent++;
    }
  }
}

/*
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr) {
  struct sr_arpreq *req = sr->cache.requests;
  while (req) {
    /* Save next BEFORE handling (it may destroy the current request) */
    struct sr_arpreq *next = req->next;
    handle_arpreq(sr, req);
    req = next;
  }
 }

/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
  pthread_mutex_lock(&(cache->lock));

  struct sr_arpentry *entry = NULL, *copy = NULL;

  int i;
  for (i = 0; i < SR_ARPCACHE_SZ; i++) {
    if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
      entry = &(cache->entries[i]);
    }
  }

  /* Must return a copy b/c another thread could jump in and modify
     table after we return. */
  if (entry) {
    copy = (struct sr_arpentry *)malloc(sizeof(struct sr_arpentry));
    memcpy(copy, entry, sizeof(struct sr_arpentry));
  }

  pthread_mutex_unlock(&(cache->lock));

  return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.

   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache, uint32_t ip,
                                       uint8_t *packet, /* borrowed */
                                       unsigned int packet_len, char *iface) {
  pthread_mutex_lock(&(cache->lock));

  struct sr_arpreq *req;
  for (req = cache->requests; req != NULL; req = req->next) {
    if (req->ip == ip) {
      break;
    }
  }

  /* If the IP wasn't found, add it */
  if (!req) {
    req = (struct sr_arpreq *)calloc(1, sizeof(struct sr_arpreq));
    req->ip = ip;
    req->next = cache->requests;
    cache->requests = req;
  }

  /* Add the packet to the list of packets for this request */
  if (packet && packet_len && iface) {
    struct sr_packet *new_pkt =
        (struct sr_packet *)malloc(sizeof(struct sr_packet));

    new_pkt->buf = (uint8_t *)malloc(packet_len);
    memcpy(new_pkt->buf, packet, packet_len);
    new_pkt->len = packet_len;
    new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
    strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
    new_pkt->next = req->packets;
    req->packets = new_pkt;
  }

  pthread_mutex_unlock(&(cache->lock));

  return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac, uint32_t ip) {
  pthread_mutex_lock(&(cache->lock));

  struct sr_arpreq *req, *prev = NULL, *next = NULL;
  for (req = cache->requests; req != NULL; req = req->next) {
    if (req->ip == ip) {
      if (prev) {
        next = req->next;
        prev->next = next;
      } else {
        next = req->next;
        cache->requests = next;
      }

      break;
    }
    prev = req;
  }

  int i;
  for (i = 0; i < SR_ARPCACHE_SZ; i++) {
    if (!(cache->entries[i].valid))
      break;
  }

  if (i != SR_ARPCACHE_SZ) {
    memcpy(cache->entries[i].mac, mac, 6);
    cache->entries[i].ip = ip;
    cache->entries[i].added = time(NULL);
    cache->entries[i].valid = 1;
  }

  pthread_mutex_unlock(&(cache->lock));

  return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
  pthread_mutex_lock(&(cache->lock));

  if (entry) {
    struct sr_arpreq *req, *prev = NULL, *next = NULL;
    for (req = cache->requests; req != NULL; req = req->next) {
      if (req == entry) {
        if (prev) {
          next = req->next;
          prev->next = next;
        } else {
          next = req->next;
          cache->requests = next;
        }

        break;
      }
      prev = req;
    }

    struct sr_packet *pkt, *nxt;

    for (pkt = entry->packets; pkt; pkt = nxt) {
      nxt = pkt->next;
      if (pkt->buf)
        free(pkt->buf);
      if (pkt->iface)
        free(pkt->iface);
      free(pkt);
    }

    free(entry);
  }

  pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
  fprintf(stderr,
          "\nMAC            IP         ADDED                      VALID\n");
  fprintf(stderr,
          "-----------------------------------------------------------\n");

  int i;
  for (i = 0; i < SR_ARPCACHE_SZ; i++) {
    struct sr_arpentry *cur = &(cache->entries[i]);
    unsigned char *mac = cur->mac;
    fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0],
            mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip),
            ctime(&(cur->added)), cur->valid);
  }

  fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {
  /* Seed RNG to kick out a random entry if all entries full. */
  srand(time(NULL));

  /* Invalidate all entries */
  memset(cache->entries, 0, sizeof(cache->entries));
  cache->requests = NULL;

  /* Acquire mutex lock */
  pthread_mutexattr_init(&(cache->attr));
  pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
  int success = pthread_mutex_init(&(cache->lock), &(cache->attr));

  return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
  return pthread_mutex_destroy(&(cache->lock)) &&
         pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were
   added more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
  struct sr_instance *sr = sr_ptr;
  struct sr_arpcache *cache = &(sr->cache);

  while (1) {
    sleep(1.0);

    pthread_mutex_lock(&(cache->lock));

    time_t curtime = time(NULL);

    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
      if ((cache->entries[i].valid) &&
          (difftime(curtime, cache->entries[i].added) > SR_ARPCACHE_TO)) {
        cache->entries[i].valid = 0;
      }
    }

    sr_arpcache_sweepreqs(sr);

    pthread_mutex_unlock(&(cache->lock));
  }

  return NULL;
}
