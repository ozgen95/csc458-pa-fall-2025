#include "sr_router.h"

#include <assert.h>
#include <stdio.h>

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
  if (!iface) return; // if packet came to the wrong interface ignore  

  if (len < sizeof(sr_ethernet_hdr_t)) return; // if length of the packet is less than ethernet header size it's not a valid ethernet frame so discard
  
  sr_ethernet_hdr_t *eth = (sr_ethernet_hdr_t *)packet; 

  uint16_t ethtype = ntohs(eth->ether_type); 

  // handle arp
  if(ethtype = ethertype_arp_t){
    if (len < sizeof(sr_arp_hdr_t) + sizeof(sr_ethernet_hdr_t)) return; 

    sr_arp_hdr_t * arp = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    
    if (ntohs(arp->ar_op) == arp_op_request) { // handle arp request 
      // check interfaces of the router and see if any of them matches 
      handle_arp_request(sr, eth, arp, interface);
    }
    else if (ntohs(arp->ar_op) == arp_op_reply) { // handle arp reply  

    }
    else {
      fprintf("Invalid arp operation code"); 
      return; 
    } 
      
  }
  // handle ip 
  else if (ethtype = ethertype_ip){
    if (len < sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t)) return;
  }



} /* end sr_ForwardPacket */

// handle arp request 

void handle_arp_request(struct sr_instance *sr, sr_ethernet_hdr_t *eth, sr_arp_hdr_t *arp, char *interface_name) {
  // check if arp request's ip matches any of the interfaces of the router
  struct sr_if * owner; 
  for (struct sr_if * iface = sr->if_list; iface != NULL; iface = iface->next){
    if (iface->ip == arp->ar_tip){
      owner = iface;
      break; 
    }
  }
  if (!owner) fprintf("No matching router has no interface matching arp request's IP"); 


}

