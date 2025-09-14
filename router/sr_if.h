#ifndef sr_INTERFACE_H
#define sr_INTERFACE_H

#include "sr_protocol.h"
#include <stdint.h>

struct sr_instance;

/* ----------------------------------------------------------------------------
 * struct sr_if
 *
 * Node in the interface list for each router
 *
 * --------------------------------------------------------------------------
 */

struct sr_if {
  char name[sr_IFACE_NAMELEN];
  unsigned char addr[ETHER_ADDR_LEN];
  uint32_t ip;
  uint32_t speed;
  struct sr_if *next;
};

struct sr_if *sr_get_interface(struct sr_instance *sr, const char *name);
void sr_add_interface(struct sr_instance *, const char *);
void sr_set_ether_addr(struct sr_instance *, const unsigned char *);
void sr_set_ether_ip(struct sr_instance *, uint32_t ip_nbo);
void sr_print_if_list(struct sr_instance *);
void sr_print_if(struct sr_if *);

#endif /* --  sr_INTERFACE_H -- */
