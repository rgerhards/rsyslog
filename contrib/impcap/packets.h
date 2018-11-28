#include "config.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdarg.h>
#include <ctype.h>
#include <pcap.h>

#include "rsyslog.h"
#include "msg.h"
#include "dirty.h"

#ifdef __FreeBSD__
  #include <sys/socket.h>
#endif

#ifndef __FreeBSD__
  #include <netinet/ether.h>
#endif

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>  /* arp structure */
#include <arpa/inet.h>   /* IP address extraction */

#ifndef INCLUDED_PACKETS_H
#define INCLUDED_PACKETS_H 1
typedef struct ether_header    eth_header_t;
typedef struct ip              ipv4_header_t;
typedef struct ether_arp       arp_header_t;
typedef struct ip6_hdr        ipv6_header_t;
#define ip6_addr_sub16 __in6_u.__u6_addr16

/* --- prototypes --- */
void handle_packet(uchar *arg, const struct pcap_pkthdr *pkthdr, const uchar *packet);
void handle_eth_header(const uchar *packet, size_t pktSize, struct json_object *jparent);
void handle_ipv4_header(const uchar *packet, size_t pktSize, struct json_object *jparent);
void handle_icmp_header(const uchar *packet, size_t pktSize, struct json_object *jparent);
void handle_ipv6_header(const uchar *packet, size_t pktSize, struct json_object *jparent);
void handle_arp_header(const uchar *packet, size_t pktSize, struct json_object *jparent);

#endif
