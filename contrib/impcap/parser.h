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
#else
  #include <netinet/ether.h>
#endif

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
// #include <netinet/if_ether.h>  /* arp structure */
#include <arpa/inet.h>   /* IP address extraction */

#ifndef INCLUDED_PARSER_H
#define INCLUDED_PARSER_H 1

#define IP_PROTO_NUM 256
#define ETH_PROTO_NUM 0x9000  /* initializing 36000+ values for just 11... there MUST be a better way... */

void (*ipProtoHandlers[IP_PROTO_NUM]) (const uchar *packet, size_t pktSize, struct json_object *jparent);
void (*ethProtoHandlers[ETH_PROTO_NUM]) (const uchar *packet, size_t pktSize, struct json_object *jparent);

/* --- handlers prototypes --- */
void packet_parse(uchar *arg, const struct pcap_pkthdr *pkthdr, const uchar *packet);
void eth_parse(const uchar *packet, size_t pktSize, struct json_object *jparent);
void llc_parse(const uchar *packet, size_t pktSize, struct json_object *jparent);
void ipx_parse(const uchar *packet, size_t pktSize, struct json_object *jparent);
void ipv4_parse(const uchar *packet, size_t pktSize, struct json_object *jparent);
void icmp_parse(const uchar *packet, size_t pktSize, struct json_object *jparent);
void tcp_parse(const uchar *packet, size_t pktSize, struct json_object *jparent);
void udp_parse(const uchar *packet, size_t pktSize, struct json_object *jparent);
void ipv6_parse(const uchar *packet, size_t pktSize, struct json_object *jparent);
void arp_parse(const uchar *packet, size_t pktSize, struct json_object *jparent);
void rarp_parse(const uchar *packet, size_t pktSize, struct json_object *jparent);
void dont_parse(const uchar *packet, size_t pktSize, struct json_object *jparent);
void ah_parse(const uchar *packet,size_t pktSize, struct json_object *jparent);
void esp_parse(const uchar *packet,size_t pktSize, struct json_object *jparent);

#endif /* INCLUDED_PARSER_H */
