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

char* (*ipProtoHandlers[IP_PROTO_NUM]) (const uchar *packet, int pktSize, struct json_object *jparent);
char* (*ethProtoHandlers[ETH_PROTO_NUM]) (const uchar *packet, int pktSize, struct json_object *jparent);

/* --- handlers prototypes --- */
void packet_parse(uchar *arg, const struct pcap_pkthdr *pkthdr, const uchar *packet);
char* eth_parse(const uchar *packet, int pktSize, struct json_object *jparent);
char* llc_parse(const uchar *packet, int pktSize, struct json_object *jparent);
char* ipx_parse(const uchar *packet, int pktSize, struct json_object *jparent);
char* ipv4_parse(const uchar *packet, int pktSize, struct json_object *jparent);
char* icmp_parse(const uchar *packet, int pktSize, struct json_object *jparent);
char* tcp_parse(const uchar *packet, int pktSize, struct json_object *jparent);
char* udp_parse(const uchar *packet, int pktSize, struct json_object *jparent);
char* ipv6_parse(const uchar *packet, int pktSize, struct json_object *jparent);
char* arp_parse(const uchar *packet, int pktSize, struct json_object *jparent);
char* rarp_parse(const uchar *packet, int pktSize, struct json_object *jparent);
char* dont_parse(const uchar *packet, int pktSize, struct json_object *jparent);
char* ah_parse(const uchar *packet,int pktSize, struct json_object *jparent);
char* esp_parse(const uchar *packet,int pktSize, struct json_object *jparent);
char* smb_parse(const uchar *packet, int pktSize, struct json_object *jparent);
// char* http_parse(const uchar *packet, int pktSize, struct json_object *jparent);

#define RETURN_DATA_AFTER(x)   if(pktSize > x) {  \
                                uint8_t dataSize = pktSize - x; \
                                char *retBuf = malloc((dataSize+1)*sizeof(char)); \
                                memcpy(retBuf, packet+x, dataSize); \
                                retBuf[dataSize] = '\0';  \
                                return retBuf;  \
                              } else {  \
                                return NULL; \
                              }

#endif /* INCLUDED_PARSER_H */
