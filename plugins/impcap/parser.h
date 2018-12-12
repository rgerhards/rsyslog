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

/* data return structure */
struct data_ret_s {
  size_t size;
  char *pData;
};
typedef struct data_ret_s data_ret_t;

data_ret_t* (*ipProtoHandlers[IP_PROTO_NUM]) (const uchar *packet, int pktSize, struct json_object *jparent);
data_ret_t* (*ethProtoHandlers[ETH_PROTO_NUM]) (const uchar *packet, int pktSize, struct json_object *jparent);

/* --- handlers prototypes --- */
void packet_parse(uchar *arg, const struct pcap_pkthdr *pkthdr, const uchar *packet);
data_ret_t* eth_parse(const uchar *packet, int pktSize, struct json_object *jparent);
data_ret_t* llc_parse(const uchar *packet, int pktSize, struct json_object *jparent);
data_ret_t* ipx_parse(const uchar *packet, int pktSize, struct json_object *jparent);
data_ret_t* ipv4_parse(const uchar *packet, int pktSize, struct json_object *jparent);
data_ret_t* icmp_parse(const uchar *packet, int pktSize, struct json_object *jparent);
data_ret_t* tcp_parse(const uchar *packet, int pktSize, struct json_object *jparent);
data_ret_t* udp_parse(const uchar *packet, int pktSize, struct json_object *jparent);
data_ret_t* ipv6_parse(const uchar *packet, int pktSize, struct json_object *jparent);
data_ret_t* arp_parse(const uchar *packet, int pktSize, struct json_object *jparent);
data_ret_t* rarp_parse(const uchar *packet, int pktSize, struct json_object *jparent);
data_ret_t* dont_parse(const uchar *packet, int pktSize, struct json_object *jparent);
data_ret_t* ah_parse(const uchar *packet,int pktSize, struct json_object *jparent);
data_ret_t* esp_parse(const uchar *packet,int pktSize, struct json_object *jparent);
data_ret_t* smb_parse(const uchar *packet, int pktSize, struct json_object *jparent);
data_ret_t* ftp_parse(const uchar *packet, int pktSize, struct json_object *jparent);
data_ret_t* http_parse(const uchar *packet, int pktSize, struct json_object *jparent);

#define RETURN_DATA_AFTER(x)    data_ret_t *retData = malloc(sizeof(data_ret_t)); \
                                if(pktSize > x) { \
                                  retData->size = pktSize - x;  \
                                  retData->pData = packet + x;  \
                                } \
                                else {  \
                                  retData->size = 0;  \
                                  retData->pData = NULL;  \
                                } \
                                return retData; \

#endif /* INCLUDED_PARSER_H */
