#include "parser.h"

struct ipv6_header_s {
#define IPV6_VERSION_MASK 0xF0000000
#define IPV6_TC_MASK      0x0FF00000
#define IPV6_FLOW_MASK    0x000FFFFF
  uint32_t vtf;
  uint16_t dataLength;
  uint8_t nextHeader;
  uint8_t hopLimit;
  uint8_t addrSrc[16];
  uint8_t addrDst[16];
} __attribute__ ((__packed__));

#define IPV6_VERSION(h) (ntohl(h->vtf) & IPV6_VERSION_MASK)>>28
#define IPV6_TC(h)      (ntohl(h->vtf) & IPV6_TC_MASK)>>20
#define IPV6_FLOW(h)    (ntohl(h->vtf) & IPV6_FLOW_MASK)

typedef struct ipv6_header_s ipv6_header_t;

void ipv6_parse(const uchar *packet, size_t pktSize, struct json_object *jparent) {
  DBGPRINTF("ipv6_parse\n");
  DBGPRINTF("packet size %d\n", pktSize);

  if(pktSize <= 40) { /* too small for IPv6 header + data (header might be longer)*/
    DBGPRINTF("IPv6 packet too small : %d\n", pktSize);
    return;
  }

	ipv6_header_t *ipv6_header = (ipv6_header_t *)packet;

  char addrSrc[40], addrDst[40];

  inet_ntop(AF_INET6, (void *)&ipv6_header->addrSrc, addrSrc, 40);
  inet_ntop(AF_INET6, (void *)&ipv6_header->addrDst, addrDst, 40);

  json_object_object_add(jparent, "net_dst_ip", json_object_new_string((char*)addrDst));
  json_object_object_add(jparent, "net_src_ip", json_object_new_string((char*)addrSrc));
  json_object_object_add(jparent, "IP6_next_header", json_object_new_int(ipv6_header->nextHeader));
  json_object_object_add(jparent, "net_ttl", json_object_new_int(ipv6_header->hopLimit));
  if (ipv6_header->nextHeader == 58)
  {
	   icmp_parse(packet+sizeof(ipv6_header_t),pktSize-sizeof(ipv6_header_t),jparent);
  }

}
