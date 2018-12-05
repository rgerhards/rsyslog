#include "parser.h"

void ipv6_parse(const uchar *packet, size_t pktSize, struct json_object *jparent) {
  DBGPRINTF("ipv6_parse\n");
  DBGPRINTF("packet size %d\n", pktSize);

  if(pktSize <= 40) { /* too small for IPv6 header + data (header might be longer)*/
    DBGPRINTF("IPv6 packet too small : %d\n", pktSize);
    return;
  }

	ipv6_header_t *ipv6_header = (ipv6_header_t *)packet;

  char addrSrc[40], addrDst[40];

  inet_ntop(AF_INET6, (void *)&ipv6_header->ip6_src, addrSrc, 40);
  inet_ntop(AF_INET6, (void *)&ipv6_header->ip6_dst, addrDst, 40);

  json_object_object_add(jparent, "IP6_dest", json_object_new_string((char*)addrDst));
  json_object_object_add(jparent, "IP6_src", json_object_new_string((char*)addrSrc));
  json_object_object_add(jparent, "IP6_next_header", json_object_new_int(ipv6_header->ip6_nxt));
  json_object_object_add(jparent, "IP6_hop_limit", json_object_new_int(ipv6_header->ip6_hops));
  if (ipv6_header->ip6_nxt == 58)
  {
	icmp_parse(packet+sizeof(ipv6_header_t),pktSize-sizeof(ipv6_header_t),jparent);
  }

}
