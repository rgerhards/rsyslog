#include "parser.h"


void ipv4_parse(const uchar *packet, size_t pktSize, struct json_object *jparent) {
  DBGPRINTF("ipv4_parse\n");
  DBGPRINTF("packet size %d\n", pktSize);

  if(pktSize <= 20) { /* too small for IPv4 header + data (header might be longer)*/
    DBGPRINTF("IPv4 packet too small : %d\n", pktSize);
    return;
  }

	ipv4_header_t *ipv4_header = (ipv4_header_t *)packet;

  char addrSrc[20], addrDst[20];
  uint8_t hdrLen = 4*ipv4_header->ip_hl;  /* 4 x length in words */

  inet_ntop(AF_INET, (void *)&ipv4_header->ip_src, addrSrc, 20);
  inet_ntop(AF_INET, (void *)&ipv4_header->ip_dst, addrDst, 20);

  json_object_object_add(jparent, "net_dst_ip", json_object_new_string((char*)addrDst));
  json_object_object_add(jparent, "net_src_ip", json_object_new_string((char*)addrSrc));
  json_object_object_add(jparent, "IP_ihl", json_object_new_int(ipv4_header->ip_hl));
  json_object_object_add(jparent, "net_ttl", json_object_new_int(ipv4_header->ip_ttl));

  (*ipProtoHandlers[ipv4_header->ip_p])((packet + hdrLen), (pktSize - hdrLen), jparent);
}
