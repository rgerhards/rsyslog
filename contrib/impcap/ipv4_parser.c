#include "parser.h"

struct ipv4_header_s {
#if __BYTE_ORDER == __BIG_ENDIAN
  unsigned char version:4;
  unsigned char ihl:4;
#else
  unsigned char ihl:4;
  unsigned char version:4;
#endif
  uint8_t service;
  uint16_t totLen;
  uint16_t id;
  uint16_t frag;
  uint8_t ttl;
  uint8_t proto;
  uint16_t hdrChksum;
  uint8_t addrSrc[4];
  uint8_t addrDst[4];
  uint8_t pOptions[];
};

typedef struct ipv4_header_s ipv4_header_t;

char* ipv4_parse(const uchar *packet, int pktSize, struct json_object *jparent) {
  DBGPRINTF("ipv4_parse\n");
  DBGPRINTF("packet size %d\n", pktSize);

  if(pktSize <= 20) { /* too small for IPv4 header + data (header might be longer)*/
    DBGPRINTF("IPv4 packet too small : %d\n", pktSize);
    RETURN_DATA_AFTER(0)
  }

	ipv4_header_t *ipv4_header = (ipv4_header_t *)packet;

  char addrSrc[20], addrDst[20];
  uint8_t hdrLen = 4*ipv4_header->ihl;  /* 4 x length in words */

  inet_ntop(AF_INET, (void *)&ipv4_header->addrSrc, addrSrc, 20);
  inet_ntop(AF_INET, (void *)&ipv4_header->addrDst, addrDst, 20);

  json_object_object_add(jparent, "net_dst_ip", json_object_new_string((char*)addrDst));
  json_object_object_add(jparent, "net_src_ip", json_object_new_string((char*)addrSrc));
  json_object_object_add(jparent, "IP_ihl", json_object_new_int(ipv4_header->ihl));
  json_object_object_add(jparent, "net_ttl", json_object_new_int(ipv4_header->ttl));

  return (*ipProtoHandlers[ipv4_header->proto])((packet + hdrLen), (pktSize - hdrLen), jparent);
}
