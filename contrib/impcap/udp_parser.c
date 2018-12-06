#include "parser.h"

struct udp_header_s {
  uint16_t srcPort;
  uint16_t dstPort;
  uint16_t totalLength;
  uint16_t checksum;
};

typedef struct udp_header_s udp_header_t;

void udp_parse(const uchar *packet, size_t pktSize, struct json_object *jparent){
  DBGPRINTF("udp_parse\n");
  DBGPRINTF("packet size %d\n", pktSize);

  if(pktSize < 8) {
    DBGPRINTF("UDP packet too small : %d\n", pktSize);
    return;
  }

  udp_header_t *udp_header = (udp_header_t *)packet;

  json_object_object_add(jparent, "net_src_port", json_object_new_int(ntohs(udp_header->srcPort)));
  json_object_object_add(jparent, "net_dst_port", json_object_new_int(ntohs(udp_header->dstPort)));
  json_object_object_add(jparent, "UDP_Length", json_object_new_int(ntohs(udp_header->totalLength)));
  json_object_object_add(jparent, "UDP_Checksum", json_object_new_int(ntohs(udp_header->checksum)));

}
