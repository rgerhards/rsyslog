#include "parser.h"

void icmp_parse(const uchar *packet, size_t pktSize, struct json_object *jparent) {
  DBGPRINTF("icmp_parse\n");
  DBGPRINTF("packet size %d\n", pktSize);

  if(pktSize < 8) {
    DBGPRINTF("ICMP packet too small : %d\n", pktSize);
    return;
  }

  icmp_header_t *icmp_header = (icmp_header_t *)packet;

  json_object_object_add(jparent, "net_icmp_type", json_object_new_int(icmp_header->type));
  json_object_object_add(jparent, "net_icmp_code", json_object_new_int(icmp_header->code));
}
