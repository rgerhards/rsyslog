#include "parser.h"

void udp_parse(const uchar *packet, size_t pktSize, struct json_object *jparent){
  DBGPRINTF("udp_parse\n");
  DBGPRINTF("packet size %d\n", pktSize);

  if(pktSize < 8) {
    DBGPRINTF("UDP packet too small : %d\n", pktSize);
    return;
  }

  udp_header_t *udp_header = (udp_header_t *)packet;

  json_object_object_add(jparent, "UDP_Source_Port", json_object_new_int(ntohs(udp_header->uh_sport)));
  json_object_object_add(jparent, "UDP_Destination_Port", json_object_new_int(ntohs(udp_header->uh_dport)));
  json_object_object_add(jparent, "UDP_Length", json_object_new_int(ntohs(udp_header->uh_ulen)));

}
