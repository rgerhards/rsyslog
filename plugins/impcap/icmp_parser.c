#include "parser.h"

struct icmp_header_s {
  uint8_t type;
  uint8_t code;
  uint16_t checksum;
  uint8_t data[];
};

typedef struct icmp_header_s icmp_header_t;

data_ret_t* icmp_parse(const uchar *packet, int pktSize, struct json_object *jparent) {
  DBGPRINTF("icmp_parse\n");
  DBGPRINTF("packet size %d\n", pktSize);

  if(pktSize < 8) {
    DBGPRINTF("ICMP packet too small : %d\n", pktSize);
    RETURN_DATA_AFTER(0);
  }

  icmp_header_t *icmp_header = (icmp_header_t *)packet;

  json_object_object_add(jparent, "net_icmp_type", json_object_new_int(icmp_header->type));
  json_object_object_add(jparent, "net_icmp_code", json_object_new_int(icmp_header->code));
  json_object_object_add(jparent, "icmp_checksum", json_object_new_int(ntohs(icmp_header->checksum)));

  RETURN_DATA_AFTER(8)
}
