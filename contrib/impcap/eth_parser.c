#include "parser.h"

struct eth_header_s
{
  uint8_t  addrDst[6];
  uint8_t  addrSrc[6];
  uint16_t type;
} __attribute__ ((__packed__));

typedef struct eth_header_s eth_header_t;

void eth_parse(const uchar *packet, size_t pktSize, struct json_object *jparent) {
  DBGPRINTF("entered eth_parse\n");
  DBGPRINTF("packet size %d\n", pktSize);
  if (pktSize < 14) {  /* too short for eth header */
    DBGPRINTF("ETH packet too small : %d\n", pktSize);
    return;
  }

  eth_header_t *eth_header = (eth_header_t *)packet;
  char ethMacSrc[20], ethMacDst[20];

  ether_ntoa_r((struct eth_addr *)eth_header->addrSrc, ethMacSrc);
  ether_ntoa_r((struct eth_addr *)eth_header->addrDst, ethMacDst);

  json_object_object_add(jparent, "ETH_src", json_object_new_string((char*)ethMacSrc));
  json_object_object_add(jparent, "ETH_dst", json_object_new_string((char*)ethMacDst));

  uint16_t ethType = (uint16_t)ntohs(eth_header->type);

  if(ethType < 1500) {
    /* this is a LLC header */
    json_object_object_add(jparent, "ETH_len", json_object_new_int(ethType));
    llc_parse(packet + 14, pktSize - 14, jparent);
    return;
  }

  json_object_object_add(jparent, "ETH_type", json_object_new_int(ethType));
  (*ethProtoHandlers[ethType])((packet + sizeof(eth_header_t)), (pktSize - sizeof(eth_header_t)), jparent);
}
