#include "parser.h"

void handle_eth_header(const uchar *packet, size_t pktSize, struct json_object *jparent) {
  DBGPRINTF("entered handle_eth_header\n");
  DBGPRINTF("packet size %d\n", pktSize);
  if (pktSize < 14) {  /* too short for eth header */
    DBGPRINTF("ETH packet too small : %d\n", pktSize);
    return;
  }

  eth_header_t *eth_header = (eth_header_t *)packet;
  char ethMacSrc[20], ethMacDst[20];

  ether_ntoa_r((struct eth_addr *)eth_header->ether_shost, ethMacSrc);
  ether_ntoa_r((struct eth_addr *)eth_header->ether_dhost, ethMacDst);

  json_object_object_add(jparent, "ETH_src", json_object_new_string((char*)ethMacSrc));
  json_object_object_add(jparent, "ETH_dst", json_object_new_string((char*)ethMacDst));

  uint16_t ethType = (uint16_t)ntohs(eth_header->ether_type);

  if(ethType < 1500) {
    /* this is a LLC header */
    json_object_object_add(jparent, "ETH_len", json_object_new_int(ethType));
    handle_llc_header(packet + 14, pktSize - 14, jparent);
    return;
  }

  json_object_object_add(jparent, "ETH_type", json_object_new_int(ethType));
  (*ethProtoHandlers[ethType])((packet + sizeof(eth_header_t)), (pktSize - sizeof(eth_header_t)), jparent);
}
