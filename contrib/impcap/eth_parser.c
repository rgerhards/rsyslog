#include "parser.h"

struct eth_header_s
{
  uint8_t  addrDst[6];
  uint8_t  addrSrc[6];
  uint16_t type;
} __attribute__ ((__packed__));

struct vlan_header_s
{
  uint8_t  addrDst[6];
  uint8_t  addrSrc[6];
  uint16_t vlanCode;
  uint16_t vlanTag;
  uint16_t type;
} __attribute__ ((__packed__));

typedef struct eth_header_s eth_header_t;
typedef struct vlan_header_s vlan_header_t;

data_ret_t* eth_parse(const uchar *packet, int pktSize, struct json_object *jparent) {
  DBGPRINTF("entered eth_parse\n");
  DBGPRINTF("packet size %d\n", pktSize);
  if (pktSize < 14) {  /* too short for eth header */
    DBGPRINTF("ETH packet too small : %d\n", pktSize);
    RETURN_DATA_AFTER(0)
  }

  eth_header_t *eth_header = (eth_header_t *)packet;
  char ethMacSrc[20], ethMacDst[20];
  uint8_t hdrLen = 14;

  ether_ntoa_r((struct eth_addr *)eth_header->addrSrc, ethMacSrc);
  ether_ntoa_r((struct eth_addr *)eth_header->addrDst, ethMacDst);

  json_object_object_add(jparent, "ETH_src", json_object_new_string((char*)ethMacSrc));
  json_object_object_add(jparent, "ETH_dst", json_object_new_string((char*)ethMacDst));

  uint16_t ethType = (uint16_t)ntohs(eth_header->type);

  if(ethType == ETHERTYPE_VLAN) {
    vlan_header_t *vlan_header = (vlan_header_t *)packet;
    json_object_object_add(jparent, "ETH_tag", json_object_new_int(ntohs(vlan_header->vlanTag)));
    ethType = (uint16_t)ntohs(vlan_header->type);
    hdrLen += 4;
  }

  if(ethType < 1500) {
    /* this is a LLC header */
    json_object_object_add(jparent, "ETH_len", json_object_new_int(ethType));
    return llc_parse(packet + hdrLen, pktSize - hdrLen, jparent);
  }

  json_object_object_add(jparent, "ETH_type", json_object_new_int(ethType));
  return (*ethProtoHandlers[ethType])((packet + hdrLen), (pktSize - hdrLen), jparent);
}
