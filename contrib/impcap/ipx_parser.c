#include "parser.h"

struct ipx_header_s {
  uint16_t chksum;
  uint16_t pktLen;
  uint8_t transCtrl;
  uint8_t type;
  uint32_t dstNet;
  uint8_t dstNode[6];
  uint16_t dstSocket;
  uint32_t srcNet;
  uint8_t srcNode[6];
  uint16_t srcSocket;
}__attribute__ ((__packed__));

typedef struct ipx_header_s ipx_header_t;

void ipx_parse(const uchar *packet, size_t pktSize, struct json_object *jparent) {

  DBGPRINTF("entered ipx_parse\n");
  DBGPRINTF("packet size %d\n", pktSize);

  if (pktSize < 30) {  /* too short for IPX header */
    DBGPRINTF("IPX packet too small : %d\n", pktSize);
    return;
  }

  char ipxSrcNode[20], ipxDstNode[20];
  ipx_header_t *ipx_header = (ipx_header_t *)packet;

  snprintf(ipxDstNode, sizeof(ipxDstNode), "%02x:%02x:%02x:%02x:%02x:%02x"
    ,ipx_header->dstNode[0]
    ,ipx_header->dstNode[1]
    ,ipx_header->dstNode[2]
    ,ipx_header->dstNode[3]
    ,ipx_header->dstNode[4]
    ,ipx_header->dstNode[5]);

  snprintf(ipxSrcNode, sizeof(ipxSrcNode), "%02x:%02x:%02x:%02x:%02x:%02x"
    ,ipx_header->srcNode[0]
    ,ipx_header->srcNode[1]
    ,ipx_header->srcNode[2]
    ,ipx_header->srcNode[3]
    ,ipx_header->srcNode[4]
    ,ipx_header->srcNode[5]);

  json_object_object_add(jparent, "IPX_transCtrl", json_object_new_int(ipx_header->transCtrl));
  json_object_object_add(jparent, "IPX_type", json_object_new_int(ipx_header->type));
  json_object_object_add(jparent, "IPX_dest_net", json_object_new_int(ntohl(ipx_header->dstNet)));
  json_object_object_add(jparent, "IPX_src_net", json_object_new_int(ntohl(ipx_header->srcNet)));
  json_object_object_add(jparent, "IPX_dest_node", json_object_new_string(ipxDstNode));
  json_object_object_add(jparent, "IPX_src_node", json_object_new_string(ipxSrcNode));
  json_object_object_add(jparent, "IPX_dest_socket", json_object_new_int(ntohs(ipx_header->dstSocket)));
  json_object_object_add(jparent, "IPX_src_soket", json_object_new_int(ntohs(ipx_header->srcSocket)));
}
