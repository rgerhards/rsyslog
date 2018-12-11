#include "parser.h"

struct arp_header_s {
  uint16_t hwType;
  uint16_t pType;
  uint8_t hwAddrLen;
  uint8_t pAddrLen;
  uint16_t opCode;
  uint8_t pAddr[];
};

typedef struct arp_header_s arp_header_t;

char* arp_parse(const uchar *packet, int pktSize, struct json_object *jparent) {
  DBGPRINTF("arp_parse\n");
  DBGPRINTF("packet size %d\n", pktSize);

  if(pktSize < 28) { /* too small for ARP header*/
    DBGPRINTF("ARP packet too small : %d\n", pktSize);
    return NULL;
  }

	arp_header_t *arp_header = (arp_header_t *)packet;

  char pAddrSrc[20], pAddrDst[20];

  json_object_object_add(jparent, "ARP_hwType", json_object_new_int(ntohs(arp_header->hwType)));
  json_object_object_add(jparent, "ARP_pType", json_object_new_int(ntohs(arp_header->pType)));
  json_object_object_add(jparent, "ARP_op", json_object_new_int(ntohs(arp_header->opCode)));

  if(ntohs(arp_header->hwType) == 1) { /* ethernet addresses */
    char hwAddrSrc[20], hwAddrDst[20];

    ether_ntoa_r((struct eth_addr *)arp_header->pAddr, hwAddrSrc);
    ether_ntoa_r((struct eth_addr *)(arp_header->pAddr+arp_header->hwAddrLen+arp_header->pAddrLen), hwAddrDst);

    json_object_object_add(jparent, "ARP_hwSrc", json_object_new_string((char*)hwAddrSrc));
    json_object_object_add(jparent, "ARP_hwDst", json_object_new_string((char*)hwAddrDst));
  }

  if(ntohs(arp_header->pType) == ETHERTYPE_IP) {
    inet_ntop(AF_INET, (void *)(arp_header->pAddr+arp_header->hwAddrLen), pAddrSrc, 20);
    inet_ntop(AF_INET, (void *)(arp_header->pAddr+2*arp_header->hwAddrLen+arp_header->pAddrLen), pAddrDst, 20);

    json_object_object_add(jparent, "ARP_pSrc", json_object_new_string((char*)pAddrSrc));
    json_object_object_add(jparent, "ARP_pDst", json_object_new_string((char*)pAddrDst));
  }

  RETURN_DATA_AFTER(28)
}

/* copy of ARP handler, as structure is the same but protocol code and name are different */
char* rarp_parse(const uchar *packet, int pktSize, struct json_object *jparent) {
  DBGPRINTF("rarp_parse\n");
  DBGPRINTF("packet size %d\n", pktSize);

  if(pktSize < 28) { /* too small for RARP header*/
    DBGPRINTF("RARP packet too small : %d\n", pktSize);
    return;
  }

	arp_header_t *rarp_header = (arp_header_t *)packet;

  char pAddrSrc[20], pAddrDst[20];

  json_object_object_add(jparent, "RARP_hwType", json_object_new_int(ntohs(rarp_header->hwType)));
  json_object_object_add(jparent, "RARP_pType", json_object_new_int(ntohs(rarp_header->pType)));
  json_object_object_add(jparent, "RARP_op", json_object_new_int(ntohs(rarp_header->opCode)));

  if(ntohs(rarp_header->hwType) == 1) { /* ethernet addresses */
    char *hwAddrSrc = ether_ntoa((struct eth_addr *)rarp_header->pAddr);
    char *hwAddrDst = ether_ntoa((struct eth_addr *)(rarp_header->pAddr+rarp_header->hwAddrLen+rarp_header->pAddrLen));

    json_object_object_add(jparent, "RARP_hwSrc", json_object_new_string((char*)hwAddrSrc));
    json_object_object_add(jparent, "RARP_hwDst", json_object_new_string((char*)hwAddrDst));
  }

  if(ntohs(rarp_header->pType) == ETHERTYPE_IP) {
    inet_ntop(AF_INET, (void *)(rarp_header->pAddr+rarp_header->hwAddrLen), pAddrSrc, 20);
    inet_ntop(AF_INET, (void *)(rarp_header->pAddr+2*rarp_header->hwAddrLen+rarp_header->pAddrLen), pAddrDst, 20);

    json_object_object_add(jparent, "RARP_pSrc", json_object_new_string((char*)pAddrSrc));
    json_object_object_add(jparent, "RARP_pDst", json_object_new_string((char*)pAddrDst));
  }

  RETURN_DATA_AFTER(28)
}
