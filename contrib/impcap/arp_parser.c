#include "parser.h"

void arp_parse(const uchar *packet, size_t pktSize, struct json_object *jparent) {
  DBGPRINTF("arp_parse\n");
  DBGPRINTF("packet size %d\n", pktSize);

  if(pktSize <= 27) { /* too small for ARP header*/
    DBGPRINTF("ARP packet too small : %d\n", pktSize);
    return;
  }

	arp_header_t *arp_header = (arp_header_t *)packet;

  char pAddrSrc[20], pAddrDst[20];

  json_object_object_add(jparent, "ARP_hwType", json_object_new_int(ntohs(arp_header->arp_hrd)));
  json_object_object_add(jparent, "ARP_pType", json_object_new_int(ntohs(arp_header->arp_pro)));
  json_object_object_add(jparent, "ARP_op", json_object_new_int(ntohs(arp_header->arp_op)));

  if(ntohs(arp_header->arp_hrd) == 1) { /* ethernet addresses */
    char *hwAddrSrc = ether_ntoa((struct eth_addr *)arp_header->arp_sha);
    char *hwAddrDst = ether_ntoa((struct eth_addr *)arp_header->arp_tha);

    json_object_object_add(jparent, "ARP_hwSrc", json_object_new_string((char*)hwAddrSrc));
    json_object_object_add(jparent, "ARP_hwDst", json_object_new_string((char*)hwAddrDst));
  }

  if(ntohs(arp_header->arp_pro) == ETHERTYPE_IP) {
    inet_ntop(AF_INET, (void *)&arp_header->arp_spa, pAddrSrc, 20);
    inet_ntop(AF_INET, (void *)&arp_header->arp_tpa, pAddrDst, 20);

    json_object_object_add(jparent, "ARP_pSrc", json_object_new_string((char*)pAddrSrc));
    json_object_object_add(jparent, "ARP_pDst", json_object_new_string((char*)pAddrDst));
  }

}

/* copy of ARP handler, as structure is the same but protocol code and name are different */
void rarp_parse(const uchar *packet, size_t pktSize, struct json_object *jparent) {
  DBGPRINTF("rarp_parse\n");
  DBGPRINTF("packet size %d\n", pktSize);

  if(pktSize <= 27) { /* too small for RARP header*/
    DBGPRINTF("RARP packet too small : %d\n", pktSize);
    return;
  }

	arp_header_t *rarp_header = (arp_header_t *)packet;

  char pAddrSrc[20], pAddrDst[20];

  json_object_object_add(jparent, "RARP_hwType", json_object_new_int(ntohs(rarp_header->arp_hrd)));
  json_object_object_add(jparent, "RARP_pType", json_object_new_int(ntohs(rarp_header->arp_pro)));
  json_object_object_add(jparent, "RARP_op", json_object_new_int(ntohs(rarp_header->arp_op)));

  if(ntohs(rarp_header->arp_hrd) == 1) { /* ethernet addresses */
    char *hwAddrSrc = ether_ntoa((struct eth_addr *)rarp_header->arp_sha);
    char *hwAddrDst = ether_ntoa((struct eth_addr *)rarp_header->arp_tha);

    json_object_object_add(jparent, "RARP_hwSrc", json_object_new_string((char*)hwAddrSrc));
    json_object_object_add(jparent, "RARP_hwDst", json_object_new_string((char*)hwAddrDst));
  }

  if(ntohs(rarp_header->arp_pro) == ETHERTYPE_IP) {
    inet_ntop(AF_INET, (void *)&rarp_header->arp_spa, pAddrSrc, 20);
    inet_ntop(AF_INET, (void *)&rarp_header->arp_tpa, pAddrDst, 20);

    json_object_object_add(jparent, "RARP_pSrc", json_object_new_string((char*)pAddrSrc));
    json_object_object_add(jparent, "RARP_pDst", json_object_new_string((char*)pAddrDst));
  }

}
