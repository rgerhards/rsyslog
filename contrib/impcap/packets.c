#include "packets.h"

void (*ipProtoHandlers[IP_PROTO_NUM]) (const uchar *packet, size_t pktSize, struct json_object *jparent);
void (*ethProtoHandlers[ETH_PROTO_NUM]) (const uchar *packet, size_t pktSize, struct json_object *jparent);

/* ---message handling functions --- */

/* callback for packet received from pcap_loop */

/* TODO check ETH II or 802.3 or 802.3 Tagué (VLAN)
    difference in proto field (after source field) :
      - >1500 means ETH II and is proto
      - <= 1500 means 802.3 and is length
        - special value of proto means tagged (+ tag 2 bytes after)
*/
void handle_packet(uchar *arg, const struct pcap_pkthdr *pkthdr, const uchar *packet) {
  DBGPRINTF("impcap : entered handle_packet\n");
  smsg_t *pMsg;

  if(pkthdr->len < 40 || pkthdr->len > 1514) {
    DBGPRINTF("bad packet length, discarded\n");
    return;
  }

  msgConstruct(&pMsg);

	struct json_object *jown = json_object_new_object();

  handle_eth_header(packet, pkthdr->len, jown);

  msgAddJSON(pMsg, JSON_LOOKUP_NAME, jown, 0, 0);
  submitMsg2(pMsg);
}

void handle_eth_header(const uchar *packet, size_t pktSize, struct json_object *jparent) {
  DBGPRINTF("entered handle_eth_header\n");
  if (pktSize <= 14) {  /* too short for eth header + data */
    DBGPRINTF("ETH packet too small : %d\n", pktSize);
    return;
  }
  struct json_object *jown = json_object_new_object();

  eth_header_t *eth_header = (eth_header_t *)packet;

  char *ethMacSrc = ether_ntoa((struct eth_addr *)eth_header->ether_shost);
  char *ethMacDst = ether_ntoa((struct eth_addr *)eth_header->ether_dhost);
  uint16_t ethType = ntohs(eth_header->ether_type);
  char errMsg[50];

  DBGPRINTF("MAC destination : %s\n", ethMacDst);
  DBGPRINTF("MAC source : %s\n", ethMacSrc);
  DBGPRINTF("ether type : %04X\n", ethType);

  json_object_object_add(jown, "ETH_src", json_object_new_string((char*)ethMacSrc));
  json_object_object_add(jown, "ETH_dst", json_object_new_string((char*)ethMacDst));
  json_object_object_add(jown, "ETH_type", json_object_new_int(ethType));

  json_object_object_add(jparent, "ETH", jown);

  (*ethProtoHandlers[ethType])((packet + sizeof(eth_header_t)), (pktSize - sizeof(eth_header_t)), jown);
}

void handle_ipv4_header(const uchar *packet, size_t pktSize, struct json_object *jparent) {
  struct json_object *jown = json_object_new_object();
  DBGPRINTF("handle_ipv4_header\n");

  if(pktSize <= 20) { /* too small for IPv4 header + data (header might be longer)*/
    DBGPRINTF("IPv4 packet too small : %d\n", pktSize);
    return;
  }

	ipv4_header_t *ipv4_header = (ipv4_header_t *)packet;

  char addrSrc[20], addrDst[20], hdrLenStr[2], proto[8];
  uint8_t hdrLen = 4*ipv4_header->ip_hl;  /* 4 x length in words */

  inet_ntop(AF_INET, (void *)&ipv4_header->ip_src, addrSrc, 20);
  inet_ntop(AF_INET, (void *)&ipv4_header->ip_dst, addrDst, 20);
  snprintf(hdrLenStr, 2, "%d", ipv4_header->ip_hl);

  DBGPRINTF("IP destination : %s\n", addrDst);
  DBGPRINTF("IP source : %s\n", addrSrc);
  DBGPRINTF("IHL : %s\n", hdrLenStr);

  json_object_object_add(jown, "IP_dest", json_object_new_string((char*)addrDst));
  json_object_object_add(jown, "IP_src", json_object_new_string((char*)addrSrc));
  json_object_object_add(jown, "IP_ihl", json_object_new_int(ipv4_header->ip_hl));
  json_object_object_add(jparent, "IPV4", jown);


  DBGPRINTF("protocol: %d\n", ipv4_header->ip_p);
  (*ipProtoHandlers[ipv4_header->ip_p])((packet + hdrLen), (pktSize - hdrLen), jown);
}

void handle_icmp_header(const uchar *packet, size_t pktSize, struct json_object *jparent) {
  struct json_object *jown = json_object_new_object();
  DBGPRINTF("handle_icmp_header\n");

  if(pktSize < 8) {
    DBGPRINTF("ICMP packet too small : %d\n", pktSize);
    return;
  }

  icmp_header_t *icmp_header = (icmp_header_t *)packet;
  char typeStr[4], codeStr[4];

  snprintf(typeStr, 4, "%d", icmp_header->type);
  snprintf(codeStr, 4, "%d", icmp_header->code);

  DBGPRINTF("ICMP type : %s\n", typeStr);
  DBGPRINTF("ICMP code : %s\n", codeStr);

  json_object_object_add(jown, "ICMP_type", json_object_new_int(icmp_header->type));
  json_object_object_add(jown, "ICMP_code", json_object_new_int(icmp_header->code));
  json_object_object_add(jparent, "ICMP", jown);

}

void handle_tcp_header(const uchar *packet, size_t pktSize, struct json_object *jparent){
  struct json_object *jown = json_object_new_object();
  DBGPRINTF("handle_tcp_header\n");

  if(pktSize < 20) {
    DBGPRINTF("TCP packet too small : %d\n", pktSize);
    return;
  }

  tcp_header_t *tcp_header = (tcp_header_t *)packet;
  char sportStr[8], dportStr[8];

  snprintf(sportStr, 8, "%d", tcp_header->th_sport);
  snprintf(dportStr, 8, "%d", tcp_header->th_dport);

  DBGPRINTF("TCP Source Port : %s\n", sportStr);
  DBGPRINTF("TCP Destination Port : %s\n", dportStr);

  json_object_object_add(jown, "TCP_Source_Port", json_object_new_int(tcp_header->th_sport));
  json_object_object_add(jown, "TCP_Destination_Port", json_object_new_int(tcp_header->th_dport));
  json_object_object_add(jparent, "TCP", jown);

}

void handle_udp_header(const uchar *packet, size_t pktSize, struct json_object *jparent){
  struct json_object *jown = json_object_new_object();
  DBGPRINTF("handle_udp_header\n");

  if(pktSize < 8) {
    DBGPRINTF("UDP packet too small : %d\n", pktSize);
    return;
  }

  udp_header_t *udp_header = (udp_header_t *)packet;
  char usport[8], udport[8], ulen[8];

  snprintf(usport, 8, "%d", udp_header->uh_sport);
  snprintf(udport, 8, "%d", udp_header->uh_dport);
  snprintf(ulen, 8, "%d", udp_header->uh_ulen);

  DBGPRINTF("UDP Source Port : %s\n", usport);
  DBGPRINTF("UDP Destination Port : %s\n", udport);
  DBGPRINTF("UDP Length : %s\n", ulen);

  json_object_object_add(jown, "UDP_Source_Port", json_object_new_int(udp_header->uh_sport));
  json_object_object_add(jown, "UDP_Destination_Port", json_object_new_int(udp_header->uh_dport));
  json_object_object_add(jown, "UDP_Length", json_object_new_int(udp_header->uh_ulen));
  json_object_object_add(jparent, "UDP", jown);

}

void handle_ipv6_header(const uchar *packet, size_t pktSize, struct json_object *jparent) {
  struct json_object *jown = json_object_new_object();
  DBGPRINTF("handle_ipv6_header\n");

  if(pktSize <= 40) { /* too small for IPv6 header + data (header might be longer)*/
    DBGPRINTF("IPv6 packet too small : %d\n", pktSize);
    return;
  }

	ipv6_header_t *ipv6_header = (ipv6_header_t *)packet;

  char addrSrc[40], addrDst[40];

  inet_ntop(AF_INET6, (void *)&ipv6_header->ip6_src, addrSrc, 40);
  inet_ntop(AF_INET6, (void *)&ipv6_header->ip6_dst, addrDst, 40);
  DBGPRINTF("IP6 source : %s\n", addrSrc);
  DBGPRINTF("IP6 destination : %s\n", addrDst);

  json_object_object_add(jown, "IP6_dest", json_object_new_string((char*)addrDst));
  json_object_object_add(jown, "IP6_src", json_object_new_string((char*)addrSrc));
  json_object_object_add(jparent, "IPV6", jown);

}

void handle_arp_header(const uchar *packet, size_t pktSize, struct json_object *jparent) {
  struct json_object *jown = json_object_new_object();
  DBGPRINTF("handle_arp_header\n");

  if(pktSize <= 27) { /* too small for ARP header*/
    DBGPRINTF("ARP packet too small : %d\n", pktSize);
    return;
  }

	arp_header_t *arp_header = (arp_header_t *)packet;

  char hwType[5], pType[5], op[5], pAddrSrc[20], pAddrDst[20];
  snprintf(hwType, 5, "%04X", ntohs(arp_header->arp_hrd));
  snprintf(pType, 5, "%04X", ntohs(arp_header->arp_pro));
  snprintf(op, 5, "%04X", ntohs(arp_header->arp_op));

  DBGPRINTF("ARP hardware type : %s\n", hwType);
  DBGPRINTF("ARP proto type : %s\n", pType);
  DBGPRINTF("ARP operation : %s\n", op);

  json_object_object_add(jown, "ARP_hwType", json_object_new_int(ntohs(arp_header->arp_hrd)));
  json_object_object_add(jown, "ARP_pType", json_object_new_int(ntohs(arp_header->arp_pro)));
  json_object_object_add(jown, "ARP_op", json_object_new_int(ntohs(arp_header->arp_op)));

  if(ntohs(arp_header->arp_hrd) == 1) { /* ethernet addresses */
    char *hwAddrSrc = ether_ntoa((struct eth_addr *)arp_header->arp_sha);
    char *hwAddrDst = ether_ntoa((struct eth_addr *)arp_header->arp_tha);

    json_object_object_add(jown, "ARP_hwSrc", json_object_new_string((char*)hwAddrSrc));
    json_object_object_add(jown, "ARP_hwDst", json_object_new_string((char*)hwAddrDst));
  }

  if(ntohs(arp_header->arp_pro) == ETHERTYPE_IP) {
    inet_ntop(AF_INET, (void *)&arp_header->arp_spa, pAddrSrc, 20);
    inet_ntop(AF_INET, (void *)&arp_header->arp_tpa, pAddrDst, 20);

    json_object_object_add(jown, "ARP_pSrc", json_object_new_string((char*)pAddrSrc));
    json_object_object_add(jown, "ARP_pDst", json_object_new_string((char*)pAddrDst));
  }

  json_object_object_add(jparent, "ARP", jown);
}

void dont_handle(const uchar *packet, size_t pktSize, struct json_object *jparent) {
  DBGPRINTF("protocol not handled\n");
}

/* TODO: add user parameters to select handled protocols */
void init_eth_proto_handlers() {
  DBGPRINTF("begining init eth handlers\n");
  // set all to blank function
  for(int i = 0; i < ETH_PROTO_NUM; ++i) {
    ethProtoHandlers[i] = dont_handle;
  }

  ethProtoHandlers[ETHERTYPE_IP] = handle_ipv4_header;
  ethProtoHandlers[ETHERTYPE_ARP] = handle_arp_header;
  ethProtoHandlers[ETHERTYPE_IPV6] = handle_ipv6_header;

}

/* TODO: add user parameters to select handled protocols */
void init_ip_proto_handlers() {
  DBGPRINTF("begining init ip handlers\n");
  // set all to blank function
  for(int i = 0; i < IP_PROTO_NUM; ++i) {
    ipProtoHandlers[i] = dont_handle;
  }

  ipProtoHandlers[IPPROTO_ICMP] = handle_icmp_header;
}
