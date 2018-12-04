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
  int * id = (int *)arg;
  msgConstruct(&pMsg);
  struct json_object *jown = json_object_new_object();
  json_object_object_add(jown, "ID", json_object_new_int(++(*id)));
  json_object_object_add(jown, "total packet length", json_object_new_int(pkthdr->len));

  handle_eth_header(packet, pkthdr->caplen, jown);


  msgAddJSON(pMsg, JSON_LOOKUP_NAME, jown, 0, 0);
  submitMsg2(pMsg);
}

void handle_eth_header(const uchar *packet, size_t pktSize, struct json_object *jparent) {
  DBGPRINTF("entered handle_eth_header\n");
  DBGPRINTF("packet size %d\n", pktSize);
  if (pktSize < 14) {  /* too short for eth header */
    DBGPRINTF("ETH packet too small : %d\n", pktSize);
    return;
  }

  eth_header_t *eth_header = (eth_header_t *)packet;

  char *ethMacSrc = ether_ntoa((struct eth_addr *)eth_header->ether_shost);
  char *ethMacDst = ether_ntoa((struct eth_addr *)eth_header->ether_dhost);

  json_object_object_add(jparent, "ETH_src", json_object_new_string((char*)ethMacSrc));
  json_object_object_add(jparent, "ETH_dst", json_object_new_string((char*)ethMacDst));

  uint16_t ethType = (uint16_t)ntohs(eth_header->ether_type);

  if(ethType < 1500) {
    /* this is a LLC header */
    handle_llc_header(packet + 12, pktSize - 12, jparent);
    return;
  }

  json_object_object_add(jparent, "ETH_type", json_object_new_int(ethType));
  (*ethProtoHandlers[ethType])((packet + sizeof(eth_header_t)), (pktSize - sizeof(eth_header_t)), jparent);
}

void handle_llc_header(const uchar *packet, size_t pktSize, struct json_object *jparent) {
  DBGPRINTF("entered handle_llc_header\n");
  DBGPRINTF("packet size %d\n", pktSize);

  if (pktSize < 3) {  /* too short for llc header */
    DBGPRINTF("LLC packet too small : %d\n", pktSize);
    return;
  }

  uint8_t dsapField, dsap, ssapField, ssap;
  uint16_t ctrl;
  uint8_t headerLen;

  dsapField = packet[0];
  ssapField = packet[1];

  if(dsapField == 0xff && ssapField == 0xff) {
    /* this is an IPX packet, without LLC */
    handle_ipx_header(packet, pktSize, jparent);
    return;
  }

  if((packet[2] & 0x03) == 3) {
    /* U frame: LLC control is 8 bits */
    ctrl = (uint8_t)packet[2];
    headerLen = 3;
  }
  else {
    /* I and S data frames: LLC control is 16 bits */
    ctrl = ntohs((uint16_t)packet[2]);
    headerLen = 4;
  }

  /* don't take last bit into account */
  dsap = dsapField & 0xfe;
  ssap = ssapField & 0xfe;

  json_object_object_add(jparent, "LLC_dsap", json_object_new_int(dsap));
  json_object_object_add(jparent, "LLC_ssap", json_object_new_int(ssap));
  json_object_object_add(jparent, "LLC_ctrl", json_object_new_int(ctrl));

  if(dsap == 0xaa && ssap == 0xaa && ctrl == 0x03) {
    /* SNAP header */
    uint16_t ethType = (uint16_t)ntohs(packet[headerLen+3]);
    (*ethProtoHandlers[ethType])(packet + headerLen, pktSize - headerLen, jparent);
    return;
  }
  if(dsap == 0x06 && ssap == 0x06 && ctrl == 0x03) {
    /* IPv4 header */
    handle_ipv4_header(packet + headerLen, pktSize - headerLen, jparent);
    return;
  }
  if(dsap == 0xe0 && ssap == 0xe0 && ctrl == 0x03) {
    /* IPX packet with LLC */
    handle_ipx_header(packet + headerLen, pktSize - headerLen, jparent);
  }
}

void handle_ipx_header(const uchar *packet, size_t pktSize, struct json_object *jparent) {
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
  };

  DBGPRINTF("entered handle_ipx_header\n");
  DBGPRINTF("packet size %d\n", pktSize);

  if (pktSize < 30) {  /* too short for IPX header */
    DBGPRINTF("IPX packet too small : %d\n", pktSize);
    return;
  }

  char ipxSrcNode[20], ipxDstNode[20];
  struct ipx_header_s *ipx_header = (struct ipx_header_s *)packet;

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

  json_object_object_add(jparent, "IPX_transCtrl", json_object_new_int(ntohs(ipx_header->transCtrl)));
  json_object_object_add(jparent, "IPX_type", json_object_new_int(ntohs(ipx_header->type)));
  json_object_object_add(jparent, "IPX_dest_net", json_object_new_int(ntohl(ipx_header->dstNet)));
  json_object_object_add(jparent, "IPX_src_net", json_object_new_int(ntohl(ipx_header->srcNet)));
  json_object_object_add(jparent, "IPX_dest_node", json_object_new_string(ipxDstNode));
  json_object_object_add(jparent, "IPX_src_node", json_object_new_string(ipxSrcNode));
  json_object_object_add(jparent, "IPX_dest_socket", json_object_new_int(ntohs(ipx_header->dstSocket)));
  json_object_object_add(jparent, "IPX_src_soket", json_object_new_int(ntohs(ipx_header->srcSocket)));
}

void handle_ipv4_header(const uchar *packet, size_t pktSize, struct json_object *jparent) {
  DBGPRINTF("handle_ipv4_header\n");
  DBGPRINTF("packet size %d\n", pktSize);

  if(pktSize <= 20) { /* too small for IPv4 header + data (header might be longer)*/
    DBGPRINTF("IPv4 packet too small : %d\n", pktSize);
    return;
  }

	ipv4_header_t *ipv4_header = (ipv4_header_t *)packet;

  char addrSrc[20], addrDst[20];
  uint8_t hdrLen = 4*ipv4_header->ip_hl;  /* 4 x length in words */

  inet_ntop(AF_INET, (void *)&ipv4_header->ip_src, addrSrc, 20);
  inet_ntop(AF_INET, (void *)&ipv4_header->ip_dst, addrDst, 20);

  json_object_object_add(jparent, "IP_dest", json_object_new_string((char*)addrDst));
  json_object_object_add(jparent, "IP_src", json_object_new_string((char*)addrSrc));
  json_object_object_add(jparent, "IP_ihl", json_object_new_int(ipv4_header->ip_hl));
  json_object_object_add(jparent, "IP_ttl", json_object_new_int(ipv4_header->ip_ttl));

  (*ipProtoHandlers[ipv4_header->ip_p])((packet + hdrLen), (pktSize - hdrLen), jparent);
}

void handle_icmp_header(const uchar *packet, size_t pktSize, struct json_object *jparent) {
  DBGPRINTF("handle_icmp_header\n");
  DBGPRINTF("packet size %d\n", pktSize);

  if(pktSize < 8) {
    DBGPRINTF("ICMP packet too small : %d\n", pktSize);
    return;
  }

  icmp_header_t *icmp_header = (icmp_header_t *)packet;

  json_object_object_add(jparent, "ICMP_type", json_object_new_int(icmp_header->type));
  json_object_object_add(jparent, "ICMP_code", json_object_new_int(icmp_header->code));
}

void handle_tcp_header(const uchar *packet, size_t pktSize, struct json_object *jparent){
  DBGPRINTF("handle_tcp_header\n");
  DBGPRINTF("packet size %d\n", pktSize);

  if(pktSize < 20) {
    DBGPRINTF("TCP packet too small : %d\n", pktSize);
    return;
  }

  tcp_header_t *tcp_header = (tcp_header_t *)packet;


  char flags[10] = {0};
  flags[0] = (tcp_header->res1 & 0b01) ? '1':'0';
  flags[1] = (tcp_header->res2 & 0b10) ? '1':'0';
  flags[2] = (tcp_header->res2 & 0b01) ? '1':'0';
  flags[3] = (tcp_header->urg) ? '1':'0';
  flags[4] = (tcp_header->ack) ? '1':'0';
  flags[5] = (tcp_header->psh) ? '1':'0';
  flags[6] = (tcp_header->rst) ? '1':'0';
  flags[7] = (tcp_header->syn) ? '1':'0';
  flags[8] = (tcp_header->fin) ? '1':'0';


  json_object_object_add(jparent, "TCP_Source_Port", json_object_new_int(ntohs(tcp_header->th_sport)));
  json_object_object_add(jparent, "TCP_Destination_Port", json_object_new_int(ntohs(tcp_header->th_dport)));
  json_object_object_add(jparent, "TCP_Seq_Number", json_object_new_int(ntohl(tcp_header->seq)));
  json_object_object_add(jparent, "TCP_Ack_Number", json_object_new_int(ntohl(tcp_header->ack_seq)));
  json_object_object_add(jparent, "TCP_Flags", json_object_new_string(flags));

}

void handle_udp_header(const uchar *packet, size_t pktSize, struct json_object *jparent){
  DBGPRINTF("handle_udp_header\n");
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

void handle_ipv6_header(const uchar *packet, size_t pktSize, struct json_object *jparent) {
  DBGPRINTF("handle_ipv6_header\n");
  DBGPRINTF("packet size %d\n", pktSize);

  if(pktSize <= 40) { /* too small for IPv6 header + data (header might be longer)*/
    DBGPRINTF("IPv6 packet too small : %d\n", pktSize);
    return;
  }

	ipv6_header_t *ipv6_header = (ipv6_header_t *)packet;

  char addrSrc[40], addrDst[40];

  inet_ntop(AF_INET6, (void *)&ipv6_header->ip6_src, addrSrc, 40);
  inet_ntop(AF_INET6, (void *)&ipv6_header->ip6_dst, addrDst, 40);

  json_object_object_add(jparent, "IP6_dest", json_object_new_string((char*)addrDst));
  json_object_object_add(jparent, "IP6_src", json_object_new_string((char*)addrSrc));
  json_object_object_add(jparent, "IP6_next_header", json_object_new_int(ipv6_header->ip6_nxt));
  json_object_object_add(jparent, "IP6_hop_limit", json_object_new_int(ipv6_header->ip6_hops));
  if (ipv6_header->ip6_nxt == 58)
  {
	handle_icmp_header(packet+sizeof(ipv6_header_t),pktSize-sizeof(ipv6_header_t),jparent);
  }

}

void handle_arp_header(const uchar *packet, size_t pktSize, struct json_object *jparent) {
  DBGPRINTF("handle_arp_header\n");
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
void handle_rarp_header(const uchar *packet, size_t pktSize, struct json_object *jparent) {
  DBGPRINTF("handle_rarp_header\n");
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
  ethProtoHandlers[ETHERTYPE_REVARP] = handle_rarp_header;
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
  ipProtoHandlers[IPPROTO_TCP] = handle_tcp_header;
  ipProtoHandlers[IPPROTO_UDP] = handle_udp_header;
}
