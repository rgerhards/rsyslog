#include "packets.h"

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
  DEFiRet;
  char tag[20];
  int length;

  msgConstruct(&pMsg);

	struct json_object *jchild = json_object_new_object();
	struct json_object *jparent = json_object_new_object();
	//jval = json_object_new_string((char*)"a");



  // /* ----- DEBUG REMOVE ----- */
  // /* give the raw packet to rsyslog */
  // char rawMsg[1600] = {0};
  // for(int i = 0; i < pkthdr->len; ++i) {
  //   char hexPart[4];
  //
  //   snprintf(hexPart, 4, " %02X", packet[i]);
  //   strncat(rawMsg, hexPart, 4);
  // }
  // DBGPRINTF("raw message is %s\n", rawMsg);
  // DBGPRINTF("message length is %d\n", pkthdr->len);
  // DBGPRINTF("min length is %d\n", ETHER_MIN_LEN);
  // DBGPRINTF("max length is %d\n", ETHER_MAX_LEN);
  //
  // MsgSetRawMsg(pMsg, rawMsg, 1600);
  // /* ----- DEBUG REMOVE ----- */

  if(pkthdr->len >= 40 && pkthdr->len <= 1514) {
    handle_eth_header(packet,pkthdr->len, jchild);
    json_object_object_add(jparent, "eth", jchild);
  }
  else {
    DBGPRINTF("bad packet length, discarded\n");
    msgDestruct(&pMsg);
    return;
  }

  msgAddJSON(pMsg, "!impcap", jparent, 0, 0);
  submitMsg2(pMsg);
}

void handle_eth_header(const uchar *packet, size_t pktSize, struct json_object *jparent) {
  DBGPRINTF("entered handle_eth_header\n");
  if (pktSize <= 14) {  /* too short for eth header + data */
    DBGPRINTF("ETH packet too small : %d\n", pktSize);
    return;
  }
  struct json_object *jchild = json_object_new_object();
  struct json_object *jvar;
  
  eth_header_t *eth_header = (eth_header_t *)packet;

  char *ethMacSrc = ether_ntoa((struct eth_addr *)eth_header->ether_shost);
  char *ethMacDst = ether_ntoa((struct eth_addr *)eth_header->ether_dhost);
  uint16_t ethType = ntohs(eth_header->ether_type);
  char errMsg[50];

  DBGPRINTF("MAC destination : %s\n", ethMacDst);
  DBGPRINTF("MAC source : %s\n", ethMacSrc);
  DBGPRINTF("ether type : %04X\n", ethType);

  jvar = json_object_new_string((char*)ethMacSrc);
  json_object_object_add(jparent, "ETH_src", jvar);
  jvar = json_object_new_string((char*)ethMacDst);
  json_object_object_add(jparent, "ETH_dst", jvar);
  //msgAddMetadata(pMsg, "ETH_src", ethMacSrc);
  //msgAddMetadata(pMsg, "ETH_dst", ethMacDst);

  //msgSetJSONFromVar(pMsg,"ETH_src",creatsvar_char(ethMacSrc),0);
  //msgSetJSONFromVar(pMsg,"ETH_dst",creatsvar_char(ethMacDst),0);

  switch(ethType) {
    case ETHERTYPE_IP:
	jvar = json_object_new_string((char*)"IPV4");
	json_object_object_add(jparent, "ETH_type", jvar);
        //msgAddMetadata(pMsg, "ETH_type", "IPV4");
        handle_ipv4_header((uchar *)(packet + sizeof(eth_header_t)), (pktSize - sizeof(eth_header_t)), jchild);
	json_object_object_add(jparent, "IPV4", jchild);
        break;
    case ETHERTYPE_IPV6:
	jvar = json_object_new_string((char*)"IPV6");
	json_object_object_add(jparent, "ETH_type", jvar);
        //msgAddMetadata(pMsg, "ETH_type", "IPV6");
        handle_ipv6_header((uchar *)(packet + sizeof(eth_header_t)), (pktSize - sizeof(eth_header_t)), jchild);
	json_object_object_add(jparent, "IPV6", jchild);
        break;
    case ETHERTYPE_ARP:
	jvar = json_object_new_string((char*)"ARP");
	json_object_object_add(jparent, "ETH_type", jvar);
        //msgAddMetadata(pMsg, "ETH_type", "ARP");
        handle_arp_header((uchar *)(packet + sizeof(eth_header_t)), (pktSize - sizeof(eth_header_t)), jchild);
	json_object_object_add(jparent, "ARP", jchild);
        break;
    case ETHERTYPE_REVARP:
	jvar = json_object_new_string((char*)"RARP");
	json_object_object_add(jparent, "ETH_type", jvar);
      	//msgAddMetadata(pMsg, "ETH_type", "RARP");
      	break;
    case ETHERTYPE_PUP:
	jvar = json_object_new_string((char*)"PUP");
	json_object_object_add(jparent, "ETH_type", jvar);
      	//msgAddMetadata(pMsg, "ETH_type", "PUP");
      	break;
    case ETHERTYPE_SPRITE:
	jvar = json_object_new_string((char*)"SPRITE");
	json_object_object_add(jparent, "ETH_type", jvar);
      	//msgAddMetadata(pMsg, "ETH_type", "SPRITE");
      	break;
    case ETHERTYPE_AT:
	jvar = json_object_new_string((char*)"AT");
	json_object_object_add(jparent, "ETH_type", jvar);
      	//msgAddMetadata(pMsg, "ETH_type", "AT");
      	break;
    case ETHERTYPE_AARP:
	jvar = json_object_new_string((char*)"AARP");
	json_object_object_add(jparent, "ETH_type", jvar);
      	//msgAddMetadata(pMsg, "ETH_type", "AARP");
      	break;
    case ETHERTYPE_VLAN:
	jvar = json_object_new_string((char*)"VLAN");
	json_object_object_add(jparent, "ETH_type", jvar);
      	//msgAddMetadata(pMsg, "ETH_type", "VLAN");
      	break;
    case ETHERTYPE_IPX:
	jvar = json_object_new_string((char*)"IPX");
	json_object_object_add(jparent, "ETH_type", jvar);
      	//msgAddMetadata(pMsg, "ETH_type", "IPX");
      	break;
    case ETHERTYPE_LOOPBACK:
	jvar = json_object_new_string((char*)"LOOPBACK");
	json_object_object_add(jparent, "ETH_type", jvar);
      	//msgAddMetadata(pMsg, "ETH_type", "LOOPBACK");
      	break;
    default:
      	snprintf(errMsg, 50, "ETH type unknown: 0x%X", ethType);
      	DBGPRINTF("no match to ethernet type\n");
	jvar = json_object_new_string((char*)errMsg);
	json_object_object_add(jparent, "ETH_err", jvar);
      	//msgAddMetadata(pMsg, "ETH_err", errMsg);
  }
}

void handle_ipv4_header(const uchar *packet, size_t pktSize, struct json_object *jparent) {
  struct json_object *jchild = json_object_new_object();
  struct json_object *jvar;
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

  /*switch(ipv4_header->ip_p) {
    case IPPROTO_IP:
          msgAddMetadata(pMsg, "IP_proto", "IP");
          break;
    case IPPROTO_ICMP:
          msgAddMetadata(pMsg, "IP_proto", "ICMP");
          handle_icmp_header((packet + hdrLen), (pktSize - hdrLen), pMsg);
          break;
    case IPPROTO_IGMP:
          msgAddMetadata(pMsg, "IP_proto", "IGMP");
          break;
    case IPPROTO_IPIP:
          msgAddMetadata(pMsg, "IP_proto", "IPIP");
          break;
    case IPPROTO_TCP:
          msgAddMetadata(pMsg, "IP_proto", "TCP");
          break;
    case IPPROTO_EGP:
          msgAddMetadata(pMsg, "IP_proto", "EGP");
          break;
    case IPPROTO_PUP:
          msgAddMetadata(pMsg, "IP_proto", "PUP");
          break;
    case IPPROTO_UDP:
          msgAddMetadata(pMsg, "IP_proto", "UDP");
          break;
    case IPPROTO_IDP:
          msgAddMetadata(pMsg, "IP_proto", "IDP");
          break;
    case IPPROTO_TP:
          msgAddMetadata(pMsg, "IP_proto", "TP");
          break;
    case IPPROTO_DCCP:
          msgAddMetadata(pMsg, "IP_proto", "DCCP");
          break;
    case IPPROTO_IPV6:
          msgAddMetadata(pMsg, "IP_proto", "IPV6");
          break;
    case IPPROTO_RSVP:
          msgAddMetadata(pMsg, "IP_proto", "RSVP");
          break;
    case IPPROTO_GRE:
          msgAddMetadata(pMsg, "IP_proto", "GRE");
          break;
    case IPPROTO_ESP:
          msgAddMetadata(pMsg, "IP_proto", "ESP");
          break;
    case IPPROTO_AH:
          msgAddMetadata(pMsg, "IP_proto", "AH");
          break;
    case IPPROTO_MTP:
          msgAddMetadata(pMsg, "IP_proto", "MTP");
          break;
    case IPPROTO_BEETPH:
          msgAddMetadata(pMsg, "IP_proto", "BEETPH");
          break;
    case IPPROTO_ENCAP:
          msgAddMetadata(pMsg, "IP_proto", "ENCAP");
          break;
    case IPPROTO_PIM:
          msgAddMetadata(pMsg, "IP_proto", "PIM");
          break;
    case IPPROTO_COMP:
          msgAddMetadata(pMsg, "IP_proto", "COMP");
          break;
    case IPPROTO_SCTP:
          msgAddMetadata(pMsg, "IP_proto", "SCTP");
          break;
    case IPPROTO_UDPLITE:
          msgAddMetadata(pMsg, "IP_proto", "UDPLITE");
          break;
    case IPPROTO_MPLS:
          msgAddMetadata(pMsg, "IP_proto", "MPLS");
          break;
    case IPPROTO_RAW:
          msgAddMetadata(pMsg, "IP_proto", "RAW");
          break;
    default:
          DBGPRINTF("no match to IP type\n");
  }*/

  DBGPRINTF("IP destination : %s\n", addrDst);
  DBGPRINTF("IP source : %s\n", addrSrc);
  DBGPRINTF("IHL : %s\n", hdrLenStr);

  jvar = json_object_new_string((char*)addrDst);
  json_object_object_add(jparent, "IP_dest", jvar);
  jvar = json_object_new_string((char*)addrSrc);
  json_object_object_add(jparent, "IP_src", jvar);
  jvar = json_object_new_string((char*)hdrLenStr);
  json_object_object_add(jparent, "IP_ihl", jvar);
  //msgAddMetadata(pMsg, "IP_dest", addrDst);
  //msgAddMetadata(pMsg, "IP_src", addrSrc);
  //msgAddMetadata(pMsg, "IP_ihl", hdrLenStr);
}

void handle_ipv6_header(const uchar *packet, size_t pktSize, struct json_object *jparent) {
  struct json_object *jchild = json_object_new_object();
  struct json_object *jvar;
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

  jvar = json_object_new_string((char*)addrDst);
  json_object_object_add(jparent, "IP6_dest", jvar);
  jvar = json_object_new_string((char*)addrSrc);
  json_object_object_add(jparent, "IP6_src", jvar);
  //msgAddMetadata(pMsg, "IP6_dest", addrDst);
  //msgAddMetadata(pMsg, "IP6_src", addrSrc);
}

void handle_arp_header(const uchar *packet, size_t pktSize, struct json_object *jparent) {
  struct json_object *jchild = json_object_new_object();
  struct json_object *jvar;
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

  jvar = json_object_new_string((char*)hwType);
  json_object_object_add(jparent, "ARP_hwType", jvar);
  jvar = json_object_new_string((char*)pType);
  json_object_object_add(jparent, "ARP_pType", jvar);
  jvar = json_object_new_string((char*)op);
  json_object_object_add(jparent, "ARP_op", jvar);
  //msgAddMetadata(pMsg, "ARP_hwType", hwType);
  //msgAddMetadata(pMsg, "ARP_pType", pType);
  //msgAddMetadata(pMsg, "ARP_op", op);

  if(ntohs(arp_header->arp_hrd) == 1) { /* ethernet addresses */
    char *hwAddrSrc = ether_ntoa((struct eth_addr *)arp_header->arp_sha);
    char *hwAddrDst = ether_ntoa((struct eth_addr *)arp_header->arp_tha);

    jvar = json_object_new_string((char*)hwAddrSrc);
    json_object_object_add(jparent, "ARP_hwSrc", jvar);
    jvar = json_object_new_string((char*)hwAddrDst);
    json_object_object_add(jparent, "ARP_hwDst", jvar);
    //msgAddMetadata(pMsg, "ARP_hwSrc", hwAddrSrc);
    //msgAddMetadata(pMsg, "ARP_hwDst", hwAddrDst);
  }

  if(ntohs(arp_header->arp_pro) == ETHERTYPE_IP) {
    inet_ntop(AF_INET, (void *)&arp_header->arp_spa, pAddrSrc, 20);
    inet_ntop(AF_INET, (void *)&arp_header->arp_tpa, pAddrDst, 20);

    jvar = json_object_new_string((char*)pAddrSrc);
    json_object_object_add(jparent, "ARP_pSrc", jvar);
    jvar = json_object_new_string((char*)pAddrDst);
    json_object_object_add(jparent, "ARP_pDst", jvar);
    //msgAddMetadata(pMsg, "ARP_pSrc", pAddrSrc);
    //msgAddMetadata(pMsg, "ARP_pDst", pAddrDst);
  }
}
