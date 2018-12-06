#include "parser.h"

void tcp_parse(const uchar *packet, size_t pktSize, struct json_object *jparent){
  DBGPRINTF("tcp_parse\n");
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


  json_object_object_add(jparent, "net_src_port", json_object_new_int(ntohs(tcp_header->th_sport)));
  json_object_object_add(jparent, "net_dst_port", json_object_new_int(ntohs(tcp_header->th_dport)));
  json_object_object_add(jparent, "TCP_Seq_Number", json_object_new_int(ntohl(tcp_header->seq)));
  json_object_object_add(jparent, "TCP_Ack_Number", json_object_new_int(ntohl(tcp_header->ack_seq)));
  json_object_object_add(jparent, "net_flags", json_object_new_string(flags));

}
