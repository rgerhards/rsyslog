#include "parser.h"

struct tcp_header_s {
  uint16_t srcPort;
  uint16_t dstPort;
  uint32_t seq;
  uint32_t ack;
  uint8_t dor;
  uint8_t flags;
  uint16_t windowSize;
  uint16_t checksum;
  uint16_t urgPointer;
  uint8_t options[];
};

typedef struct tcp_header_s tcp_header_t;

static char flagCodes[10] = "FSRPAUECN";

void tcp_parse(const uchar *packet, size_t pktSize, struct json_object *jparent){
  DBGPRINTF("tcp_parse\n");
  DBGPRINTF("packet size %d\n", pktSize);

  if(pktSize < 20) {
    DBGPRINTF("TCP packet too small : %d\n", pktSize);
    return;
  }

  tcp_header_t *tcp_header = (tcp_header_t *)packet;

  uint8_t i, pos = 0;
  char flags[10] = {0};

  for(i=0 ; i<8 ; ++i) {
    if(tcp_header->flags & (0x01<<i))
      flags[pos++] = flagCodes[i];
  }
  if(tcp_header->dor & 0x01)
    flags[pos++] = flagCodes[9];

  json_object_object_add(jparent, "net_src_port", json_object_new_int(ntohs(tcp_header->srcPort)));
  json_object_object_add(jparent, "net_dst_port", json_object_new_int(ntohs(tcp_header->dstPort)));
  json_object_object_add(jparent, "TCP_Seq_Number", json_object_new_int64(ntohl(tcp_header->seq)));
  json_object_object_add(jparent, "TCP_Ack_Number", json_object_new_int64(ntohl(tcp_header->ack)));
  json_object_object_add(jparent, "TCP_data_offset", json_object_new_int((tcp_header->dor&0xF0)>>4));
  json_object_object_add(jparent, "net_flags", json_object_new_string(flags));

}
