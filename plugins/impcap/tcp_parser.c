#include "parser.h"

#define SMB_PORT 445
#define HTTP_PORT 80
#define FTP_PORT 21
#define FTP_PORT_DATA 20

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

data_ret_t* tcp_parse(const uchar *packet, int pktSize, struct json_object *jparent){
  DBGPRINTF("tcp_parse\n");
  DBGPRINTF("packet size %d\n", pktSize);

  if(pktSize < 20) {
    DBGPRINTF("TCP packet too small : %d\n", pktSize);
    RETURN_DATA_AFTER(0)
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

  uint16_t srcPort = ntohs(tcp_header->srcPort);
  uint16_t dstPort = ntohs(tcp_header->dstPort);
  DBGPRINTF("TCP dst port : %d\n", dstPort);
  uint8_t headerLength = (tcp_header->dor&0xF0)>>2; //>>4 to offset and <<2 to get offset as bytes

  json_object_object_add(jparent, "net_src_port", json_object_new_int(srcPort));
  json_object_object_add(jparent, "net_dst_port", json_object_new_int(dstPort));
  json_object_object_add(jparent, "TCP_seq_number", json_object_new_int64(ntohl(tcp_header->seq)));
  json_object_object_add(jparent, "TCP_ack_number", json_object_new_int64(ntohl(tcp_header->ack)));
  //json_object_object_add(jparent, "TCP_data_offset", json_object_new_int(headerLength));
  json_object_object_add(jparent, "TCP_data_length", json_object_new_int(pktSize-headerLength));
  json_object_object_add(jparent, "net_flags", json_object_new_string(flags));

  if(srcPort == SMB_PORT || dstPort == SMB_PORT) {
    return smb_parse(packet + headerLength, pktSize - headerLength, jparent);
  }
  if(srcPort == FTP_PORT || dstPort == FTP_PORT || srcPort == FTP_PORT_DATA || dstPort == FTP_PORT_DATA) {
    return ftp_parse(packet + headerLength, pktSize - headerLength, jparent);
  }
  if(srcPort == HTTP_PORT || dstPort == HTTP_PORT){
    http_parse(packet + headerLength, pktSize - headerLength, jparent);
  }
  DBGPRINTF("tcp return after 20\n");
  RETURN_DATA_AFTER(headerLength)
}
