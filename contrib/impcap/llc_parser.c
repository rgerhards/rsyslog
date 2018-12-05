#include "parser.h"

void llc_parse(const uchar *packet, size_t pktSize, struct json_object *jparent) {
  DBGPRINTF("entered llc_parse\n");
  DBGPRINTF("packet size %d\n", pktSize);

  if (pktSize < 3) {  /* too short for llc header */
    DBGPRINTF("LLC packet too small : %d\n", pktSize);
    return;
  }

  uint8_t dsapField, dsap, ssapField, ssap;
  uint16_t ctrl;
  uint8_t headerLen;

  dsapField = (uint8_t) packet[0];
  ssapField = (uint8_t) packet[1];
  DBGPRINTF("dsapField : %02X\n", dsapField);
  DBGPRINTF("ssapField : %02X\n", ssapField);

  if(dsapField == 0xff && ssapField == 0xff) {
    /* this is an IPX packet, without LLC */
    ipx_parse(packet, pktSize, jparent);
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
    uint32_t orgCode =  packet[headerLen]<<16 |
                        packet[headerLen+1]<<8 |
                        packet[headerLen+2];
    uint16_t ethType = packet[headerLen+3]<<8 |
                        packet[headerLen+4];
    json_object_object_add(jparent, "SNAP_oui", json_object_new_int(orgCode));
    json_object_object_add(jparent, "SNAP_ethType", json_object_new_int(ethType));
    (*ethProtoHandlers[ethType])(packet + headerLen, pktSize - headerLen, jparent);
    return;
  }
  if(dsap == 0x06 && ssap == 0x06 && ctrl == 0x03) {
    /* IPv4 header */
    ipv4_parse(packet + headerLen, pktSize - headerLen, jparent);
    return;
  }
  if(dsap == 0xe0 && ssap == 0xe0 && ctrl == 0x03) {
    /* IPX packet with LLC */
    ipx_parse(packet + headerLen, pktSize - headerLen, jparent);
  }
}
