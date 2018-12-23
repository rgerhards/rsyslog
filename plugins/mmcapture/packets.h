#ifndef PACKETS_H
#define PACKETS_H

#include <stdlib.h>
#include <json.h>

#include "rsyslog.h"

#define SMB_PORT1 139
#define SMB_PORT2 445
#define SMB_PORTS (SMB_PORT1 || SMB_PORT2)

typedef struct tcp_metadata_s{
  uint16_t srcPort;
  uint16_t dstPort;
  uint32_t seqNum;
  uint32_t ackNum;
  char *flags;
}tcp_metadata;

typedef struct app_header_metadata_s{
  uint8_t type;
    #define HEADER_TYPE_FTP   1
    #define HEADER_TYPE_HTTP  2
    #define HEADER_TYPE_SMB   3
  void *pHdr;
}app_header_metadata;

typedef struct smb_metadata_s {
  uint64_t sessID;
  uint16_t opCode;
  char *flags;
  uint64_t seqNum;
  uint32_t procID;
  uint32_t treeID;
}smb_metadata;

typedef struct tcp_payload_s{
  uint8_t *data;
  uint16_t length;
}tcp_payload;

typedef struct tcp_packet_s{
  tcp_metadata *meta;
  tcp_payload *pload;
  app_header_metadata *appHeader;
}tcp_packet;

int getTCPMetadata(struct json_object *pJson, tcp_packet *pData);
int getSMBMetadata(struct json_object *pJson, tcp_packet *pData);
tcp_packet* createPacket();
void freePacket(tcp_packet *pPacket);

#endif /* PACKETS_H */
