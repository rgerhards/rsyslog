#include "parser.h"

/* SMB2 opCodes */
#define SMB2_NEGOTIATE        0x00
#define SMB2_SESSIONSET       0x01
#define SMB2_SESSIONLOGOFF    0x02
#define SMB2_TREECONNECT      0x03
#define SMB2_TREEDISCONNECT   0x04
#define SMB2_CREATE           0x05
#define SMB2_CLOSE            0x06
#define SMB2_FLUSH            0x07
#define SMB2_READ             0x08
#define SMB2_WRITE            0x09
#define SMB2_LOCK             0x0a
#define SMB2_IOCTL            0x0b
#define SMB2_CANCEL           0x0c
#define SMB2_KEEPALIVE        0x0d
#define SMB2_FIND             0x0e
#define SMB2_NOTIFY           0x0f
#define SMB2_GETINFO          0x10
#define SMB2_SETINFO          0x11
#define SMB2_BREAK            0x12

struct smb_header_s {
  uint32_t version;
  uint16_t headerLength;
  uint16_t padding1;
  uint32_t ntStatus;
  uint16_t opCode;
  uint16_t padding2;
  uint32_t flags;
  uint32_t chainOffset;
  uint32_t comSeqNumber[2];
  uint32_t processID;
  uint32_t treeID;
  uint32_t userID[2];
  uint32_t signature[4];
};

typedef struct smb_header_s smb_header_t;

static char flagCodes[5] = "RPCS";

void smb_parse(const uchar *packet, size_t pktSize, struct json_object *jparent) {
  DBGPRINTF("smb_parse\n");
  DBGPRINTF("packet size %d\n", pktSize);

  while((int)pktSize > 0) {
    /* don't check packet[0] to include SMB version byte at the beginning */
    if(packet[1] == 'S') {
      if(packet[2] == 'M') {
        if(packet[3] == 'B') {
          break;
        }
      }
    }
    packet++ , pktSize--;
  }

  if((int)pktSize < 64) {
    DBGPRINTF("SMB packet too small : %d\n", pktSize);
    return;
  }

  smb_header_t *smb_header = (smb_header_t *)packet;
  char flags[5] = {0};
  uint64_t seqNum, userID;
  uint8_t version;

  version = (smb_header->version == 0xFF) ? 1 : 2;
  seqNum = smb_header->comSeqNumber[0] | smb_header->comSeqNumber[1] << 16;
  userID = smb_header->userID[0] | smb_header->userID[1] << 16;

  uint8_t i, pos = 0;
  for(i = 0; i < 4; ++i) {
    if(smb_header->flags & (0x01<<i))
      flags[pos++] = flagCodes[i];
  }

  json_object_object_add(jparent, "SMB_version", json_object_new_int(version));
  json_object_object_add(jparent, "SMB_NTstatus", json_object_new_int64(smb_header->ntStatus));
  json_object_object_add(jparent, "SMB_operation", json_object_new_int(smb_header->opCode));
  json_object_object_add(jparent, "SMB_flags", json_object_new_string(flags));
  json_object_object_add(jparent, "SMB_seqNumber", json_object_new_int64(seqNum));
  json_object_object_add(jparent, "SMB_processID", json_object_new_int64(smb_header->processID));
  json_object_object_add(jparent, "SMB_treeID", json_object_new_int64(smb_header->treeID));
  json_object_object_add(jparent, "SMB_userID", json_object_new_int64(userID));


  DBGPRINTF("smb_parse, version: %X\n", smb_header->version);
  DBGPRINTF("smb_parse, header length: %d\n", smb_header->headerLength);
  DBGPRINTF("smb_parse, NT status: %X\n", smb_header->ntStatus);
  DBGPRINTF("smb_parse, opcode: %X\n", smb_header->opCode);
  DBGPRINTF("smb_parse, flags: %s\n", flags);
  DBGPRINTF("smb_parse, chain offset: %d\n", smb_header->chainOffset);
  DBGPRINTF("smb_parse, command sequence number: %X\n", seqNum);
  DBGPRINTF("smb_parse, process ID: %X\n", smb_header->processID);
  DBGPRINTF("smb_parse, treeID: %X\n", smb_header->treeID);
  DBGPRINTF("smb_parse, userID: %X\n", userID);
  DBGPRINTF("smb_parse, signature: %X %X %X %X\n",
                              smb_header->signature[0],
                              smb_header->signature[1],
                              smb_header->signature[2],
                              smb_header->signature[3]);


}
