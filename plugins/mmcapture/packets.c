#include "packets.h"

int getSMBMetadata(struct json_object *pJson, tcp_packet *pData){
  struct json_object *obj = NULL;
  smb_metadata *session;

  DBGPRINTF("entered getSMBMetadata\n");

  app_header_metadata *appHdrMeta = pData->appHeader;
  assert(appHdrMeta != NULL);

  session = (smb_metadata *)appHdrMeta->pHdr;
  if(session == NULL)
    session = malloc(sizeof(smb_metadata));

  if(fjson_object_object_get_ex(pJson, "SMB_userID", &obj)) {
    session->sessID = fjson_object_get_int64(obj);
    DBGPRINTF("session ID: %lu\n", session->sessID);
  }

  if(fjson_object_object_get_ex(pJson, "SMB_operation", &obj)) {
    session->opCode = fjson_object_get_int(obj);
    DBGPRINTF("opCode: %d\n", session->opCode);
  }

  if(fjson_object_object_get_ex(pJson, "SMB_flags", &obj)) {
    session->flags = fjson_object_get_string(obj);
    DBGPRINTF("flags: %s\n", session->flags);
  }

  if(fjson_object_object_get_ex(pJson, "SMB_seqNumber", &obj)) {
    session->seqNum = fjson_object_get_int64(obj);
    DBGPRINTF("sequence number: %lu\n", session->seqNum);
  }

  if(fjson_object_object_get_ex(pJson, "SMB_processID", &obj)) {
    session->procID = fjson_object_get_int64(obj);
    DBGPRINTF("process ID: %lu\n", session->procID);
  }

  if(fjson_object_object_get_ex(pJson, "SMB_treeID", &obj)) {
    session->treeID = fjson_object_get_int64(obj);
    DBGPRINTF("tree ID: %lu\n", session->treeID);
  }
}

int getTCPMetadata(struct json_object *pJson, tcp_packet *pData) {
	int iRet = 0;
	struct json_object *obj = NULL;

	assert(pData->meta != NULL);

	if(fjson_object_object_get_ex(pJson, "net_src_port", &obj)) {
		iRet++;
		pData->meta->srcPort = fjson_object_get_int(obj);
		DBGPRINTF("source_port: %u\n", pData->meta->srcPort);
    if(pData->meta->srcPort == SMB_PORTS){
      iRet += getSMBMetadata(pJson, pData);
    }
	}

	if(fjson_object_object_get_ex(pJson, "net_dst_port", &obj)) {
		iRet++;
		pData->meta->dstPort = fjson_object_get_int(obj);
		DBGPRINTF("dest_port: %u\n", pData->meta->dstPort);
    if(pData->meta->srcPort == SMB_PORTS){
      iRet += getSMBMetadata(pJson, pData);
    }
	}

	if(fjson_object_object_get_ex(pJson, "TCP_seq_number", &obj)) {
		iRet++;
		pData->meta->seqNum = fjson_object_get_int64(obj);
		DBGPRINTF("seq_number: %lu\n", pData->meta->seqNum);
	}

	if(fjson_object_object_get_ex(pJson, "TCP_ack_number", &obj)) {
		iRet++;
		pData->meta->ackNum = fjson_object_get_int64(obj);
		DBGPRINTF("ack_number: %lu\n", pData->meta->ackNum);
	}

	if(fjson_object_object_get_ex(pJson, "net_flags", &obj)) {
		iRet++;
		pData->meta->flags = fjson_object_get_string(obj);
		DBGPRINTF("flags: %s\n", pData->meta->flags);
	}

  DBGPRINTF("returning from getTCPMetadata\n");
	return iRet;
}

tcp_packet* createPacket() {
  DBGPRINTF("creating packet\n");
  tcp_packet *pPacket = NULL;

  if((pPacket = malloc(sizeof(tcp_packet))) != NULL) {
    if((pPacket->meta = malloc(sizeof(tcp_metadata))) != NULL) {
      pPacket->meta->flags = NULL;
    }

    if((pPacket->pload = malloc(sizeof(tcp_payload))) != NULL) {
      pPacket->pload->data = NULL;
    }

    if((pPacket->appHeader = malloc(sizeof(app_header_metadata))) != NULL) {
      pPacket->appHeader->pHdr = NULL;
    }
  }

  return pPacket;
}

void freePacket(tcp_packet *pPacket) {
  DBGPRINTF("freeing packet\n");
	if(pPacket != NULL) {
    DBGPRINTF("pPacket not null\n");

		if(pPacket->appHeader != NULL) {
      DBGPRINTF("appHeader not null\n");

			if(pPacket->appHeader->pHdr != NULL) {
        DBGPRINTF("pHdr not null\n");

				switch(pPacket->appHeader->type) {
					case HEADER_TYPE_FTP:
							break;
					case HEADER_TYPE_HTTP:
							break;
					case HEADER_TYPE_SMB:
              DBGPRINTF("appHeader is SMB\n");

							free((smb_metadata *)pPacket->appHeader->pHdr);
							break;
					default:
							break;
				}
			}
			free(pPacket->appHeader);
      DBGPRINTF("freed appHeader\n");

		}
		if(pPacket->pload != NULL) {
      DBGPRINTF("pload not null\n");

			free(pPacket->pload->data);
			free(pPacket->pload);
      DBGPRINTF("freed pload\n");

		}
		if(pPacket->meta != NULL) {
      DBGPRINTF("meta not null\n");

			free(pPacket->meta);
      DBGPRINTF("freed meta\n");

		}
		free(pPacket);
    DBGPRINTF("freed packet\n");

	}
}
