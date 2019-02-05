/* packets.c
 *
 * This file contains functions to parse metadata from Rsyslog packets
 * to internal 'packet' structures, defined in packets.h
 *
 * File begun on 2018-12-5
 *
 * Created by:
 *  - François Bernard (francois.bernard@isen.yncrea.fr)
 *  - Théo Bertin (theo.bertin@isen.yncrea.fr)
 *  - Tianyu Geng (tianyu.geng@isen.yncrea.fr)
 *
 * This file is part of rsyslog.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *       -or-
 *       see COPYING.ASL20 in the source distribution
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "packets.h"

/*
 *  This function recovers SMB fields from an impcap metadata json
 *
 *  It gets in parameters:
 *  - the json of impcap metadata
 *  - the tcp_packet to fill informations in
 *
 *  It returns the number of fields recovered
*/
int getSMBMetadata(struct json_object *pJson, tcp_packet *pData){
	struct json_object *obj = NULL;
	int iRet = 0;
	smb_metadata *session;

	DBGPRINTF("entered getSMBMetadata\n");

	app_header_metadata *appHdrMeta = pData->appHeader;
	assert(appHdrMeta != NULL);

	if(appHdrMeta->pHdr == NULL)
		appHdrMeta->pHdr = malloc(sizeof(smb_metadata));
	assert(appHdrMeta->pHdr != NULL);

	session = (smb_metadata *)appHdrMeta->pHdr;

	if(fjson_object_object_get_ex(pJson, "SMB_userID", &obj)) {
		session->sessID = fjson_object_get_int64(obj);
		DBGPRINTF("session ID: %llu\n", (unsigned long long)session->sessID);
		iRet++;
	}

	if(fjson_object_object_get_ex(pJson, "SMB_operation", &obj)) {
		session->opCode = fjson_object_get_int(obj);
		DBGPRINTF("opCode: %d\n", session->opCode);
		iRet++;
	}

	if(fjson_object_object_get_ex(pJson, "SMB_flags", &obj)) {
		session->flags = (char *)fjson_object_get_string(obj);
		DBGPRINTF("flags: %s\n", session->flags);
		iRet++;
	}

	if(fjson_object_object_get_ex(pJson, "SMB_seqNumber", &obj)) {
		session->seqNum = fjson_object_get_int64(obj);
		DBGPRINTF("sequence number: %llu\n", (unsigned long long)session->seqNum);
		iRet++;
	}

	if(fjson_object_object_get_ex(pJson, "SMB_processID", &obj)) {
		session->procID = fjson_object_get_int64(obj);
		DBGPRINTF("process ID: %u \n", session->procID);
		iRet++;
	}

	if(fjson_object_object_get_ex(pJson, "SMB_treeID", &obj)) {
		session->treeID = fjson_object_get_int64(obj);
		DBGPRINTF("tree ID: %u \n", session->treeID);
		iRet++;
	}
	return iRet;
}

/*
 *  This function recovers TCP fields from an impcap metadata json
 *
 *  It gets in parameters:
 *  - the json of impcap metadata
 *  - the tcp_packet to fill informations in
 *
 *  It returns the number of fields recovered
*/
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
		DBGPRINTF("seq_number: %u \n", pData->meta->seqNum);
	}

	if(fjson_object_object_get_ex(pJson, "TCP_ack_number", &obj)) {
		iRet++;
		pData->meta->ackNum = fjson_object_get_int64(obj);
		DBGPRINTF("ack_number: %u \n", pData->meta->ackNum);
	}

	if(fjson_object_object_get_ex(pJson, "net_flags", &obj)) {
		iRet++;
		pData->meta->flags = (char *)fjson_object_get_string(obj);
		DBGPRINTF("flags: %s\n", pData->meta->flags);
	}

	DBGPRINTF("returning from getTCPMetadata\n");
	return iRet;
}

/*
 *  This function creates and initialize a tcp_packet structure,
 *  first-level structures are allocated as well
 *
 *  It returns the newly allocated structure
*/
tcp_packet* createPacket(void) {
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

/*
 *  This function completely frees a tcp_packet structure
 *
 *  It gets in parameter the pointer on the structure to free
*/
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
