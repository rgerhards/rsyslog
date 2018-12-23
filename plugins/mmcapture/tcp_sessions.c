#include "tcp_sessions.h"

static tcp_session* sessions[512];

void checkTcpSessions(tcp_packet *packet){
	DBGPRINTF("entering checkTcpSessions\n");
	tcp_session *session = NULL;
	int i;
	for(i = 0 ; sessions[i] != NULL ; i++){
		if(sessions[i]->cCon->hPort==packet->meta->srcPort ||
			sessions[i]->sCon->hPort==packet->meta->srcPort) {
			if(sessions[i]->cCon->hPort==packet->meta->dstPort ||
				sessions[i]->sCon->hPort==packet->meta->dstPort) {
				session = sessions[i];
				break;
			}
		}
	}

	if(session != NULL) {
		updateSession(session, packet);
	}
	else {
		session = createNewSession(packet);
		for(int i=0;i<512;i++){
			if(sessions[i] == NULL){
				DBGPRINTF("added session %d\n", i);
				sessions[i] = session;
				break;
			}
		}
	}
}

tcp_session* createNewSession(tcp_packet* packet){
	DBGPRINTF("entering createNewSession\n");
	tcp_connection* cCon = malloc(sizeof(tcp_connection));
	tcp_connection* sCon = malloc(sizeof(tcp_connection));
	tcp_session* new_session = malloc(sizeof(tcp_session));
	cCon->hPort = packet->meta->srcPort;
	cCon->seqNum = packet->meta->seqNum;
	cCon->ackNum = packet->meta->ackNum;
	sCon->hPort = packet->meta->dstPort;
	sCon->seqNum = 0;
	sCon->ackNum = (packet->meta->seqNum)+1;
	new_session->cCon = cCon;
	new_session->sCon = sCon;
	return new_session;
}

void updateSession(tcp_session* session, tcp_packet* packet){
	DBGPRINTF("entering updateSession\n");
	if(session->sCon->hPort == packet->meta->srcPort){
		DBGPRINTF("msg from server\n");
		session->cCon->ackNum += packet->pload->length;
		session->sCon->seqNum += packet->pload->length;
		if(session->sCon->seqNum == 0){
			session->sCon->seqNum = packet->meta->seqNum;
			session->cCon->ackNum = packet->meta->seqNum+1;
		}
	}
	else{
		DBGPRINTF("msg from client\n");
		session->cCon->seqNum += packet->pload->length;
		session->sCon->ackNum += packet->pload->length;
	}
}
