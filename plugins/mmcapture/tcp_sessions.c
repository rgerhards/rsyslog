#include "tcp_sessions.h"

static tcp_session* sessions[512];

void checkTcpSessions(tcp_packet *packet){
	tcp_session *session = NULL;
	for(int i=0;sessions[i]!=NULL;i++){
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
				sessions[i] = session;
				break;
			}
		}

	}
}

tcp_session* createNewSession(tcp_packet* packet){
	tcp_connection* cCon = malloc(sizeof(tcp_connection));
	tcp_connection* sCon = malloc(sizeof(tcp_connection));
	tcp_session* new_session = malloc(sizeof(tcp_session));
	cCon->hPort = packet->meta->srcPort;
	cCon->seqNum = packet->meta->seqNum;
	cCon->ackNum = packet->meta->ackNum;
	sCon->hPort = packet->meta->dstPort;
	sCon->seqNum = 0;
	sCon->ackNum = (packet->meta->seqNum)+1;
	new_session->cCon=cCon;
	new_session->sCon=sCon;
	return new_session;
}

void updatesession(struct tcp_session* session, struct tcp_packet* packet){
	if(session->sCon->hPort==packet->meta->srcPort){
		session->cCon->ackNum += packet->pload->length;
		session->sCon->seqNum += packet->pload->length;
    if(session->sCon->seqNum==0){
			session->sCon->seqNum= packet->meta->seqNum;
      session->cCon->ackNum= packet->meta->seqNum+1;
		}
	}
	else{
		session->cCon->seqNum += packet->pload->length;
		session->sCon->ackNum += packet->pload->length;
	}
}
