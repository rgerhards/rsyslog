struct tcp_connection{
        uint16_t hPort;
	uint32_t seqNum;
        uint32_t ackNum;         
}

struct tcp_session{
        struct tcp_connection* cCon;
	struct tcp_connection* sCon;
}

struct tcp_metadata{
	uint16_t srcPort:
	uint16_t dstPort;
	uint32_t seqNum;
	uint32_t ackNum;
	uint8_t flags;
}

struct tcp_payload{
	uint8_t* data;
	uint16_t length;
}

struct tcp_packet{
	struct tcp_metadata* meta;
	struct tcp_payload* pload;
}

struct tcp_session* sessions[512];

void checktcpsessions(struct tcp_packet *packet){
	tcp_session *session = NULL;
	for(int i=0;sessions[i]!=NUll;i++){
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
		updatesession(session, packet);
	}
	else {
		session = createnewsession(packet);
		for(int i=0;i<512;i++){
			if(sessions[i] == NUll){
				sessions[i] = session;
				break;
			}
		}
		
	}
}

struct tcp_session* createnewsession(struct tcp_packet* packet){
	struct tcp_connection* cCon = malloc(sizeof(struct tcp_connection));
	struct tcp_connection* sCon = malloc(sizeof(struct tcp_connection));
	struct tcp_session* new_session = malloc(sizeof(struct tcp_session));
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
	}
	else{
		session->cCon->seqNum += packet->pload->length;
		session->sCon->ackNum += packet->pload->length;
		if(session->sCon->seqNum==0){
			session->sCon->seqNum= packet->meta->seqNum;
		}
	}  
}




















