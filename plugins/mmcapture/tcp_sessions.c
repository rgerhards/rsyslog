#include "tcp_sessions.h"

static tcp_session_list *sessions = NULL;

tcp_session_list* initTcp(){
	DBGPRINTF("initializing TCP sessions list\n");

	if(sessions == NULL) {
		sessions = malloc(sizeof(tcp_session_list));
		if(sessions != NULL) {
			sessions->activeSessions = 0;
			sessions->head = NULL;
			sessions->tail = NULL;
		}
	}
	return sessions;
}

uint8_t addSession(tcp_session *session) {
	DBGPRINTF("entering addSession\n");

	if(session == NULL)
		return 0;

	if(sessions->activeSessions == MAX_TCP_SESSIONS)
		return 0;

	if(sessions->activeSessions == 0) {
		sessions->head = session;
		sessions->tail = session;
	}
	else {
		sessions->tail->nextSession = session;
		sessions->tail = session;
	}

	(sessions->activeSessions)++;
	return 1;
}

uint8_t removeSession(tcp_session *session) {
	DBGPRINTF("entering removeSession\n");
	if(session == NULL)
		return 0;

	 if(session->prevSession != NULL) {
		 session->prevSession->nextSession = session->nextSession;
	 }
	 else {
		 sessions->head = session->nextSession;
	 }

	 if(session->nextSession != NULL) {
		 session->nextSession->prevSession = session->prevSession;
	 }
	 else {
		 sessions->tail = session->prevSession;
	 }

	 (sessions->activeSessions)--;
	 return 1;
}

void checkTcpSessions(tcp_packet *packet){
	DBGPRINTF("entering checkTcpSessions\n");
	tcp_session *session;
	for(session = sessions->head ; session != NULL ; session = session->nextSession){
		if(session->cCon->hPort==packet->meta->srcPort ||
			session->sCon->hPort==packet->meta->srcPort) {
			if(session->cCon->hPort==packet->meta->dstPort ||
				session->sCon->hPort==packet->meta->dstPort) {
				break;
			}
		}
	}

	if(session != NULL) {
		updateSession(session, packet);
	}
	else if(HAS_TCP_FLAG(packet->meta->flags, 'S')){
		session = createNewSession(packet);
		addSession(session);
	}

	dbgPrintSessionsStats();
}

void dbgPrintSessionsStats() {
	tcp_session *session;
	DBGPRINTF("\ntcp sessions status:\n");
	DBGPRINTF("number of active sessions %u\n", sessions->activeSessions);

	for(session = sessions->head; session != NULL; session = session->nextSession) {
		DBGPRINTF("client port %u\n", session->cCon->hPort);
		DBGPRINTF("\tclient seq %u\n", session->cCon->seqNum);
		DBGPRINTF("\tclient ack %u\n", session->cCon->ackNum);
		DBGPRINTF("server port %u\n", session->sCon->hPort);
		DBGPRINTF("\tserver seq %u\n", session->sCon->seqNum);
		DBGPRINTF("\tserver ack %u\n\n", session->sCon->ackNum);
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
	new_session->prevSession = NULL;
	new_session->nextSession = NULL;
	return new_session;
}

uint8_t freeSession(tcp_session *session) {
	DBGPRINTF("entering freeSession\n");

	if(session != NULL) {
		if(session->cCon != NULL)
			free(session->cCon);
		if(session->sCon != NULL)
			free(session->sCon);
		free(session);
	}
}

void updateSession(tcp_session* session, tcp_packet* packet){
	DBGPRINTF("entering updateSession\n");

	if(HAS_TCP_FLAG(packet->meta->flags, 'R') || HAS_TCP_FLAG(packet->meta->flags, 'F')) {
		DBGPRINTF("reset or end of TCP session\n");
		removeSession(session);
		freeSession(session);
		return;
	}

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
