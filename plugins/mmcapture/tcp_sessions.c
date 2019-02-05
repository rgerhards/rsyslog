/* tcp_sessions.c
 *
 * This file contains functions to handle TCP sessions
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

#include "tcp_sessions.h"

static tcp_session_list *sessions = NULL;

/*
 *	Initializes the linked list to contain TCP sessions
*/
tcp_session_list* initTcp(void){
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

/*
 *	Initializes the linked list to contain TCP sessions
*/
tcp_session_list* destroyTcp(void){
	DBGPRINTF("initializing TCP sessions list\n");

	tcp_session *session = NULL;

	for( session=sessions->tail ; session != sessions->head ; session=session->prevSession ) {
		if( session != NULL ) {
			removeSession(session);
			freeSession(session);
		}
	}
	session = sessions->head;
	removeSession(session);
	freeSession(session);
	sessions->activeSessions = 0;
	sessions->head = NULL;
	sessions->tail = NULL;
	free(sessions);
	sessions = NULL;
	return sessions;
}

/*
 *	Adds a session to the global linked list
 *
 *	Gets the pointer on the created tcp_session
 *
 *	Doesn't add the session if MAX_TCP_SESSIONS
 *	is reached
*/
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

/*
 *	Removes a session from the global linked list
 *
 *	It gets in parameter the session to remove
 *
 *	the session must be in the linked list,
 *	or the behaviour will be undetermined
*/
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

/*
 *	Compares a tcp_packet to the existing sessions,
 *	if the session exists (defined by source and destination ports)
 *	it is updated, otherwise it is created
 *
 *	Get as parameter a pointer on a tcp_packet
*/
void checkTcpSessions(tcp_packet *packet){
	DBGPRINTF("entering checkTcpSessions\n");
	tcp_session *session = NULL;

	/* search for an existing session with same ports involved */
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
	else if(HAS_TCP_FLAG(packet->meta->flags, 'S')){	/* if the TCP packet has a SYN flag */
		session = createNewSession(packet);
		addSession(session);
	}

	dbgPrintSessionsStats();
}

/*
 *	Prints information about all the active sessions in the linked list
 *
 *	**TODO** This is a debug function and should be removed for production
*/
void dbgPrintSessionsStats(void) {
	tcp_session *session = NULL;
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

/*
 *	Creates a new session from a tcp_packet
 *
 *	Get a pointer on a tcp_packet structure
 *
 *	Returns a pointer on a tcp_session structure,
 *	this session is not added to the global linked list
*/
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

/*
 *	Frees completely a tcp_session
 *
 *	Gets in parameter the pointer on the tcp_session to free
*/
void freeSession(tcp_session *session) {
	DBGPRINTF("entering freeSession\n");

	if(session != NULL) {
		if(session->cCon != NULL)
			free(session->cCon);
		if(session->sCon != NULL)
			free(session->sCon);
		free(session);
	}
}

/*
 *	Updates a tcp session with the information contained in a packet
 *
 *	Get in parameters:
 *		-	a pointer on the tcp_session to update
 *		-	a pointer on the tcp_packet
*/
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
