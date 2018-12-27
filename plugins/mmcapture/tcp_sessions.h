#ifndef TCP_SESSIONS_H
#define TCP_SESSIONS_H

#include <stdlib.h>

#include "rsyslog.h"
#include "packets.h"

#define MAX_TCP_SESSIONS 512
#define TCP_PROTO 6

#define HAS_TCP_FLAG(flags, flag) ((strchr(flags, flag) == NULL) ? 0 : 1)

typedef struct tcp_connection_s{
  uint16_t hPort;
  uint32_t seqNum;
  uint32_t ackNum;
}tcp_connection;

typedef struct tcp_session_s{
  struct tcp_session_s *prevSession;
  tcp_connection *cCon;
  tcp_connection *sCon;
  struct tcp_session_s *nextSession;
}tcp_session;

typedef struct tcp_session_list_s{
  uint32_t activeSessions;
  tcp_session *head;
  tcp_session *tail;
}tcp_session_list;

tcp_session_list* initTcp();
uint8_t addSession(tcp_session *session);
uint8_t removeSession(tcp_session *session);
void checkTcpSessions(tcp_packet *packet);
tcp_session* createNewSession(tcp_packet* packet);
void updateSession(tcp_session* session, tcp_packet* packet);

void dbgPrintSessionsStats();

#endif /* TCP_SESSIONS_H */
