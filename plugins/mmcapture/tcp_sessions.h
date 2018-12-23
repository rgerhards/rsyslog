#ifndef TCP_SESSIONS_H
#define TCP_SESSIONS_H

#include <stdlib.h>

#include "rsyslog.h"
#include "packets.h"

#define TCP_PROTO 6

#define IS_TCP_FLAG(x, y) ((strchr(x, y) == NULL) ? 0 : 1)

typedef struct tcp_connection_s{
  uint16_t hPort;
  uint32_t seqNum;
  uint32_t ackNum;
}tcp_connection;

typedef struct tcp_session_s{
  tcp_connection *cCon;
  tcp_connection *sCon;
}tcp_session;

void checkTcpSessions(tcp_packet *packet);
tcp_session* createNewSession(tcp_packet* packet);
void updateSession(tcp_session* session, tcp_packet* packet);

#endif /* TCP_SESSIONS_H */
