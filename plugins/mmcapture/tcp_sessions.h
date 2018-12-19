#include <stdlib.h>
#include "rsyslog.h"

#ifndef TCP_SESSIONS_H
#define TCP_SESSIONS_H

#define TCP_PROTO 6

typedef struct tcp_connection_s{
  uint16_t hPort;
  uint32_t seqNum;
  uint32_t ackNum;
}tcp_connection;

typedef struct tcp_session_s{
  tcp_connection* cCon;
  tcp_connection* sCon;
}tcp_session;

typedef struct tcp_metadata_s{
  uint16_t srcPort;
  uint16_t dstPort;
  uint32_t seqNum;
  uint32_t ackNum;
  char* flags;
}tcp_metadata;

typedef struct tcp_payload_s{
  uint8_t* data;
  uint16_t length;
}tcp_payload;

typedef struct tcp_packet_s{
  tcp_metadata* meta;
  tcp_payload* pload;
}tcp_packet;

void checkTcpSessions(tcp_packet *packet);
tcp_session* createNewSession(tcp_packet* packet);
void updateSession(tcp_session* session, tcp_packet* packet);

#endif /* TCP_SESSIONS_H */
