#!/bin/bash
# Ensure malformed stream-compressed input is rejected and the session is closed.
. ${srcdir:=.}/diag.sh init
check_command_available python3

RSYSLOGD_LOG="${RSYSLOG_DYNNAME}.rsyslogd.log"

generate_conf
add_conf '
module(load="../plugins/imptcp/.libs/imptcp")
input(type="imptcp" port="0" listenPortFileName="'$RSYSLOG_DYNNAME'.tcpflood_port" compression.mode="stream:always")

template(name="outfmt" type="string" string="%msg%\n")
:msg, contains, "msgnum:" action(type="omfile" file=`echo $RSYSLOG_OUT_LOG` template="outfmt")
'

: > "$RSYSLOGD_LOG"
export RS_REDIR=">>\"$RSYSLOGD_LOG\" 2>&1"
startup
assign_tcpflood_port $RSYSLOG_DYNNAME.tcpflood_port

python3 - <<'PY' "$TCPFLOOD_PORT"
import socket
import sys

sock = socket.create_connection(("127.0.0.1", int(sys.argv[1])))
sock.sendall(b"not-a-valid-zlib-stream")
sock.shutdown(socket.SHUT_WR)
sock.close()
PY

shutdown_when_empty
wait_shutdown
unset RS_REDIR

if [ -e "$RSYSLOG_OUT_LOG" ] && [ -s "$RSYSLOG_OUT_LOG" ]; then
    echo "unexpected message output for malformed compressed stream"
    cat "$RSYSLOG_OUT_LOG"
    exit 1
fi

content_check 'invalid compressed stream from remote peer localhost[127.0.0.1]: inflate() returned' "$RSYSLOGD_LOG"
content_check 'error processing data from remote peer localhost[127.0.0.1]; closing session' "$RSYSLOGD_LOG"
exit_test
