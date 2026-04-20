#!/bin/bash
# Ensure a single recv() cannot expand into unbounded stream-compressed work.
. ${srcdir:=.}/diag.sh init
check_command_available python3

RSYSLOGD_LOG="${RSYSLOG_DYNNAME}.rsyslogd.log"

generate_conf
add_conf '
$MaxMessageSize 32m

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
import zlib

payload = b"A" * (17 * 1024 * 1024)
stream = zlib.compressobj(level=9)
compressed = stream.compress(payload) + stream.flush()

sock = socket.create_connection(("127.0.0.1", int(sys.argv[1])))
sock.sendall(compressed)
sock.shutdown(socket.SHUT_WR)
sock.close()
PY

shutdown_when_empty
wait_shutdown
unset RS_REDIR

if [ -e "$RSYSLOG_OUT_LOG" ] && [ -s "$RSYSLOG_OUT_LOG" ]; then
    echo "unexpected message output for expansion-limited compressed stream"
    cat "$RSYSLOG_OUT_LOG"
    exit 1
fi

content_check 'stream-compressed session from remote peer localhost[127.0.0.1] exceeded 16777216 decompressed bytes in a single recv() call; closing session' "$RSYSLOGD_LOG"
content_check 'error processing data from remote peer localhost[127.0.0.1]; closing session' "$RSYSLOGD_LOG"
exit_test
