#!/bin/bash
# Test imptcp default MaxSessions behavior
# added 2026-04-16 by AI-Agent
#
# This file is part of the rsyslog project, released  under GPLv3
. ${srcdir:=.}/diag.sh init
skip_platform "FreeBSD"  "This test currently does not work on FreeBSD"
export NUMMESSAGES=500

DEFAULT_MAXSESSIONS=200
CONNECTIONS=220
EXPECTED_DROPS=$((CONNECTIONS - DEFAULT_MAXSESSIONS))

EXPECTED_STR='too many tcp sessions - dropping incoming request'
wait_too_many_sessions()
{
  test "$(grep "$EXPECTED_STR" "$RSYSLOG_OUT_LOG" | wc -l)" = "$EXPECTED_DROPS"
}

export QUEUE_EMPTY_CHECK_FUNC=wait_too_many_sessions
generate_conf
add_conf '
$MaxMessageSize 10k

module(load="../plugins/imptcp/.libs/imptcp")
input(type="imptcp" port="0" listenPortFileName="'$RSYSLOG_DYNNAME'.tcpflood_port")
action(type="omfile" file=`echo $RSYSLOG_OUT_LOG`)

$template outfmt,"%msg:F,58:2%,%msg:F,58:3%,%msg:F,58:4%\n"
$OMFileFlushInterval 2
$OMFileIOBufferSize 256k
'
startup

tcpflood -c$CONNECTIONS -m$NUMMESSAGES -r -d100 -P129 -A
shutdown_when_empty
wait_shutdown

content_count_check "$EXPECTED_STR" $EXPECTED_DROPS

exit_test
