#!/bin/bash
# Validate stream:always compression end-to-end with omfwd -> imptcp.
. ${srcdir:=.}/diag.sh init
export NUMMESSAGES=20000
export QUEUE_EMPTY_CHECK_FUNC=wait_file_lines

export RSYSLOG_DEBUGLOG="log"
generate_conf
add_conf '
module(load="../plugins/imptcp/.libs/imptcp")
input(type="imptcp" port="0" listenPortFileName="'$RSYSLOG_DYNNAME'.tcpflood_port" compression.mode="stream:always")

$template outfmt,"%msg:F,58:2%\n"
$template dynfile,"'$RSYSLOG_OUT_LOG'"
:msg, contains, "msgnum:" ?dynfile;outfmt
'
startup

export RCVR_PORT=$TCPFLOOD_PORT
export RSYSLOG_DEBUGLOG="log2"
generate_conf 2
add_conf '
action(type="omfwd" target="127.0.0.1" protocol="tcp" port="'$RCVR_PORT'" compression.mode="stream:always")
' 2
startup 2
assign_tcpflood_port $RSYSLOG_DYNNAME.tcpflood_port

injectmsg2
shutdown_when_empty 2
wait_shutdown 2
shutdown_when_empty
wait_shutdown

seq_check
exit_test
