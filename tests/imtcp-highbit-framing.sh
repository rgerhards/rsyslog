#!/bin/bash
# Regression test for framing classification on high-bit input bytes.
. ${srcdir:=.}/diag.sh init
generate_conf
add_conf '
module(load="../plugins/imtcp/.libs/imtcp")
input(type="imtcp" port="0" listenPortFileName="'$RSYSLOG_DYNNAME'.tcpflood_port")

template(name="outfmt" type="string" string="%msg:F,58:2%\n")
:msg, contains, "msgnum:" action(type="omfile" template="outfmt"
			         file=`echo $RSYSLOG_OUT_LOG`)
'
startup
printf '\377\n<167>Mar  6 16:57:54 172.20.245.8 test: msgnum:0 high-bit framing test\n' > $RSYSLOG_DYNNAME.input
tcpflood -B -I $RSYSLOG_DYNNAME.input
shutdown_when_empty
wait_shutdown
seq_check 0 0
exit_test
