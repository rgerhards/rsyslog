#!/bin/bash
# addd 2016-03-30 by RGerhards, released under ASL 2.0

. ${srcdir:=.}/diag.sh init
generate_conf
add_conf '
module(load="../plugins/imtcp/.libs/imtcp")
input(type="imtcp" port="'$TCPFLOOD_PORT'")

template(name="outfmt" type="list") {
	property(name="msg")
	constant(value="\n")
}
:msg, contains, "x-pid" stop

:msg, contains, "msgnum" action(type="omfile" template="outfmt" file=`echo $RSYSLOG_OUT_LOG`)

:msg, contains, "this does not occur" action(type="omfwd"
	target="10.0.0.1" keepalive="on" keepalive.probes="10"
	keepalive.time="60" keepalive.interval="10")
 
'
startup
tcpflood -m1
shutdown_when_empty
wait_shutdown
export EXPECTED=" msgnum:00000000:"
cmp_exact $RSYSLOG_OUT_LOG

exit_test
