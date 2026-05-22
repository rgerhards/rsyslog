#!/bin/bash
## Test RFC3164 parser accepts IPv6 literals as HOSTNAME.
. ${srcdir:=.}/diag.sh init
generate_conf
add_conf '
module(load="../plugins/imtcp/.libs/imtcp")
input(type="imtcp" port="0" listenPortFileName="'$RSYSLOG_DYNNAME'.tcpflood_port" ruleset="customparser")
parser(name="custom.rfc3164" type="pmrfc3164" permit.squarebracketsinhostname="on")
template(name="outfmt" type="string" string="%hostname%\n")

ruleset(name="customparser" parser="custom.rfc3164") {
	action(type="omfile" template="outfmt" file="'$RSYSLOG_OUT_LOG'")
}
'
startup
tcpflood -m1 -M "\"<129>Mar 10 01:00:00 2001:db8::1 tag: msgnum:1\""
tcpflood -m1 -M "\"<129>Mar 10 01:00:00 [2001:db8::2] tag: msgnum:2\""
shutdown_when_empty
wait_shutdown
export EXPECTED='2001:db8::1
[2001:db8::2]'
cmp_exact

exit_test
