#!/bin/bash
# Ensure a failed session EPOLL_CTL_ADD does not leave a poisoned session list.
. ${srcdir:=.}/diag.sh init
skip_ASAN "LD_PRELOAD conflicts with ASan runtime load order"
export RSYSLOG_PRELOAD=.libs/liboverride_epoll_ctl.so
# With the testbench's imdiag listener plus the imptcp listener setup,
# the first accepted imptcp session reaches EPOLL_CTL_ADD call number 5.
export RSYSLOG_TEST_EPOLL_FAIL_ADD_AT=5

generate_conf
add_conf '
module(load="../plugins/imptcp/.libs/imptcp")
input(type="imptcp" port="0" listenPortFileName="'$RSYSLOG_DYNNAME'.tcpflood_port")

template(name="outfmt" type="string" string="%msg%\n")
:msg, contains, "msgnum:" action(type="omfile" file=`echo $RSYSLOG_OUT_LOG` template="outfmt")
'

startup
assign_tcpflood_port $RSYSLOG_DYNNAME.tcpflood_port
tcpflood -m1 -M"\"<129>Mar 10 01:00:00 172.20.245.8 tag: msgnum:1\""
tcpflood -m1 -M"\"<129>Mar 10 01:00:00 172.20.245.8 tag: msgnum:2\""
shutdown_when_empty
wait_shutdown

export EXPECTED=' msgnum:2'
cmp_exact
content_check 'os error during epoll ADD for socket' "${RSYSLOG_DYNNAME}.started"
content_check 'failed to fully accept session from remote peer localhost[127.0.0.1]' "${RSYSLOG_DYNNAME}.started"
exit_test
