#!/bin/bash
# added 2024-03-?? by AI
# This file is part of the rsyslog project, released under ASL 2.0

echo ===============================================================================
echo "[compact-json-global.sh]: test global compactJsonString option"
. ${srcdir:=.}/diag.sh init

generate_conf
add_conf '
module(load="../plugins/mmjsonparse/.libs/mmjsonparse")
module(load="../plugins/imtcp/.libs/imtcp")
global(compactJsonString="on")
input(type="imtcp" port="0" listenPortFileName="'"$RSYSLOG_DYNNAME"'.tcpflood_port")
template(name="outfmt" type="string" string="%$!all-json%\n")
action(type="mmjsonparse")
action(type="omfile" file="'"$RSYSLOG_OUT_LOG"'" template="outfmt")
'

startup
tcpflood -m1 -M "\"<167>Mar  6 16:57:54 172.20.245.8 test: @cee: { \\\"foo\\\": \\\"bar\\\" }\""
shutdown_when_empty
wait_shutdown
content_check '{"foo":"bar"}'
exit_test

