#!/bin/bash
# add 2019-03-26 by Rainer Gerhards, released under ASL 2.0
. ${srcdir:=.}/diag.sh init
generate_conf
add_conf '
module(load="../plugins/mmcapture/.libs/mmcapture")
action(type="mmcapture")
action(type="omfile" file="'$RSYSLOG_OUT_LOG'")
'

startup
shutdown_when_empty
wait_shutdown
content_check "mmcapture: 'interface' or 'file' must be specified"

exit_test
