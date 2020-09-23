#!/bin/bash
# Test for disk-only queue mode
# This test checks if queue files can be correctly written
# and read back, but it does not test the transition from
# memory to disk mode for DA queues.
# added 2009-04-17 by Rgerhards
# This file is part of the rsyslog project, released under ASL 2.0
. ${srcdir:=.}/diag.sh init
export NUMMESSAGES=1000
export QUEUE_EMPTY_CHECK_FUNC=wait_file_lines
generate_conf
add_conf '


echo we do not see any change in output behavior here if we switch
echo compatjsonstring on/off -- looks like PR has different effect,
echo it compresses spaces, but thats it

global(compactjsonstring="on")
# set spool locations and switch queue to disk-only mode
$WorkDirectory '$RSYSLOG_DYNNAME'.spool

$template outfmt,"%msg:F,58:2%,%$!var%\n"
set $!var = "Hello World";
if ($msg contains "msgnum:") then
	action(type="omfile" file="'$RSYSLOG_OUT_LOG'" template="outfmt"
	queue.type="disk" queue.filename="actq" queue.timeoutenqueue="300000")
else
	action(type="omfile" file="'$RSYSLOG_DYNNAME.syslog.log'")
'
startup
injectmsg
shutdown_when_empty
wait_shutdown
seq_check
check_not_present "spool.* open error" $RSYSLOG_DYNNAME.syslog.log
tail -n20 $RSYSLOG_OUT_LOG
exit_test
