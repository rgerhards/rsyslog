#!/bin/bash
# Exercise deterministic ownership failures for explicit sparseLanes action
# queues with both action.copyMsg modes. An early copy/allocation failure must
# leave the source RDY and deliver it exactly once after the one-shot fault.
# A late failure after the first action was staged must publish that accepted
# branch, retry the source, and therefore deliver first exactly twice and
# second exactly once. These exact counts also detect leaked or double-freed
# references without depending on TCP packet batching or allocation luck.
if [ "$1" != "--case" ]; then
	for copy in off on; do
		for point in early late; do
			fault_action=only
			[ "$point" = late ] && fault_action=second
			if [ "$copy" = on ]; then
				RSTB_CA_ACTION_COPY=$copy RSTB_CA_ACTION_FAULT=$point \
					RSYSLOG_TEST_CA_ACTION_COPY_FAIL=$fault_action \
					RSYSLOG_TEST_CA_ACTION_COPY_FAIL_MESSAGE=msgnum:00000000 \
					"$0" --case || exit $?
			else
				RSTB_CA_ACTION_COPY=$copy RSTB_CA_ACTION_FAULT=$point \
					RSYSLOG_TEST_CA_ACTION_STAGE_FAIL=$fault_action \
					RSYSLOG_TEST_CA_ACTION_STAGE_FAIL_MESSAGE=msgnum:00000000 \
					"$0" --case || exit $?
			fi
		done
	done
	exit 0
fi
. ${srcdir:=.}/diag.sh init

if [ "$RSTB_CA_ACTION_FAULT" = late ]; then
	actions='action(name="first" type="omfile" file="'$RSYSLOG_OUT_LOG'.first" template="outfmt"
       action.copyMsg="'$RSTB_CA_ACTION_COPY'" queue.type="ConcurrentArray"
       queue.concurrentCore="sparseLanes" queue.size="16" queue.workerThreads="1")
  action(name="second" type="omfile" file="'$RSYSLOG_OUT_LOG'.second" template="outfmt"
       action.copyMsg="'$RSTB_CA_ACTION_COPY'" queue.type="ConcurrentArray"
       queue.concurrentCore="sparseLanes" queue.size="16" queue.workerThreads="1")'
else
	actions='action(name="only" type="omfile" file="'$RSYSLOG_OUT_LOG'" template="outfmt"
       action.copyMsg="'$RSTB_CA_ACTION_COPY'" queue.type="ConcurrentArray"
       queue.concurrentCore="sparseLanes" queue.size="16" queue.workerThreads="1")'
fi

generate_conf
add_conf '
global(executionEngine="reservedBatch")
main_queue(queue.type="ConcurrentArray" queue.concurrentCore="sparseLanes"
           queue.size="32" queue.workerThreads="1" queue.dequeueBatchSize="8")
template(name="outfmt" type="string" string="%msg:F,58:2%\n")
if $msg contains "msgnum:00000000" then {
  '"$actions"'
}
'
startup
injectmsg 0 1
if [ "$RSTB_CA_ACTION_FAULT" = late ]; then
	wait_file_lines "$RSYSLOG_OUT_LOG.first" 2
	wait_file_lines "$RSYSLOG_OUT_LOG.second" 1
else
	wait_file_lines "$RSYSLOG_OUT_LOG" 1
fi
shutdown_when_empty
wait_shutdown

if [ "$RSTB_CA_ACTION_FAULT" = late ]; then
	content_count_check '00000000' 2 "$RSYSLOG_OUT_LOG.first"
	content_count_check '00000000' 1 "$RSYSLOG_OUT_LOG.second"
else
	content_count_check '00000000' 1 "$RSYSLOG_OUT_LOG"
fi
exit_test
