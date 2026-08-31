#!/bin/bash
# Verify qqueue ownership when sparseLanes lazy-chunk allocation fails once.
# The single-submit oracle recovers IDs 0 and 2 while ID 1 has one explicit
# unpublished-destruction marker. The startup command-file hook constructs one
# deterministic native MultiEnq span: preparation failure must publish none of
# IDs 0..7 and destroy each exactly once, while independent ID 8 recovers.
# These exact output/debug identities catch leaks, double destruction, or a
# partially published logical span without depending on TCP recv boundaries.
. ${srcdir:=.}/diag.sh init

export RSYSLOG_DEBUG="debug nostdout"
export RSYSLOG_DEBUGLOG="$RSYSLOG_DYNNAME.debug.log"
export RSYSLOG_TEST_CA_FAIL_CHUNK_ON_MESSAGE="msgnum:00000001:"

generate_conf
add_conf '
main_queue(queue.type="ConcurrentArray" queue.concurrentCore="sparseLanes"
	queue.size="128" queue.workerThreads="1" queue.dequeueBatchSize="32")
template(name="outfmt" type="string" string="%msg:F,58:2%\n")
:msg, contains, "msgnum:" action(type="omfile" file="'$RSYSLOG_OUT_LOG'" template="outfmt")
'
startup
injectmsg 0 3
wait_file_lines "$RSYSLOG_OUT_LOG" 2
shutdown_when_empty
wait_shutdown
export EXPECTED=$'00000000\n00000002'
cmp_exact
[ "$(grep -c 'destroying unpublished message .*msgnum:00000001:' "$RSYSLOG_DEBUGLOG")" -eq 1 ] || {
	error_exit 1 "single-submit OOM did not destroy ID 1 exactly once"
}

rm -f "$RSYSLOG_OUT_LOG" "$RSYSLOG_DEBUGLOG"
export RSYSLOG_TEST_CA_MULTI_COMMAND_FILE="$RSYSLOG_DYNNAME.ca-oom.commands"
printf '0 8 - expect-error\n8 1\n' >"$RSYSLOG_TEST_CA_MULTI_COMMAND_FILE"
generate_conf
add_conf '
main_queue(queue.type="ConcurrentArray" queue.concurrentCore="sparseLanes"
	queue.size="128" queue.workerThreads="1" queue.dequeueBatchSize="32")
template(name="outfmt" type="string" string="%msg:F,58:2%\n")
:msg, contains, "msgnum:" action(type="omfile" file="'$RSYSLOG_OUT_LOG'" template="outfmt")
'
startup
for id in 0 1 2 3 4 5 6 7; do
	padded=$(printf '%08d' "$id")
	wait_content "destroying unpublished message '.*msgnum:${padded}:" "$RSYSLOG_DEBUGLOG"
done
wait_file_lines "$RSYSLOG_OUT_LOG" 1
shutdown_when_empty
wait_shutdown
export EXPECTED=$'00000008'
cmp_exact
for id in 0 1 2 3 4 5 6 7; do
	padded=$(printf '%08d' "$id")
	[ "$(grep -c "destroying unpublished message .*msgnum:${padded}:" "$RSYSLOG_DEBUGLOG")" -eq 1 ] || {
		error_exit 1 "MultiEnq OOM did not destroy ID $id exactly once"
	}
done

unset RSYSLOG_DEBUG RSYSLOG_DEBUGLOG RSYSLOG_TEST_CA_FAIL_CHUNK_ON_MESSAGE \
	RSYSLOG_TEST_CA_MULTI_COMMAND_FILE EXPECTED
exit_test
