#!/bin/bash
# Verify the explicit Checkpoint 5 queue matrix without changing legacy action
# paths. A source ruleset is either synchronous (no queue) or asynchronously
# backed by ConcurrentArray; its action is either Direct or explicitly
# ConcurrentArray. With one worker per queue, exact ordered IDs
# 0..15 prove that every source transfers exactly one action reference and that
# the queued-action builder publishes before the source is completed.
if [ "$1" != "--case" ]; then
	for source in direct queued; do
		for action_queue in direct queued; do
			RSTB_CA_ACTION_SOURCE=$source RSTB_CA_ACTION_QUEUE=$action_queue "$0" --case || exit $?
		done
	done
	exit 0
fi
. ${srcdir:=.}/diag.sh init
CA_CORE=${RSYSLOG_TEST_CA_CORE:-sparseLanes}

source_decl='ruleset(name="source")'
if [ "$RSTB_CA_ACTION_SOURCE" = queued ]; then
	source_decl='ruleset(name="source" queue.type="ConcurrentArray" queue.concurrentCore="'$CA_CORE'"
        queue.size="64" queue.workerThreads="1" queue.dequeueBatchSize="16")'
fi
action_decl='action(name="matrix" type="omfile" file="'$RSYSLOG_OUT_LOG'" template="outfmt"
         queue.type="Direct")'
if [ "$RSTB_CA_ACTION_QUEUE" = queued ]; then
	action_decl='action(name="matrix" type="omfile" file="'$RSYSLOG_OUT_LOG'" template="outfmt"
         queue.type="ConcurrentArray" queue.concurrentCore="'$CA_CORE'"
         queue.size="64" queue.workerThreads="1" queue.dequeueBatchSize="16")'
fi

generate_conf
conf='
global(executionEngine="reservedBatch")
main_queue(queue.type="ConcurrentArray" queue.concurrentCore="'$CA_CORE'"
           queue.size="64" queue.workerThreads="1" queue.dequeueBatchSize="16")
template(name="outfmt" type="string" string="%msg:F,58:2%\n")
'
conf="$conf
$source_decl {
  if \$msg contains \"msgnum:\" then
    $action_decl
}
if \$msg contains \"msgnum:\" then call source"
add_conf "$conf"
startup
injectmsg 0 16
wait_file_lines "$RSYSLOG_OUT_LOG" 16
shutdown_when_empty
wait_shutdown
EXPECTED=$(seq -f '%08g' 0 15)
export EXPECTED
cmp_exact
unset EXPECTED
exit_test
