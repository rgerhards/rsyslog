#!/bin/bash
# Drive a capacity-two ConcurrentArray queue with a burst much larger than its
# capacity while the sole consumer is deliberately slow. Enqueue timeout is
# long enough for backpressure to drain each full condition. Exact 0..63 output
# proves that full-queue pushback neither discards nor duplicates ownership.
# The impstats oracle additionally requires full>0, proving the test actually
# reached the capacity boundary instead of passing without exercising it.
. ${srcdir:=.}/diag.sh init
require_plugin omtesting
require_plugin impstats
export NUMMESSAGES=64
STATS_FILE="$RSYSLOG_DYNNAME.stats.log"

generate_conf
add_conf '
module(load="../plugins/omtesting/.libs/omtesting")
module(load="../plugins/impstats/.libs/impstats" log.file="'$STATS_FILE'" interval="1")
main_queue(queue.type="ConcurrentArray" queue.concurrentCore="sparseLanes"
	queue.size="2" queue.workerThreads="1" queue.dequeueBatchSize="2"
	queue.timeoutEnqueue="30000")
template(name="outfmt" type="string" string="%msg:F,58:2%\n")
:msg, contains, "msgnum:" :omtesting:sleep 0 50000
:msg, contains, "msgnum:" action(type="omfile" file="'$RSYSLOG_OUT_LOG'" template="outfmt")
'

startup
injectmsg 0 "$NUMMESSAGES"
wait_content 'main Q: origin=core.queue .* full=[1-9][0-9]* .* maxqsize=2' "$STATS_FILE"
shutdown_when_empty
wait_shutdown
seq_check 0 63
exit_test
