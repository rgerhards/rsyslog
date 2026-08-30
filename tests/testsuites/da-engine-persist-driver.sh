#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# Copyright 2026 Rainer Gerhards and Adiscon GmbH.
#
# Shared DA save-on-shutdown/restart driver. The wrapper selects the memory
# queue and disk engine. Single-record, deliberately slowed dequeue leaves a
# durable spill at immediate shutdown; restart must recover every accepted ID.
# The memory parent and disk child are independent consumers, so their merged
# output has no global ordering guarantee. Duplicates are accepted because an
# interrupted in-flight batch is replayable. The oracle therefore waits for
# the complete unique ID set, rejects malformed/out-of-range records, and only
# then permits shutdown.
. ${srcdir:=.}/diag.sh init
export NUMMESSAGES=2000
DA_ENGINE=${DA_ENGINE:?DA_ENGINE must be auto or disk}
DA_QUEUE_TYPE=${DA_QUEUE_TYPE:?DA_QUEUE_TYPE must be LinkedList, FixedArray, or ConcurrentArray}
SPOOL_DIR="${RSYSLOG_DYNNAME}.spool"
idle_config=
if [ "$DA_ENGINE" = auto ]; then
	idle_config='queue.diskQueueIdleTimeout="-1"'
fi
if [ "$DA_QUEUE_TYPE" = ConcurrentArray ]; then
	core_config='queue.concurrentCore="sparseLanes"'
	global_engine=' executionEngine="reservedBatch"'
	dequeue_slowdown=
	consumer_delay=':omtesting:sleep 0 1000'
else
	core_config=
	global_engine=
	dequeue_slowdown='queue.dequeueSlowdown="10000"'
	consumer_delay=
fi

generate_conf
# shellcheck disable=SC2090 # RainerScript quotes are intentionally retained.
add_conf '
global(workDirectory="'"$SPOOL_DIR"'"'"$global_engine"')
module(load="../plugins/omtesting/.libs/omtesting")
main_queue(queue.type="'"$DA_QUEUE_TYPE"'" queue.filename="mainq"
	'"$core_config"'
	queue.size="6000" queue.highWatermark="10" queue.lowWatermark="5"
	queue.dequeueBatchSize="1" '"$dequeue_slowdown"'
	queue.timeoutShutdown="1000"
	queue.saveOnShutdown="on"
	queue.diskQueueType="'"$DA_ENGINE"'" '"$idle_config"')
template(name="outfmt" type="string" string="%msg:F,58:2%\n")
'"$consumer_delay"'
:msg, contains, "msgnum:" action(type="omfile" file="'"$RSYSLOG_OUT_LOG"'" template="outfmt")
'

startup
injectmsg
shutdown_immediate
wait_shutdown
if [ "$DA_ENGINE" = auto ]; then
	[ -s "$SPOOL_DIR/mainq.segq/state" ] ||
		error_exit 1 "segmented DA save-on-shutdown did not persist state"
	content_check "RSYSLOG-DA-ENGINE-V1 segmentedDisk" "$SPOOL_DIR/mainq.da-engine"
else
	check_mainq_spool
fi
startup
# Main-queue emptiness may be observed while the DA child is still draining.
# Poll the accepted set instead of queue emptiness or global output order.
deadline=$(( $(date +%s) + 60 ))
while :; do
	if [ -f "$RSYSLOG_OUT_LOG" ]; then
		malformed=$(awk -v max="$NUMMESSAGES" '$0 !~ /^[0-9]{8}$/ || ($0 + 0) < 0 || ($0 + 0) >= max { n++ } END { print n + 0 }' "$RSYSLOG_OUT_LOG")
		[ "$malformed" -eq 0 ] || error_exit 1 "DA restart produced malformed or out-of-range records"
		unique=$(awk -v max="$NUMMESSAGES" '$0 ~ /^[0-9]{8}$/ && ($0 + 0) >= 0 && ($0 + 0) < max { seen[$0] = 1 } END { print length(seen) }' "$RSYSLOG_OUT_LOG")
		[ "$unique" -eq "$NUMMESSAGES" ] && break
	fi
	[ "$(date +%s)" -lt "$deadline" ] || error_exit 1 "DA restart did not recover the complete accepted ID set"
	"$TESTTOOL_DIR/msleep" 100
done
shutdown_when_empty
wait_shutdown
expected_ids="${RSYSLOG_DYNNAME}.expected.ids"
actual_ids="${RSYSLOG_DYNNAME}.actual.ids"
awk -v max="$NUMMESSAGES" 'BEGIN { for (i = 0; i < max; ++i) printf "%08d\n", i }' > "$expected_ids"
sort -u "$RSYSLOG_OUT_LOG" > "$actual_ids"
cmp -s "$expected_ids" "$actual_ids" || error_exit 1 "DA restart accepted ID set differs from input"
exit_test
