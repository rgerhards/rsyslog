#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# Copyright 2026 Rainer Gerhards and Adiscon GmbH.
#
# Shared pure disk-assisted queue behavior driver. The wrapper selects one
# engine, memory queue type, and placement (main, ruleset, or action).
# A tiny queue with single-record, slowed dequeue must spill a 2000-message
# burst. The engine-specific filesystem object proves the child was used; the
# exact 0..1999 accepted set proves lossless spill and drain. The memory parent
# and disk child are independent consumers, so their merged order is not an
# oracle; malformed, missing, or duplicate IDs still fail.
. ${srcdir:=.}/diag.sh init

export NUMMESSAGES=2000
DA_SCOPE=${DA_SCOPE:?DA_SCOPE must be main, ruleset, or action}
DA_ENGINE=${DA_ENGINE:?DA_ENGINE must be auto or disk}
DA_QUEUE_TYPE=${DA_QUEUE_TYPE:?DA_QUEUE_TYPE must be LinkedList, FixedArray, or ConcurrentArray}
CA_CORE=${RSYSLOG_TEST_CA_CORE:-sparseLanes}
SPOOL_DIR="${RSYSLOG_DYNNAME}.spool"

wait_for_path() {
	local path="$1"
	local deadline=$((SECONDS + 30))
	while [ ! -e "$path" ]; do
		if [ "$SECONDS" -ge "$deadline" ]; then
			find "$SPOOL_DIR" -maxdepth 2 -print 2>/dev/null || true
			error_exit 1 "$DA_SCOPE DA child did not create $path"
		fi
		./msleep 25
	done
}

wait_for_classic_segment() {
	local deadline=$((SECONDS + 30))
	while ! compgen -G "$SPOOL_DIR/scopeq.[0-9]*" >/dev/null; do
		if [ "$SECONDS" -ge "$deadline" ]; then
			find "$SPOOL_DIR" -maxdepth 1 -print 2>/dev/null || true
			error_exit 1 "$DA_SCOPE classic DA child did not create a numeric segment"
		fi
		./msleep 25
	done
}

if [ "$DA_ENGINE" = auto ]; then
	ENGINE_CONFIG='queue.diskQueueType="auto"
	queue.diskQueueIdleTimeout="-1"'
	EXPECTED_ENGINE=segmentedDisk
else
	ENGINE_CONFIG='queue.diskQueueType="disk"'
	EXPECTED_ENGINE=disk
fi

if [ "$DA_QUEUE_TYPE" = ConcurrentArray ]; then
	CORE_CONFIG='queue.concurrentCore="'"$CA_CORE"'"'
	ENGINE_GLOBAL=' executionEngine="reservedBatch"'
	CA_MODULE='module(load="../plugins/omtesting/.libs/omtesting")'
	CA_MAIN_CONFIG='main_queue(queue.type="ConcurrentArray" queue.concurrentCore="'"$CA_CORE"'")'
	CA_DELAY=':omtesting:sleep 0 2000'
	SLOWDOWN_CONFIG=
else
	CORE_CONFIG=
	ENGINE_GLOBAL=
	CA_MODULE=
	CA_MAIN_CONFIG=
	CA_DELAY=
	SLOWDOWN_CONFIG='queue.dequeueSlowdown="2"'
fi

QUEUE_CONFIG='queue.type="'"$DA_QUEUE_TYPE"'"
	'"$CORE_CONFIG"'
	queue.filename="scopeq"
	queue.size="50"
	queue.highWatermark="10"
	queue.lowWatermark="5"
	queue.dequeueBatchSize="1"
	'"$SLOWDOWN_CONFIG"'
	'"$ENGINE_CONFIG"

generate_conf
case "$DA_SCOPE" in
main)
	add_conf '
global(workDirectory="'"$SPOOL_DIR"'"'"$ENGINE_GLOBAL"')
'"$CA_MODULE"'
main_queue(
'"$QUEUE_CONFIG"'
)
template(name="outfmt" type="string" string="%msg:F,58:2%\n")
'"$CA_DELAY"'
:msg, contains, "msgnum:" action(type="omfile" file="'"$RSYSLOG_OUT_LOG"'" template="outfmt")
'
	;;
ruleset)
	add_conf '
global(workDirectory="'"$SPOOL_DIR"'"'"$ENGINE_GLOBAL"')
'"$CA_MODULE"'
'"$CA_MAIN_CONFIG"'
template(name="outfmt" type="string" string="%msg:F,58:2%\n")
ruleset(name="queued"
'"$QUEUE_CONFIG"'
) {
	'"$CA_DELAY"'
	action(type="omfile" file="'"$RSYSLOG_OUT_LOG"'" template="outfmt")
}
:msg, contains, "msgnum:" call queued
'
	;;
action)
	add_conf '
global(workDirectory="'"$SPOOL_DIR"'"'"$ENGINE_GLOBAL"')
'"$CA_MODULE"'
'"$CA_MAIN_CONFIG"'
template(name="outfmt" type="string" string="%msg:F,58:2%\n")
:msg, contains, "msgnum:" action(
	type="omfile" file="'"$RSYSLOG_OUT_LOG"'" template="outfmt"
'"$QUEUE_CONFIG"'
)
'
	;;
*)
	error_exit 1 "unknown DA_SCOPE: $DA_SCOPE"
	;;
esac

startup
injectmsg

MARKER="$SPOOL_DIR/scopeq.da-engine"
wait_for_path "$MARKER"
[ "$(cat "$MARKER")" = "RSYSLOG-DA-ENGINE-V1 $EXPECTED_ENGINE" ] ||
	error_exit 1 "$DA_SCOPE DA engine marker selected the wrong engine"
if [ "$DA_ENGINE" = auto ]; then
	wait_for_path "$SPOOL_DIR/scopeq.segq"
else
	wait_for_classic_segment
fi

wait_file_lines "$RSYSLOG_OUT_LOG" "$NUMMESSAGES" 300
shutdown_when_empty
wait_shutdown
if [ "$DA_QUEUE_TYPE" = ConcurrentArray ]; then
	# DA has independent memory-parent and disk-child consumers.  Validate the
	# exact accepted set and multiplicity without inventing a merged order.
	sort -n "$RSYSLOG_OUT_LOG" > "${RSYSLOG_OUT_LOG}.sorted"
	seq -f '%08g' 0 1999 > "${RSYSLOG_OUT_LOG}.expected"
	diff -u "${RSYSLOG_OUT_LOG}.expected" "${RSYSLOG_OUT_LOG}.sorted" ||
		error_exit 1 "$DA_SCOPE ConcurrentArray DA output set or multiplicity mismatch"
else
	seq_check 0 1999
fi
exit_test
