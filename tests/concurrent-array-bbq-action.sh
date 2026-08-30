#!/bin/bash
# Exercise BBQ actions through the Direct/queued four-way matrix, transactional
# batches, consumer retry, immediate shutdown, suspend/recovery, and
# deterministic early/late ownership failures. Shared exact oracles are reused.
export RSYSLOG_TEST_CA_CORE=bbq
for test in concurrent-array-action.sh concurrent-array-action-transaction.sh \
	concurrent-array-action-retry.sh concurrent-array-action-shutdown.sh \
	concurrent-array-action-suspend.sh concurrent-array-action-oom.sh; do
	"${srcdir:=.}/$test" || exit $?
done
