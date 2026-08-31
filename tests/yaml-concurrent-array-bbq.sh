#!/bin/bash
# Verify YAML reaches the shared BBQ selector for Main, routed target, and DA
# configurations. The reused tests require exact runtime output, queued-action
# validation, and a materialized segmented child rather than parser acceptance
# alone.
export RSYSLOG_TEST_CA_CORE=bbq
for test in yaml-concurrent-array-queue.sh yaml-concurrent-array-da.sh; do
	"${srcdir:=.}/$test" || exit $?
done
