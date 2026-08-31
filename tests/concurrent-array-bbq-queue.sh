#!/bin/bash
# Exercise the BBQ selector through the candidate-neutral Main/named queue
# adapters. Shared exact oracles cover W1/W8/W16 ownership, ordering, fallback,
# idle wake, legacy modes, and roomy/pressure/timeout/discard native MultiSubmit.
export RSYSLOG_TEST_CA_CORE=bbq
for test in concurrent-array-queue.sh concurrent-array-native-multi.sh; do
	"${srcdir:=.}/$test" || exit $?
done
