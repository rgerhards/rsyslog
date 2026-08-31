#!/bin/bash
# Exercise BBQ through dynamic target routing, identity isolation, discard,
# late preparation replay, repeated 3/6-way fanout, cross-target pressure, and
# source retry. Each shared test retains its deterministic exact oracle.
export RSYSLOG_TEST_CA_CORE=bbq
for test in concurrent-array-reserved-batch.sh concurrent-array-routing-identity.sh \
	concurrent-array-routing-discard.sh concurrent-array-routing-fanout.sh \
	concurrent-array-routing-subsets.sh concurrent-array-reserved-pressure.sh \
	concurrent-array-routing-retry.sh; do
	"${srcdir:=.}/$test" || exit $?
done
