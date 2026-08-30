#!/bin/bash
# Exercise BBQ as the unchanged DA memory parent for classic and segmented
# children, all queue placements, unordered dual-consumer drain, durable
# save/restart, and constrained max-disk-space pressure with saveOnShutdown off.
# The shared drivers retain their marker and exact accepted-set oracles.
export RSYSLOG_TEST_CA_CORE=bbq
for test in concurrent-array-da.sh concurrent-array-da-persist.sh concurrent-array-da-maxdiskspace.sh; do
	"${srcdir:=.}/$test" || exit $?
done
