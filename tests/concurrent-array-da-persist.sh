#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# Verify sparseLanes saveOnShutdown through both unchanged DA children.  A fast
# immediate stop must leave durable classic/segmented child state; restart must
# recover the complete accepted sequence.  Duplicates are allowed only at the
# documented interruption boundary.
for DA_ENGINE in disk auto; do
	export DA_ENGINE
	export DA_QUEUE_TYPE=ConcurrentArray
	"${srcdir:=.}/testsuites/da-engine-persist-driver.sh" || exit $?
done
