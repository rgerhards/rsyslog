#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# Exercise the selected ConcurrentArray core as the memory parent of both
# unchanged DA engines in Main, queued-ruleset, and queued-action placements.
# The child marker/store
# proves that high/low-water spill occurred.  Exact sorted IDs prove no loss,
# duplication, or malformed output without claiming an ordering relationship
# between the concurrently consumed memory parent and disk child.
for DA_ENGINE in disk auto; do
	for DA_SCOPE in main ruleset action; do
		export DA_SCOPE DA_ENGINE
		export DA_QUEUE_TYPE=ConcurrentArray
		"${srcdir:=.}/testsuites/da-engine-behavior-driver.sh" || exit $?
	done
done
