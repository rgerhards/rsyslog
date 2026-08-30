#!/bin/bash
# Prove sparseLanes retains untransferred work while a constrained segmented
# child applies pressure.  Two fill/drain cycles plus exact unordered IDs are
# the progress and ownership oracle; disk usage must remain within the existing
# segmented-child bound.
export DA_QUEUE_TYPE=ConcurrentArray
exec "${srcdir:=.}/segmented-da-maxdiskspace.sh"
