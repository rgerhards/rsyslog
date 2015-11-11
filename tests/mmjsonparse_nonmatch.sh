#!/bin/bash
# added 2014-07-15 by rgerhards
# This file is part of the rsyslog project, released under ASL 2.0
echo ===============================================================================
echo \[mmjsonparse_nonmatch.sh\]: check that mmjsonparse does not hold processing if it does not match
. $srcdir/diag.sh init
. $srcdir/diag.sh startup mmjsonparse_nonmatch.conf
. $srcdir/diag.sh tcpflood -m 5000
echo doing shutdown
. $srcdir/diag.sh shutdown-when-empty
echo wait on shutdown
. $srcdir/diag.sh wait-shutdown 
. $srcdir/diag.sh seq-check  0 4999
. $srcdir/diag.sh exit
