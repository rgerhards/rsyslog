#!/bin/bash
# added 2015-10-08 by Rgerhards
# We test that an error message is emitted if omfile cannot open
# a dynafile. For this, we set a file to read-only, which prevents 
# omfile's open for writing.
# This file is part of the rsyslog project, released under ASL 2.0
. $srcdir/diag.sh init
touch rsyslog.out.log
chmod 0400 rsyslog.out.log
. $srcdir/diag.sh startup omfile_dynfile_open_err.conf
. $srcdir/diag.sh tcpflood -m1 -P 129
. $srcdir/diag.sh shutdown-when-empty # shut down rsyslogd when done processing messages
. $srcdir/diag.sh wait-shutdown       # and wait for it to terminate
chmod 0500 rsyslog.out.log

NUMLINES=$(grep -c rsyslog.out.log rsyslog.errorfile 2>/dev/null)
if [ -z $NUMLINES ]; then
    echo "ERROR: cannot find any expected message, maybe rsyslog.errorfile wasn't even written?"
    . $srcdir/diag.sh error-exit 1
fi
. $srcdir/diag.sh exit
