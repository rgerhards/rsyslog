#!/bin/bash
# This file is part of the rsyslog project, released  under ASL 2.0
# make sure message variables are used case-sensitive by default
# released under ASL 2.0
# added 2015-12-06 rgerhards
echo ===============================================================================
echo \[stop-msgvar-casesensitive.sh\]: testing stop statement together with case nsensitive message variables
. $srcdir/diag.sh init
. $srcdir/diag.sh startup stop-msgvar-casesensitive.conf
sleep 1
. $srcdir/diag.sh tcpflood -m2000 -i1
. $srcdir/diag.sh shutdown-when-empty # shut down rsyslogd when done processing messages
. $srcdir/diag.sh wait-shutdown
. $srcdir/diag.sh seq-check 100 999
. $srcdir/diag.sh exit
