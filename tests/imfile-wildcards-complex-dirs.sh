#!/bin/bash
# created 2017-12-27 by Rainer Gerhards
# This is part of the rsyslog testbench, released under ASL 2.0
# use a somewhat more unusual wildcard
. $srcdir/diag.sh init
. $srcdir/diag.sh check-inotify-only
export IMFILEINPUTFILES="10"

. $srcdir/diag.sh generate-conf
. $srcdir/diag.sh add-conf '
$WorkDirectory test-spool

module(load="../plugins/imfile/.libs/imfile" mode="inotify" PollingInterval="1")

input(type="imfile" File="./rsyslog.input.[1-9].dir/logfile"
	Tag="file:" Severity="error" Facility="local7" addMetadata="on"
)

template(name="outfmt" type="list") {
	constant(value="HEADER ")
	property(name="msg" format="json")
	constant(value=", ")
	property(name="$!metadata!filename")
	constant(value="\n")
}

if $msg contains "msgnum:" then
	action( type="omfile" file="rsyslog.out.log" template="outfmt")
'
. $srcdir/diag.sh startup

for i in `seq 1 $IMFILEINPUTFILES`;
do
	mkdir rsyslog.input.$i.dir
	./inputfilegen -m 1 > rsyslog.input.$i.dir/file.logfile
done

. $srcdir/diag.sh shutdown-when-empty # shut down rsyslogd when done processing messages
. $srcdir/diag.sh wait-shutdown	# we need to wait until rsyslogd is finished!
. $srcdir/diag.sh content-check-with-count "HEADER msgnum:00000000:" $IMFILEINPUTFILES
. $srcdir/diag.sh exit
