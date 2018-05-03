#!/bin/bash
# add 2018-05-02 by PascalWithopf, released under ASL 2.0
. $srcdir/diag.sh init
./have_relpSrvSetOversizeMode
if [ $? -eq 1 ]; then
  echo "imrelp parameter oversizeMode not available. Test stopped"
  exit 77
fi;
. $srcdir/diag.sh generate-conf
. $srcdir/diag.sh add-conf '
module(load="../plugins/imrelp/.libs/imrelp")
global(maxMessageSize="230"
	oversizemsg.errorfile="oversizemsg")


input(type="imrelp" port="13514" maxdatasize="250")

template(name="outfmt" type="string" string="%rawmsg%\n")
#:msg, contains, "msgnum:" action(type="omfile" template="outfmt"
action(type="omfile" template="outfmt"
				 file="rsyslog.out.log")
'
# TODO: add tcpflood option to specific EXACT test message size!
. $srcdir/diag.sh startup
. $srcdir/diag.sh tcpflood -Trelp-plain -p13514 -m1 -d 240
. $srcdir/diag.sh shutdown-when-empty # shut down rsyslogd when done processing messages
. $srcdir/diag.sh wait-shutdown

# We need the ^-sign to symbolize the beginning and the $-sign to symbolize the end
# because otherwise we won't know if it was truncated at the right length.
grep "^ msgnum:00000000:240:XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX$" rsyslog.out.log > /dev/null
if [ $? -ne 0 ]; then
        echo
        echo "FAIL: expected message not found. rsyslog.out.log is:"
        cat rsyslog.out.log
        . $srcdir/diag.sh error-exit 1
fi

grep "message too long.*begin of message is:" rsyslog.out.log > /dev/null
if [ $? -ne 0 ]; then
        echo
        echo "FAIL: expected message not found. rsyslog.out.log is:"
        cat rsyslog.out.log
        . $srcdir/diag.sh error-exit 1
fi


exit
. $srcdir/diag.sh exit
