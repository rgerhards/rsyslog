#!/bin/bash
# add 2017-05-05 by Pascal Withopf, released under ASL 2.0
. $srcdir/diag.sh init
. $srcdir/diag.sh generate-conf
. $srcdir/diag.sh add-conf '
module(load="../plugins/mmnormalize/.libs/mmnormalize.so")
set $!input = "foo - bar foo2 - bar2";
action(
    type="mmnormalize"
    rulebase="testsuites/mmnormalize-and-unset.rb"
    variable="$!input"
    path="$!app"
)
unset $!app!ku1;
unset $!app!ku2;

template(name="outfmt" type="string" string="%$!%\n")
action(type="omfile" file="rsyslog.out.log" template="outfmt")
'
. $srcdir/diag.sh startup-vg
#. $srcdir/diag.sh tcpflood -m1
. $srcdir/diag.sh shutdown-when-empty
. $srcdir/diag.sh wait-shutdown-vg
. $srcdir/diag.sh check-exit-vg
#. $srcdir/diag.sh seq-check 0 999
cat rsyslog.out.log
. $srcdir/diag.sh exit
