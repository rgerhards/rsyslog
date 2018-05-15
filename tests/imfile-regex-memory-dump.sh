#!/bin/bash
# add 2018-05-14 by Pascal Withopf, released under ASL 2.0
. $srcdir/diag.sh init
. $srcdir/diag.sh generate-conf
. $srcdir/diag.sh add-conf '
module(load="../plugins/imfile/.libs/imfile" readTimeout="5" timeoutGranularity="4")
input(type="imfile" File="input.log" Tag="tag"
		startmsg.regex="^\\[[0-9]{4}-[0-9]{2}-[0-9]{2}")

#template(name="outfmt" type="string" string="-%msg%-\n")


:syslogtag, contains, "tag" action(type="omfile" file="rsyslog.out.log")
#				template="outfmt")
'
. $srcdir/diag.sh startup

echo -ne "[$(date +"%Y-%m-%dT%T+01:00")] foo!\n" >> ./input.log
sleep 10;
echo >> ./input.log

. $srcdir/diag.sh shutdown-when-empty
. $srcdir/diag.sh wait-shutdown

echo '' | cmp - rsyslog.out.log
if [ ! $? -eq 0 ]; then
  echo "invalid response generated, rsyslog.out.log is:"
  cat rsyslog.out.log
  . $srcdir/diag.sh error-exit  1
fi;

. $srcdir/diag.sh exit
