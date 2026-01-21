#!/bin/bash
# Added 2025-??-?? by AI agent, released under ASL 2.0

. ${srcdir:=.}/diag.sh init

getiso="$PYTHON $srcdir/rscript_strptime_to_rfc3339_expect.py"

simple_value="2025/09/17 13:45:34"
simple_format="%Y/%m/%d %H:%M:%S"
r=$($getiso "$simple_value" "$simple_format") || { echo "failed to compute expected timestamps"; error_exit 1; }
simple_expected=$r

rfc3164_value="Sep 17 13:45:34"
rfc3164_format="%b %d %H:%M:%S"
r=$($getiso "$rfc3164_value" "$rfc3164_format") || { echo "failed to compute expected timestamps"; error_exit 1; }
rfc3164_expected=$r

rfc3164_year_value="Sep 17 13:45:34 2025"
rfc3164_year_format="%b %d %H:%M:%S %Y"
r=$($getiso "$rfc3164_year_value" "$rfc3164_year_format") || { echo "failed to compute expected timestamps"; error_exit 1; }
rfc3164_year_expected=$r

tz_value="2025-09-17 13:45:34 +02:30"
tz_format="%Y-%m-%d %H:%M:%S %z"
r=$($getiso "$tz_value" "$tz_format") || { echo "failed to compute expected timestamps"; error_exit 1; }
tz_expected=$r

generate_conf
add_conf '
module(load="../plugins/imtcp/.libs/imtcp")
module(load="../plugins/omstdout/.libs/omstdout")
input(type="imtcp" port="0" listenPortFileName="'"$RSYSLOG_DYNNAME"'.tcpflood_port")

set $!iso!simple = strptime_to_rfc3339("$simple_value", "$simple_format");
set $!iso!rfc3164 = strptime_to_rfc3339("$rfc3164_value", "$rfc3164_format");
set $!iso!rfc3164_year = strptime_to_rfc3339("$rfc3164_year_value", "$rfc3164_year_format");
set $!iso!tz = strptime_to_rfc3339("$tz_value", "$tz_format");

template(name="outfmt" type="string" string="%!iso%\n")
local4.* action(type="omfile" file=`echo $RSYSLOG_OUT_LOG` template="outfmt")
local4.* :omstdout:;outfmt
'

startup
tcpflood -m1 -y
shutdown_when_empty
wait_shutdown

expected_json='{ "simple": "'"$simple_expected"'", "rfc3164": "'"$rfc3164_expected"'", "rfc3164_year": "'"$rfc3164_year_expected"'", "tz": "'"$tz_expected"'" }'

cmp <(echo "$expected_json") $RSYSLOG_OUT_LOG

if [[ $? -ne 0 ]]; then
  printf "Unexpected function output!\n"
  printf "Expected: $expected_json\n"
  printf "Got:      "
  cat $RSYSLOG_OUT_LOG
  error_exit 1
fi

exit_test
