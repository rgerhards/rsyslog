#!/bin/bash
## Ensure datetime parsing works when parse_time=on
. ${srcdir:=.}/diag.sh init

generate_conf
add_conf '
template(name="snarejson" type="list" option.jsonf="on") {
    property(outname="snare" name="$!snare" format="jsonf")
}
module(load="../plugins/mmsnarewinevtsec/.libs/mmsnarewinevtsec")
module(load="../plugins/imptcp/.libs/imptcp")
input(type="imptcp" port="0" listenPortFileName="'$RSYSLOG_DYNNAME'.tcpflood_port")

action(type="mmsnarewinevtsec" parse_time="on" default_tz="UTC")
if $parsesuccess == "OK" then {
    action(type="omfile" file="'$RSYSLOG_OUT_LOG'" template="snarejson")
}
'

startup
payload=$'<13>1 2025-09-18T13:03:42.970090Z host app - - - MSWinEventLog\t1\tSecurity\t284138676\tThu Sep 18 13:03:42 2025\t4624\tWindows\tN/A\tN/A\tSuccess Audit\thost\tLogon\t\tAn account was successfully logged on.    Subject:   Security ID:  S-1-0-0   Account Name:  -   Account Domain:  -   Logon ID:  0x0    Logon Information:   Logon Type:  3\t-15049365'
tcpflood -m1 -M "$payload"
shutdown_when_empty
wait_shutdown

python3 <<'PY'
import json
from pathlib import Path
out = Path("${RSYSLOG_OUT_LOG}")
lines = [line.strip() for line in out.read_text().splitlines() if line.strip()]
assert len(lines) == 1, f"expected one parsed line, got {len(lines)}"
record = json.loads(lines[0])["snare"]
assert record["datetime_str"] == "Thu Sep 18 13:03:42 2025"
assert record["datetime_rfc3339"] == "2025-09-18T13:03:42+00:00"
PY

exit_test
