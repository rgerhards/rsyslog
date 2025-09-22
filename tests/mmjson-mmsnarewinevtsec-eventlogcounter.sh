#!/bin/bash
## Verify numeric fields like event_log_counter are emitted as integers
. ${srcdir:=.}/diag.sh init

generate_conf
add_conf '
template(name="snarejson" type="list" option.jsonf="on") {
    property(outname="snare" name="$!snare" format="jsonf")
}
module(load="../plugins/mmsnarewinevtsec/.libs/mmsnarewinevtsec")
module(load="../plugins/imptcp/.libs/imptcp")
input(type="imptcp" port="0" listenPortFileName="'$RSYSLOG_DYNNAME'.tcpflood_port")

action(type="mmsnarewinevtsec")
if $parsesuccess == "OK" then {
    action(type="omfile" file="'$RSYSLOG_OUT_LOG'" template="snarejson")
}
'

startup
payload=$'<13>1 2025-09-18T13:08:00.000000Z host app - - - MSWinEventLog\t2\tSecurity\t400\tThu Sep 18 13:08:00 2025\t4625\tWindows\tN/A\tN/A\tFailure Audit\thost\tLogon\t\tAn account failed to log on.    Subject:   Security ID:  S-1-0-0   Account Name:  -   Account Domain:  -   Logon ID:  0x0    Failure Information:   Failure Reason:  Unknown user name or bad password\t-42'
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
assert isinstance(record["criticality"], int)
assert record["criticality"] == 2
assert record["snare_event_counter"] == 400
assert record["event_log_counter"] == -42
PY

exit_test
