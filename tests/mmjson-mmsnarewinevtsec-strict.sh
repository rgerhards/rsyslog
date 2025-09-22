#!/bin/bash
## Compare lenient and strict modes when extra fields are present
. ${srcdir:=.}/diag.sh init

generate_conf
add_conf '
template(name="snarejson" type="list" option.jsonf="on") {
    property(outname="snare" name="$!snare" format="jsonf")
}
module(load="../plugins/mmsnarewinevtsec/.libs/mmsnarewinevtsec")
module(load="../plugins/imptcp/.libs/imptcp")

ruleset(name="lenient") {
    action(type="mmsnarewinevtsec")
    if $parsesuccess == "OK" then {
        action(type="omfile" file="'$RSYSLOG_DYNNAME'.lenient.log" template="snarejson")
    }
}

ruleset(name="strict") {
    action(type="mmsnarewinevtsec" mode="strict")
    if $parsesuccess == "OK" then {
        action(type="omfile" file="'$RSYSLOG_DYNNAME'.strict.log" template="snarejson")
    }
}

input(type="imptcp" port="0" listenPortFileName="'$RSYSLOG_DYNNAME'.lenient_port" ruleset="lenient")
input(type="imptcp" port="0" listenPortFileName="'$RSYSLOG_DYNNAME'.strict_port" ruleset="strict")
'

startup
payload=$'<13>1 2025-09-18T13:07:00.000000Z host app - - - MSWinEventLog\t1\tSecurity\t999\tThu Sep 18 13:07:00 2025\t4624\tWindows\tN/A\tN/A\tSuccess Audit\thost\tLogon\t\tLogon event with trailing field.    Subject:   Security ID:  S-1-0-0   Account Name:  -   Account Domain:  -   Logon ID:  0x0\t54321\tEXTRA'
lenient_port=$(cat "$RSYSLOG_DYNNAME.lenient_port")
tcpflood -m1 -p "$lenient_port" -M "$payload"
strict_port=$(cat "$RSYSLOG_DYNNAME.strict_port")
tcpflood -m1 -p "$strict_port" -M "$payload"
shutdown_when_empty
wait_shutdown

python3 <<'PY'
import json
from pathlib import Path
lenient = Path("${RSYSLOG_DYNNAME}.lenient.log")
strict = Path("${RSYSLOG_DYNNAME}.strict.log")
assert lenient.exists(), "lenient output missing"
len_lines = [line.strip() for line in lenient.read_text().splitlines() if line.strip()]
assert len(len_lines) == 1, f"lenient mode should parse message, got {len(len_lines)}"
record = json.loads(len_lines[0])["snare"]
assert record["snare_event_counter"] == 999
assert record["extended_info"]["parse_ok"] is True
if strict.exists():
    strict_lines = [line for line in strict.read_text().splitlines() if line.strip()]
    assert len(strict_lines) == 0, "strict mode should reject message with extra field"
PY

exit_test
