#!/bin/bash
## Test delimiter auto-detection with non-tab separator
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
payload=$'<13>1 2025-09-18T13:06:00.000000Z host app - - - MSWinEventLog|1|Security|777|Thu Sep 18 13:06:00 2025|4624|Windows|N/A|N/A|Success Audit|host|Logon|Data field|An account was successfully logged on.    Subject:   Security ID:  S-1-0-0   Account Name:  -   Account Domain:  -   Logon ID:  0x0    Logon Information:   Logon Type:  2   Restricted Admin Mode:  -    Network Information:   Source Port:  44444|56789'
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
assert record["snare_event_counter"] == 777
assert record["data_string"] == "Data field"
ext = record["extended_info"]
assert ext["parse_ok"] is True
assert ext["Logon Information"]["Logon Type"] == 2
PY

exit_test
