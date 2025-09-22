#!/bin/bash
## Test SNARE Windows Security parsing for event 4672 with privileges list
. ${srcdir:=.}/diag.sh init

generate_conf
add_conf '
template(name="snarejson" type="list") {
    property(outname="snare" name="$!snare")
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
payload=$'<13>1 2025-09-18T13:05:10.000000Z host app - - - MSWinEventLog\t1\tSecurity\t284138677\tThu Sep 18 13:05:10 2025\t4672\tMicrosoft-Windows-Security-Auditing\tSYSTEM\tSidTypeUser\tSuccess Audit\thost\tSpecial Logon\t\tSpecial privileges assigned to new logon.    Subject:   Security ID:  S-1-5-18   Account Name:  WINHOST$   Account Domain:  CONTOSO   Logon ID:  0x3e7    Privileges:  SeTcbPrivilege   SeBackupPrivilege   SeRestorePrivilege   SeDebugPrivilege   SeImpersonatePrivilege\t78901'
tcpflood -m1 -M "\"$payload\""
shutdown_when_empty
wait_shutdown

python3 - "$RSYSLOG_OUT_LOG" <<'PY'
import json
import sys
from pathlib import Path
out = Path(sys.argv[1])
lines = [line.strip() for line in out.read_text().splitlines() if line.strip()]
assert len(lines) == 1, f"expected one parsed line, got {len(lines)}"
record = json.loads(lines[0])["snare"]
ext = record["extended_info"]
assert ext["parse_ok"] is True
privs = ext["Privileges"]
assert isinstance(privs, list)
assert len(privs) >= 5
assert privs[0] == "SeTcbPrivilege"
assert privs[4] == "SeImpersonatePrivilege"
PY

exit_test
