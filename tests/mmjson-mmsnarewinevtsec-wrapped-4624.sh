#!/bin/bash
## Test wrapped SNARE Windows Security event parsing (event 4624)
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
payload=$'<13>1 2025-09-18T13:03:42.970090Z host app - - - MSWinEventLog\t1\tSecurity\t284138676\tThu Sep 18 13:03:42 2025\t4624\tWindows\tN/A\tN/A\tSuccess Audit\thost\tLogon\t\tAn account was successfully logged on.    Subject:   Security ID:  S-1-0-0   Account Name:  -   Account Domain:  -   Logon ID:  0x0    Logon Information:   Logon Type:  3   Restricted Admin Mode:  -    New Logon:   Security ID:  S-1-5-21-1004336348-1177238915-682003330-512   Account Name:  Administrator   Account Domain:  CONTOSO   Logon ID:  0x5e3f4b   Linked Logon ID:  0x0   Network Account Name:  -   Network Account Domain:  -    Process Information:   Process ID:  0x4c0   Process Name:  C:\\Windows\\System32\\svchost.exe    Network Information:   Workstation Name:  WINHOST   Source Network Address:  10.0.0.5   Source Port:  62029    Detailed Authentication Information:   Logon Process:  Advapi   Authentication Package:  Negotiate   Transited Services:  -   Package Name (NTLM only):  -   Key Length:  0\t-15049365'
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
assert record["event_id"] == 4624
assert record["hostname"] == "host"
ext = record["extended_info"]
assert ext["parse_ok"] is True
assert ext["intro"].startswith("An account was successfully logged on.")
assert ext["Subject"]["Security ID"] == "S-1-0-0"
assert ext["New Logon"]["Account Domain"] == "CONTOSO"
assert ext["Network Information"]["Source Port"] == 62029
PY

exit_test
