#!/bin/bash
## Test parsing of pure SNARE messages without syslog wrapper
. ${srcdir:=.}/diag.sh init

generate_conf
add_conf '
template(name="snarejson" type="list") {
    property(outname="snare" name="$!snare")
}
module(load="../plugins/mmsnarewinevtsec/.libs/mmsnarewinevtsec")
module(load="../plugins/imfile/.libs/imfile")
input(type="imfile" File="./'$RSYSLOG_DYNNAME'.input" Tag="raw:" addmetadata="off")

action(type="mmsnarewinevtsec")
if $parsesuccess == "OK" then {
    action(type="omfile" file="'$RSYSLOG_OUT_LOG'" template="snarejson")
}
'

startup
cat <<'MSG' > "$RSYSLOG_DYNNAME.input"
purehost	MSWinEventLog	1	Security	123456	Thu Sep 18 13:10:00 2025	4624	Windows	N/A	N/A	Success Audit	purehost	Logon	Some data	An account was successfully logged on.    Subject:   Security ID:  S-1-0-0   Account Name:  -   Account Domain:  -   Logon ID:  0x0    Logon Information:   Logon Type:  3   Restricted Admin Mode:  -    New Logon:   Security ID:  S-1-5-21-1004336348-1177238915-682003330-513   Account Name:  PUREUSER   Account Domain:  CONTOSO   Logon ID:  0x123   Linked Logon ID:  0x0    Network Information:   Source Network Address:  10.0.0.1   Source Port:  50123	34567
MSG
./msleep 500
shutdown_when_empty
wait_shutdown

python3 - "$RSYSLOG_OUT_LOG" <<'PY'
import json
from pathlib import Path
import sys

out = Path(sys.argv[1])
lines = [line.strip() for line in out.read_text().splitlines() if line.strip()]
assert len(lines) == 1, f"expected one parsed line, got {len(lines)}"
record = json.loads(lines[0])["snare"]
assert record["hostname"] == "purehost"
assert record["computer_name"] == "purehost"
assert record["snare_event_counter"] == 123456
ext = record["extended_info"]
assert ext["parse_ok"] is True
assert ext["Network Information"]["Source Port"] == 50123
PY

exit_test
