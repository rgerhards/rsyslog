#!/bin/bash
# This file is part of the rsyslog project, released under ASL 2.0
# written 2025-09-26 by AI Assistant
. ${srcdir:=.}/diag.sh init

generate_conf
add_conf '
template(name="json" type="list" option.jsonf="on") {
        property(outname="status_zero" format="jsonf" name="$!status" datatype="number" omitIfZero="on")
        property(outname="status_nonzero" format="jsonf" name="$!other" datatype="number" omitIfZero="on")
        property(outname="status_empty" format="jsonf" name="$!empty" datatype="number" omitIfZero="on" onEmpty="null")
        property(outname="status_zero_fr" format="jsonfr" name="$!status" datatype="number" omitIfZero="on")
        property(outname="status_nonzero_fr" format="jsonfr" name="$!other" datatype="number" omitIfZero="on")
}

set $!status = "0";
set $!other = "200";
set $!empty = "";
action(type="omfile" file="'$RSYSLOG_OUT_LOG'" template="json")
'

startup
shutdown_when_empty
wait_shutdown
content_check '{"status_nonzero":200, "status_empty":null, "status_nonzero_fr":200}'
check_not_present 'status_zero'
check_not_present 'status_zero_fr'
exit_test
