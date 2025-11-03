#!/bin/bash
# This file is part of the rsyslog project, released under ASL 2.0

#  Starting actual testbench
. ${srcdir:=.}/diag.sh init

export NUMMESSAGES=100

omhttp_start_server 0

generate_conf
add_conf '
template(name="tpl" type="string"
         string="{\"msgnum\":\"%msg:F,58:2%\"}")

module(load="../contrib/omhttp/.libs/omhttp")

if $msg contains "msgnum:" then
        action(
                # Payload
                name="my_http_action"
                type="omhttp"
                errorfile="'$RSYSLOG_DYNNAME/omhttp.error.log'"
                template="tpl"

                server="localhost"
                serverport="'$omhttp_server_lstnport'"
                restpath="my/endpoint"
                batch="off"
                httpversion="2"
                usehttps="off"
    )
'
startup
injectmsg
shutdown_when_empty
wait_shutdown
omhttp_get_data $omhttp_server_lstnport my/endpoint
omhttp_stop_server
if [ -s "$RSYSLOG_DYNNAME/omhttp.error.log" ]; then
    exit_test
else
    echo "expected HTTP/2 request to fail" >&2
    error_exit 1
fi

