#!/bin/bash
# This file is part of the rsyslog project, released under ASL 2.0
. ${srcdir:=.}/diag.sh init
export ES_PORT=9200
export NUMMESSAGES=100
generate_conf
add_conf '
template(name="tpl" type="string"
	 string="{\"msgnum\":\"%msg:F,58:2%\"}")

module(load="../plugins/omelasticsearch/.libs/omelasticsearch")
:msg, contains, "msgnum:" {
                        action(type="omelasticsearch"
                                 template="tpl"
                                 serverport=`echo $ES_PORT`
                                 searchType=""
                                 searchIndex="rsyslog_testbench"
                                 bulkmode="on"
                                 uid="elastic"
                                 pwd="changeme"
                               )
}
'
startup
injectmsg
shutdown_when_empty
wait_shutdown 
exit_test
