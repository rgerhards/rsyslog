#!/bin/bash
## yaml-basic.sh - basic YAML parser check
##
## Builds and runs the conf_yaml_poc parser, ensuring that the sample
## YAML configuration loads a module and adds an input.

set -e
srcdir="$(cd "$(dirname "$0")" && pwd)"
cd "$srcdir"
export RSYSLOG_MODDIR="../runtime/.libs"
libtool --mode=link gcc -I.. -I../runtime -I../grammar -I/usr/include/libfastjson ../conf_yaml_poc.c ../runtime/librsyslog.la ../compat/compat.la -lfastjson -lestr -lpthread -lm -luuid -lz -lyaml -o conf_yaml_poc
./conf_yaml_poc "conf_yaml_poc.yml" >test.log 2>&1
grep -F "module imtcp loaded" test.log
grep -F "input imtcp added" test.log
