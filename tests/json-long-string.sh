#!/bin/bash
# This test checks if JSON escaping works for strings longer than the 4KB stack buffer.
# It forces the code path that switches from stack to heap allocation in msg.c
. ${srcdir:=.}/diag.sh init
generate_conf
add_conf '
# Create a long string with backslashes to force escaping
set $!long = "a\\b\"c";
# concatenate to make it long (approx 8KB)
# 5 chars initial.
# 10 iterations of doubling -> 5 * 1024 = 5120 bytes.
set $!long = $!long & $!long; # 10
set $!long = $!long & $!long; # 20
set $!long = $!long & $!long; # 40
set $!long = $!long & $!long; # 80
set $!long = $!long & $!long; # 160
set $!long = $!long & $!long; # 320
set $!long = $!long & $!long; # 640
set $!long = $!long & $!long; # 1280
set $!long = $!long & $!long; # 2560
set $!long = $!long & $!long; # 5120 - larger than 4096

template(name="json" type="list" option.json="on") {
        property(name="$!long")
        constant(value="\n")
}

:msg, contains, "msgnum:" action(type="omfile" template="json"
			         file=`echo $RSYSLOG_OUT_LOG`)
'
startup
injectmsg 0 1
shutdown_when_empty
wait_shutdown

if [ ! -f $RSYSLOG_OUT_LOG ]; then
    error_exit 1
fi

# Check if output is not empty
if [ ! -s $RSYSLOG_OUT_LOG ]; then
    echo "Output file is empty"
    error_exit 1
fi

# 5120 chars. Each needs escaping?
# "a\b"c" -> "a\\b\"c" (7 chars)
# 5120 * 7/5 = 7168 chars.
# plus quotes.
size=$(wc -c < $RSYSLOG_OUT_LOG)
echo "Output size: $size"
if [ $size -lt 6000 ]; then
    echo "Output size too small"
    error_exit 1
fi

exit_test
