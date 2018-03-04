# run compile-only tests under Travis
# This is specifically written to support Travis CI
set -e
# #################### newer compilers ####################

DO_IN_CONTAINER="$RSYSLOG_HOME/devtools/devcontainer.sh"
printf "\n\n============ STEP: gcc-7 compile test ================\n\n\n"
export CC=gcc-7
export CFLAGS=-g
$DO_IN_CONTAINER devtools/run-configure.sh
$DO_IN_CONTAINER make check TESTS=""
$DO_IN_CONTAINER make check
