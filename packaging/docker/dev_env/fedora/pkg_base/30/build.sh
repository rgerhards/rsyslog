#!/bin/bash

set -e
# Use --no-cache to rebuild image
docker build $1 -t rsyslog/rsyslog_dev_pkg_base_fedora:30 --build-arg CACHEBUST=$(date +%s) .
printf "\n\n================== BUILD DONE\n"
