#!/bin/bash
# this script prepares a clickhouse instance for use by the rsyslog testbench

CLICKHOUSE_CLIENT=${CLICKHOUSE_CLIENT:-clickhouse-client}
# shellcheck disable=SC2206 # intentional splitting of command string
CLICKHOUSE_CLIENT_CMD=($CLICKHOUSE_CLIENT)
if "${CLICKHOUSE_CLIENT_CMD[@]}" --query="CREATE DATABASE IF NOT EXISTS rsyslog"; then
    echo clickouse create database RETURN STATE: 0
else
    rc=$?
    echo clickouse create database RETURN STATE: $rc
    exit $rc
fi

# At the moment only the database is created for preperation.
# Every test creates a table for itself and drops it afterwards.
# This could look something like this:

#clickhouse-client --query="CREATE TABLE IF NOT EXISTS rsyslog.test ( id Int32, severity Int8, facility Int8, timestamp DateTime, ipaddress String, tag String, message String ) ENGINE = MergeTree() PARTITION BY severity Order By id"
#clickhouse-client --query="DROP TABLE rsyslog.test"
