#!/usr/bin/env python3
"""Validate and compactly record the exact omprog transaction protocol."""

import os
import re
import sys


result_path = os.environ.get("RSYSLOG_CA_ACTION_TX_RESULT")
transcript_path = os.environ.get("RSYSLOG_CA_ACTION_TX_TRANSCRIPT")
summary_path = os.environ.get("RSYSLOG_CA_ACTION_TX_SUMMARY")
publication_mark = os.environ.get("RSYSLOG_TEST_CA_ACTION_PUBLICATION_MARK")
in_transaction = False
count = 0
begin_count = 0
commit_count = 0
valid_message_count = 0
error_count = 0
sequence_valid = True
eof_inside_transaction = False


def append_fsynced(path, value):
    if path is None:
        return
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, f"{value}\n".encode("ascii"))
        os.fsync(fd)
    finally:
        os.close(fd)


def protocol_error(value):
    global error_count
    error_count += 1
    append_fsynced(transcript_path, f"ERROR {value}")
    print(f"Error: {value}", flush=True)


print("OK", flush=True)
for raw_line in sys.stdin:
    line = raw_line.rstrip("\n")
    if line == "BEGIN TRANSACTION":
        if in_transaction:
            protocol_error("nested begin")
            continue
        in_transaction = True
        begin_count += 1
        count = 0
        append_fsynced(transcript_path, "BEGIN")
        print("OK", flush=True)
    elif line == "COMMIT TRANSACTION":
        if not in_transaction:
            protocol_error("commit outside transaction")
            continue
        if publication_mark is not None:
            if not os.path.exists(publication_mark):
                protocol_error("direct commit preceded queued publication")
                continue
            append_fsynced(transcript_path, "COMMIT publication=present")
        else:
            append_fsynced(transcript_path, "COMMIT")
        append_fsynced(result_path, str(count))
        commit_count += 1
        in_transaction = False
        print("OK", flush=True)
    elif in_transaction:
        match = re.fullmatch(r" ?msgnum:([0-9]{8}):", line)
        if match is None:
            protocol_error("malformed message in transaction")
            continue
        message_id = int(match.group(1))
        if message_id != valid_message_count:
            sequence_valid = False
            protocol_error("non-contiguous message sequence")
            continue
        count += 1
        valid_message_count += 1
        append_fsynced(transcript_path, f"MSG msgnum:{match.group(1)}:")
        print("DEFER_COMMIT", flush=True)
    else:
        protocol_error("message outside transaction")

if in_transaction:
    eof_inside_transaction = True
    protocol_error("EOF inside transaction")

append_fsynced(
    summary_path,
    f"BEGIN={begin_count} MSG={valid_message_count} COMMIT={commit_count} "
    f"ERRORS={error_count} SEQUENCE={'contiguous-zero-based' if sequence_valid else 'invalid'} "
    f"EOF_IN_TX={'yes' if eof_inside_transaction else 'no'}",
)
