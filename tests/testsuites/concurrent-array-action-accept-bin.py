#!/usr/bin/env python3
"""Durably record accepted message IDs before acknowledging them to omprog."""

import os
import re
import sys


accepted_path = os.environ["RSYSLOG_CA_ACTION_ACCEPTED"]
pattern = re.compile(r"msgnum:[0-9]{8}:")
print("OK", flush=True)
for line in sys.stdin:
    match = pattern.search(line)
    if match is None:
        print("Error: malformed message id", flush=True)
        continue
    fd = os.open(accepted_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, f"{match.group(0)}\n".encode("ascii"))
        os.fsync(fd)
    finally:
        os.close(fd)
    print("OK", flush=True)
