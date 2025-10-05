#!/bin/bash
# Validate error handling for ratelimit() YAML policy loading.
# Added 2025-10-01, released under ASL 2.0.

. ${srcdir:=.}/diag.sh init

policy_valid="$RSYSLOG_DYNNAME.valid.yml"
cat >"$policy_valid" <<EOF_POLICY
interval: 5
burst: 10
EOF_POLICY

cfg_valid="$RSYSLOG_DYNNAME.valid.conf"
cat >"$cfg_valid" <<EOF_CFG
ratelimit(name="valid" policy="${policy_valid}")
action(type="omfile" file="/dev/null")
EOF_CFG

verify_log="$RSYSLOG_DYNNAME.policy.verify.log"
if ! ../tools/rsyslogd -N1 -f"$cfg_valid" -M../runtime/.libs:../.libs >"$verify_log" 2>&1; then
    if grep -q "libyaml support" "$verify_log"; then
        cat "$verify_log"
        echo "Skipping test because rsyslogd lacks libyaml support"
        skip_test
    fi
    cat "$verify_log"
    error_exit 1
fi
rm -f "$verify_log"

# Missing file handling.
missing_cfg="$RSYSLOG_DYNNAME.missing.conf"
cat >"$missing_cfg" <<EOF_MISSING
ratelimit(name="missing" policy="${RSYSLOG_DYNNAME}.doesnotexist.yml")
action(type="omfile" file="/dev/null")
EOF_MISSING
if ../tools/rsyslogd -N1 -f"$missing_cfg" -M../runtime/.libs:../.libs >"$verify_log" 2>&1; then
    cat "$verify_log"
    echo "Expected policy missing test to fail"
    error_exit 1
fi
if ! grep -q "could not open policy file" "$verify_log"; then
    cat "$verify_log"
    echo "Missing policy error message not found"
    error_exit 1
fi
rm -f "$verify_log"

# Mixing inline parameters with policy should fail.
mixed_cfg="$RSYSLOG_DYNNAME.mixed.conf"
cat >"$mixed_cfg" <<EOF_MIXED
ratelimit(name="mixed" policy="${policy_valid}" interval="1" burst="1")
action(type="omfile" file="/dev/null")
EOF_MIXED
if ../tools/rsyslogd -N1 -f"$mixed_cfg" -M../runtime/.libs:../.libs >"$verify_log" 2>&1; then
    cat "$verify_log"
    echo "Expected policy mixing test to fail"
    error_exit 1
fi
if ! grep -q "policy= cannot be combined" "$verify_log"; then
    cat "$verify_log"
    echo "Policy mixing error message not found"
    error_exit 1
fi
rm -f "$verify_log"

# Invalid YAML content (missing burst key).
invalid_yaml="$RSYSLOG_DYNNAME.invalid.yml"
cat >"$invalid_yaml" <<EOF_INVALID
interval: 3
EOF_INVALID
invalid_cfg="$RSYSLOG_DYNNAME.invalid.conf"
cat >"$invalid_cfg" <<EOF_INVALID_CFG
ratelimit(name="invalid" policy="${invalid_yaml}")
action(type="omfile" file="/dev/null")
EOF_INVALID_CFG
if ../tools/rsyslogd -N1 -f"$invalid_cfg" -M../runtime/.libs:../.libs >"$verify_log" 2>&1; then
    cat "$verify_log"
    echo "Expected invalid YAML test to fail"
    error_exit 1
fi
if ! grep -q "must define a burst" "$verify_log"; then
    cat "$verify_log"
    echo "Invalid YAML error message not found"
    error_exit 1
fi
rm -f "$verify_log"

exit_test
