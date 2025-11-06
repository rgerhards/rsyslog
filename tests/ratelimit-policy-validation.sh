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

# YAML with per-source defaults and overrides should validate.
per_source_policy="$RSYSLOG_DYNNAME.per_source.yml"
cat >"$per_source_policy" <<EOF_PERSRC
default:
  max: 100
  window: 5s
overrides:
  - key: "noisy.example"
    max: 250
    window: 15s
EOF_PERSRC
per_source_cfg="$RSYSLOG_DYNNAME.per_source.conf"
cat >"$per_source_cfg" <<EOF_PERSRC_CFG
ratelimit(name="per_source" policy="${per_source_policy}")
action(type="omfile" file="/dev/null")
EOF_PERSRC_CFG
if ! ../tools/rsyslogd -N1 -f"$per_source_cfg" -M../runtime/.libs:../.libs >"$verify_log" 2>&1; then
    cat "$verify_log"
    echo "Expected per-source policy to validate successfully"
    error_exit 1
fi
rm -f "$verify_log"

# Overrides without a default block should fail.
missing_default_policy="$RSYSLOG_DYNNAME.missing_default.yml"
cat >"$missing_default_policy" <<EOF_MISSING_DEFAULT
overrides:
  - key: "noisy.example"
    max: 250
    window: 15s
EOF_MISSING_DEFAULT
missing_default_cfg="$RSYSLOG_DYNNAME.missing_default.conf"
cat >"$missing_default_cfg" <<EOF_MISSING_DEFAULT_CFG
ratelimit(name="missing_default" policy="${missing_default_policy}")
action(type="omfile" file="/dev/null")
EOF_MISSING_DEFAULT_CFG
if ../tools/rsyslogd -N1 -f"$missing_default_cfg" -M../runtime/.libs:../.libs >"$verify_log" 2>&1; then
    cat "$verify_log"
    echo "Expected missing-default policy test to fail"
    error_exit 1
fi
if ! grep -q "overrides require a default block" "$verify_log"; then
    cat "$verify_log"
    echo "Missing default error message not found"
    error_exit 1
fi
rm -f "$verify_log"

# Duplicate override keys should be rejected.
duplicate_override_policy="$RSYSLOG_DYNNAME.duplicate_override.yml"
cat >"$duplicate_override_policy" <<EOF_DUP_OVERRIDE
default:
  max: 50
  window: 10s
overrides:
  - key: "dup.example"
    max: 75
    window: 10s
  - key: "dup.example"
    max: 100
    window: 5s
EOF_DUP_OVERRIDE
duplicate_override_cfg="$RSYSLOG_DYNNAME.duplicate_override.conf"
cat >"$duplicate_override_cfg" <<EOF_DUP_OVERRIDE_CFG
ratelimit(name="duplicate_override" policy="${duplicate_override_policy}")
action(type="omfile" file="/dev/null")
EOF_DUP_OVERRIDE_CFG
if ../tools/rsyslogd -N1 -f"$duplicate_override_cfg" -M../runtime/.libs:../.libs >"$verify_log" 2>&1; then
    cat "$verify_log"
    echo "Expected duplicate override policy test to fail"
    error_exit 1
fi
if ! grep -q "defines override for key" "$verify_log"; then
    cat "$verify_log"
    echo "Duplicate override error message not found"
    error_exit 1
fi
rm -f "$verify_log"

# Overrides missing required fields must fail validation.
missing_field_policy="$RSYSLOG_DYNNAME.missing_field.yml"
cat >"$missing_field_policy" <<EOF_MISSING_FIELD
default:
  max: 50
  window: 10s
overrides:
  - key: "incomplete.example"
    max: 25
EOF_MISSING_FIELD
missing_field_cfg="$RSYSLOG_DYNNAME.missing_field.conf"
cat >"$missing_field_cfg" <<EOF_MISSING_FIELD_CFG
ratelimit(name="missing_field" policy="${missing_field_policy}")
action(type="omfile" file="/dev/null")
EOF_MISSING_FIELD_CFG
if ../tools/rsyslogd -N1 -f"$missing_field_cfg" -M../runtime/.libs:../.libs >"$verify_log" 2>&1; then
    cat "$verify_log"
    echo "Expected missing-field policy test to fail"
    error_exit 1
fi
if ! grep -q "overrides must define key/max/window" "$verify_log"; then
    cat "$verify_log"
    echo "Missing field error message not found"
    error_exit 1
fi
rm -f "$verify_log"

exit_test
