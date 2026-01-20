# Module Capabilities and Dependencies

This list details the capabilities, dependencies, and testability of specific modules.

## Module-Specific Capabilities

### `omelasticsearch`
- Buildable: Yes, even in minimal environments
- Depends on: `libcurl`
- Testable: No. Tests require a running Elasticsearch instance and are skipped in Codex or constrained environments

### `imjournal`
- Buildable: Yes
- Depends on: `libsystemd`
- Testable: No. Requires journald-related libraries and a systemd journal service context not present in the Codex container

### `imkafka` and `omkafka`
- Depends on: `librdkafka` (plus `liblz4` when linking statically)

### `fmpcre`
- Buildable: Yes when `libpcre3-dev` (or equivalent) is installed
- Testable: Yes, simple regression test `ffmpcre-basic.sh` exercises `pcre_match()`

### `omhiredis` and `imhiredis`
- Depends on: `hiredis`; `imhiredis` also needs `libevent`

### `ommongodb`
- Depends on: `libmongoc-1.0`

### `omamqp1` and `omazureeventhubs`
- Depends on: `libqpid-proton` (Azure module additionally needs `libqpid-proton-proactor`)

### `imhttp`
- Depends on: `civetweb` and `apr-util`

### `imdocker`
- Depends on: `libcurl` (>= 7.40.0)

### `impcap`
- Depends on: `libpcap`

### `imczmq` and `omczmq`
- Depends on: `libczmq` (>= 4.0.0)

### `omrabbitmq`
- Depends on: `librabbitmq` (>= 0.2.0)

### `omdtls` and `imdtls`
- Depends on: `openssl` (>= 1.0.2 for output, >= 1.1.0 for input)

### `omhttp`
- Depends on: `libcurl`

### `omhttpfs`
- Depends on: `libcurl`

### `mmnormalize`
- Depends on: `liblognorm` (>= 2.0.3)

### `mmkubernetes`
- Depends on: `libcurl` and `liblognorm` (>= 2.0.3)

### `mmgrok`
- Depends on: `grok` and `glib-2.0`

### `mmdblookup`
- Depends on: `libmaxminddb` (dummy module built if absent)

### `omlibdbi`
- Depends on: `libdbi`

### `ommysql`
- Depends on: `mysqlclient` via `mysql_config`

### `ompgsql`
- Depends on: `libpq` via `pg_config`

### `omsnmp`
- Depends on: `net-snmp`

### `omgssapi`
- Depends on: `gssapi` library
