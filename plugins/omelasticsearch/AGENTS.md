# AGENTS.md – omelasticsearch output module

## Module overview
- Ships events to Elasticsearch via HTTP bulk requests using libcurl.
- User documentation: `doc/source/configuration/modules/omelasticsearch.rst`.
- Support status: core-supported. Maturity: fully-mature.

## Build & dependencies
- Configure with `--enable-elasticsearch` to compile this plugin.
- `./devtools/codex-setup.sh` installs the required libcurl development headers
  inside the sandbox.
- Re-run `./configure` after toggling the flag; rerun `./autogen.sh` if you touch
  `configure.ac`, any `Makefile.am`, or macros under `m4/`.

## Local testing
- Enable module-specific tests with `--enable-elasticsearch-tests=minimal` (or
  `yes`) during `./configure`.
- Smoke test: `make es-basic.log`. Additional coverage: `make
  es-basic-ha.log`, `make es-bulk-errfile-popul.log`, and
  `make es-bulk-retry.log`.
- Tests require a local Elasticsearch instance. Use the helpers in
  `tests/diag.sh`, e.g.:
  ```bash
  (. ./tests/diag.sh; ensure_elasticsearch_ready; init_elasticsearch)
  ```
  `ES_DOWNLOAD` can be set before sourcing to pin a different release.

## Diagnostics & troubleshooting
- impstats exposes the `omelasticsearch` counter set (submitted, fail.http,
  fail.httprequests, fail.es, and the retry-focused `response.*` metrics when
  `retryfailures="on"`).
- Configure `errorfile="/path/to/errors.json"` while testing to capture raw
  Elasticsearch responses for triage.
- Watch for `writeoperation` validation failures; tests like
  `es-writeoperation.sh` enforce accepted values.

## Cross-component coordination
- Template changes that alter JSON structure must be mirrored in
  `doc/source/configuration/modules/omelasticsearch.rst` and in the
  parameter reference snippets under `doc/source/reference/parameters/`.
- Updates that touch the curl helper patterns should be reviewed alongside
  other HTTP-based plugins (e.g., `contrib/omhttp`).

## Metadata & housekeeping
- Keep `plugins/omelasticsearch/MODULE_METADATA.yaml` current when ownership or
  maturity changes.
- Update `doc/ai/module_map.yaml` and relevant tests if new configuration
  options or diagnostics are introduced.
