# omelasticsearch developer notes

This document complements the module reference in
`doc/source/configuration/modules/omelasticsearch.rst` and focuses on local test
strategies for contributors.

## Local testing options

### Using the Python mock server

A lightweight HTTP server lives in `tests/es_mock_server.py`.  When the
environment variable `RSYSLOG_TEST_ES_MOCK` is set to `1`, the test harness uses
this mock instead of downloading a full Elasticsearch distribution.  The helper
functions in `tests/diag.sh` take care of spawning the background process,
recording its port, and tearing it down after the test run.

The mock implements the subset of Elasticsearch APIs that our shell scenarios
exercise:

* Handshake and cluster metadata via `GET /`, including the `cluster_name`
  string used by readiness probes.
* Index management (`PUT /{index}`, `PUT /{index}/_settings`, `DELETE
  /{index}`) with in-memory mappings and settings tracking.
* Document CRUD using the `_doc` type (`GET`, `POST`, and `PUT` to
  `/{index}/_doc/{id}`) with optimistic versioning and deterministic auto-ID
  generation.
* Search helpers (`GET /{index}/_refresh`, `GET /{index}/_search`) so tests can
  verify delivered payloads.
* Bulk ingestion with `POST /_bulk`, including conflict detection for
  `create` actions and synthetic error payloads for mapping violations.

These endpoints are intentionally limited to Elasticsearch 7.x-style
single-document types (`_doc`) and the JSON shapes that omelasticsearch expects
in success and failure responses.  They are sufficient for the existing
`es-basic*.sh`, `es-bulk-errfile*.sh`, `es-writeoperation.sh`, and
`es-duplicated-ruleset*.sh` scenarios, which focus on message formatting,
retries, and error-file population without relying on full-text search features.

To run a test against the mock server, export the flag and execute the scenario
as usual:

```bash
export RSYSLOG_TEST_ES_MOCK=1
./tests/es-basic.sh
```

You can also start the mock manually for ad-hoc experiments:

```bash
python3 tests/es_mock_server.py --port 19200
```

### Running against a real Elasticsearch node

Leaving `RSYSLOG_TEST_ES_MOCK` unset keeps the historical behaviour: the
`ensure_elasticsearch_ready` helper downloads (or reuses) the archive named by
`$ES_DOWNLOAD`—Elasticsearch 7.14.1 by default—unpacks it into the
`tests/.dep_wrk` directory, and starts it in the background before a test runs.
Pass `--no-start` to reuse an already running instance when you need to adjust
settings between cases.

## When a real cluster is still required

The mock does not attempt to simulate shard-level back pressure, thread pool
limits, security plugins, ingest pipelines, or other advanced cluster features.
The long-running `es-bulk-retry.sh` stress test remains skipped (exit code 77)
until we can reproduce Elasticsearch’s queue rejection behaviour in a lighter
fixture.  Use a real node when validating those scenarios or whenever you need
parity with specific upstream versions beyond the JSON shapes mentioned above.

## Legacy manual reproduction recipe

For completeness, here is the original recipe for provoking a mapping error with
curl:

1. Create an index named `testindex`.
   ```bash
   curl -XPUT localhost:9200/testindex/
   ```
2. Add a mapping that expects the field `timegenerated` to be an integer.
   ```bash
   curl -XPUT \
     localhost:9200/testindex/mytype/_mapping \
     -d '{"mytype":{"properties":{"timegenerated":{"type":"integer"}}}}'
   ```
3. Insert a document that violates the mapping.
   ```bash
   curl -XPOST \
     localhost:9200/testindex/mytype/ \
     -d '{"timegenerated":"bla"}'
   ```
   Elasticsearch responds with a `MapperParsingException` because the value is
   not numeric.
