# Elastic Test Stack (PoC) — README (rsyslog namespace)

> Local, disposable Elasticsearch + Kibana for rsyslog dev testing.
> Two goals: (1) ingest JSON; (2) validate ECS (strict mapping).
> **Not for production.**

## What’s included

* Elasticsearch 8.x (single-node, security on)
* Kibana 8.x (auto-set `kibana_system` password via init step)
* Host ports: ES `127.0.0.1:9200`, Kibana `127.0.0.1:5601`
* Uses **rsyslog-ecs-dev-**\* naming to avoid Fleet’s default `logs-*`

## Prereqs

* Docker + Docker Compose
* Some free disk; ES data is volume-mapped

Optional env:

```bash
export ELASTIC_PASSWORD='S3cureElastic!'
export KIBANA_PASSWORD='S3cureKib!'
```

## Start / Stop

```bash
docker compose up -d
curl -u elastic:$ELASTIC_PASSWORD http://127.0.0.1:9200/
# stop (keep data)
docker compose down
# stop and wipe data
docker compose down -v
```

Open Kibana: [http://127.0.0.1:5601](http://127.0.0.1:5601)
Login: `elastic` / `$ELASTIC_PASSWORD`

## Create a Data View (once)

Kibana → Stack Management → Data Views → Create:

* Name: `rsyslog-ecs-dev`
* Index pattern: `rsyslog-ecs-dev*`
* Timestamp field: `@timestamp`
  Save. Then Kibana → Discover → select `rsyslog-ecs-dev`.

---

## Two-step testing

### 1) Ingestion-at-all (no ECS checks)

A tiny local smoke test exists:

* **`tests/es-container-test.sh`** (not in testbench; local only)
* Sends minimal docs to ES via `_bulk` to `rsyslog-ecs-dev-000001`.

Example script body (baseline):

```bash
#!/usr/bin/env bash
set -euo pipefail
ES_URL="${ES_URL:-http://127.0.0.1:9200}"
ES_USER="${ES_USER:-elastic}"
ES_PASS="${ES_PASS:-${ELASTIC_PASSWORD:-changeme}}"
INDEX="${INDEX:-rsyslog-ecs-dev-000001}"
tmp=$(mktemp)
cat >"$tmp"<<'EOF'
{ "create": { "_index": "rsyslog-ecs-dev-000001" } }
{ "@timestamp":"2025-01-01T00:00:00Z","message":"hello","host":{"hostname":"dev1"} }
{ "create": { "_index": "rsyslog-ecs-dev-000001" } }
{ "@timestamp":"2025-01-01T00:00:01Z","message":"second","host":{"hostname":"dev1"} }
EOF
curl -s -u "$ES_USER:$ES_PASS" -H 'Content-Type: application/x-ndjson' \
  --data-binary @"$tmp" "$ES_URL/_bulk" | tee /dev/stderr | grep -q '"errors":false'
echo "OK: bulk ingest succeeded."
```

Run:

```bash
chmod +x tests/es-container-test.sh
tests/es-container-test.sh
```

Check in Kibana → Discover.

### 2) ECS checks (strict mapping)

Install a strict index template for the **rsyslog** namespace:

```bash
curl -u elastic:$ELASTIC_PASSWORD -H 'Content-Type: application/json' \
  -X PUT http://127.0.0.1:9200/_index_template/rsyslog-ecs-dev -d '{
    "index_patterns": ["rsyslog-ecs-dev*"],
    "template": { "mappings": { "dynamic": "strict" } },
    "priority": 200
  }'
```

* Now typos (e.g., `host.nostname`) will fail with
  `mapper_parsing_exception`.
* You can later compose official ECS component templates into this
  index template; for PoC, `"dynamic":"strict"` is enough to catch mistakes.

Bulk result rule for CI/local scripts: fail if response has `"errors": true`.

---

## rsyslog example (local ES)

```rsyslog
template(name="ecs_json" type="list" option.jsonf="on") {
  property(outname="@timestamp"    name="timereported" format="jsonf")
  property(outname="message"       name="msg"          format="jsonf")
  property(outname="host.hostname" name="hostname"     format="jsonf")
}

action(
  type="omelasticsearch"
  server="127.0.0.1" serverport="9200" usehttps="off"
  searchIndex="rsyslog-ecs-dev"
  bulkmode="on"
  template="ecs_json"
  uid="elastic"
  pwd="$(echo $ELASTIC_PASSWORD)"
  errorfile="/var/log/omelasticsearch-dev.log"
)
```

---

## Troubleshooting

* **No data in Discover:** widen time range; confirm data view pattern;
  click “Refresh” fields in the data view.
* **Disk watermark / read-only:** ensure host path has space; clear flag:

  ```bash
  curl -u elastic:$ELASTIC_PASSWORD -H 'Content-Type: application/json' \
    -X PUT http://127.0.0.1:9200/_all/_settings \
    -d '{"index.blocks.read_only_allow_delete": null}'
  ```
* **Template clashes:** avoid `logs-*`; we use `rsyslog-ecs-dev-*`.
* **Kibana auth loop:** our compose sets `kibana_system` password before
  Kibana starts; don’t point Kibana at `elastic`.

---

## Cleanup

```bash
docker compose down -v
rm -rf ./esdata
```

## Scope

* PoC/dev only. Single node, no HA, no backups.
* For Elastic Cloud validation: keep JSON/templating identical and switch the
  endpoint/credentials only.
