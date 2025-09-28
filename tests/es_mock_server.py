#!/usr/bin/env python3
"""Lightweight mock Elasticsearch server for omelasticsearch tests.

The goal is to provide a minimal HTTP surface so shell tests can run without
spawning a real Elasticsearch instance.  Only the endpoints and semantics used
inside tests/es-*.sh are implemented.  The implementation intentionally keeps
state in memory and is single-process to remain easy to reason about.
"""

from __future__ import annotations

import argparse
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse


class _IndexDoc:
    """Container for stored document metadata."""

    __slots__ = ("source", "version", "order")

    def __init__(self, source: Dict[str, object], version: int, order: int) -> None:
        self.source = source
        self.version = version
        self.order = order


class _IndexState:
    """Mutable index state tracked by the mock server."""

    __slots__ = ("docs", "mappings", "settings", "next_id", "lock")

    def __init__(self) -> None:
        self.docs: Dict[str, _IndexDoc] = {}
        self.mappings: Dict[str, Dict[str, object]] = {}
        self.settings: Dict[str, object] = {}
        self.next_id = 1
        self.lock = threading.Lock()

    def reset(self) -> None:
        with self.lock:
            self.docs.clear()
            self.mappings.clear()
            self.settings.clear()
            self.next_id = 1


class MockElasticsearchState:
    """Global state for the in-memory mock cluster."""

    def __init__(self) -> None:
        self.indices: Dict[str, _IndexState] = {}
        self.global_order = 0
        self.lock = threading.Lock()

    def get_index(self, index_name: str) -> _IndexState:
        with self.lock:
            if index_name not in self.indices:
                self.indices[index_name] = _IndexState()
            return self.indices[index_name]

    def delete_index(self, index_name: str) -> None:
        with self.lock:
            self.indices.pop(index_name, None)

    def clear(self) -> None:
        with self.lock:
            self.indices.clear()
            self.global_order = 0


STATE = MockElasticsearchState()
CLUSTER_NAME = "rsyslog-testbench"


def _load_json(body: bytes) -> Dict[str, object]:
    data = body.decode("utf-8") if body else "{}"
    return json.loads(data or "{}")


def _normalize_properties(mapping: Dict[str, object]) -> Dict[str, Dict[str, object]]:
    """Flatten mapping definitions into a property -> spec lookup."""

    if not mapping:
        return {}

    props: Dict[str, Dict[str, object]] = {}

    if "properties" in mapping:
        raw_props = mapping.get("properties", {})
        if isinstance(raw_props, dict):
            props.update({k: v for k, v in raw_props.items() if isinstance(v, dict)})
        return props

    for maybe_type in mapping.values():
        if isinstance(maybe_type, dict):
            nested_props = _normalize_properties(maybe_type)
            if nested_props:
                props.update(nested_props)
    return props


def _validate_against_mapping(index: _IndexState, doc: Dict[str, object]) -> Optional[Tuple[str, str]]:
    """Return an error tuple (type, reason) if mapping validation fails."""

    if not index.mappings:
        return None

    for field, spec in index.mappings.items():
        if not isinstance(spec, dict):
            continue
        if field not in doc:
            continue
        field_type = spec.get("type")
        value = doc[field]
        if field_type == "integer":
            try:
                # Elasticsearch accepts numeric strings that can be parsed.
                if isinstance(value, str):
                    if value.strip() == "":
                        raise ValueError
                    int(value, 10)
                elif isinstance(value, (int, float)):
                    int(value)
                else:
                    raise ValueError
            except (ValueError, TypeError):
                return (
                    "mapper_parsing_exception",
                    f"failed to parse field [{field}] of type [integer]",
                )
    return None


class MockHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args, **_kwargs):  # type: ignore[override]
        """Silence default logging to keep test output clean."""

    # Utilities -----------------------------------------------------------------
    def _json_response(self, payload: Dict[str, object], status: int = 200) -> None:
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _no_content(self, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.end_headers()

    # Endpoint handlers ---------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802 - required by BaseHTTPRequestHandler
        parsed = urlparse(self.path)
        parts = [part for part in parsed.path.split("/") if part]

        if not parts:
            payload = {"cluster_name": CLUSTER_NAME, "tagline": "rsyslog mock"}
            self._json_response(payload)
            return

        if len(parts) == 2 and parts[1] == "_refresh":
            # Refresh is a no-op but succeeds even if the index is unknown.
            self._json_response({"_shards": {"total": 1, "successful": 1, "failed": 0}})
            return

        if len(parts) == 2 and parts[1] == "_search":
            index_name = parts[0]
            params = parse_qs(parsed.query)
            size = int(params.get("size", [10])[0])
            index = STATE.indices.get(index_name)
            hits: List[Dict[str, object]] = []
            total = 0
            if index is not None:
                docs = list(index.docs.items())
                docs.sort(key=lambda item: item[1].order)
                total = len(docs)
                for doc_id, doc in docs[:size]:
                    hits.append(
                        {
                            "_index": index_name,
                            "_type": "_doc",
                            "_id": doc_id,
                            "_source": doc.source,
                        }
                    )
            payload = {
                "took": 1,
                "timed_out": False,
                "hits": {"total": {"value": total, "relation": "eq"}, "hits": hits},
            }
            self._json_response(payload)
            return

        if len(parts) == 2 and parts[1] == "_settings":
            index_name = parts[0]
            index = STATE.get_index(index_name)
            payload = {index_name: {"settings": index.settings}}
            self._json_response(payload)
            return

        if len(parts) >= 2 and parts[1] == "_doc":
            index_name = parts[0]
            doc_id = parts[2] if len(parts) >= 3 else None
            index = STATE.indices.get(index_name)
            if index is None or (doc_id and doc_id not in index.docs):
                self._json_response({"found": False}, status=404)
                return
            if doc_id is None:
                self._json_response({"found": False}, status=404)
                return
            doc = index.docs[doc_id]
            payload = {
                "_index": index_name,
                "_type": "_doc",
                "_id": doc_id,
                "found": True,
                "_source": doc.source,
            }
            self._json_response(payload)
            return

        self._json_response({"error": "not_found"}, status=404)

    def do_DELETE(self) -> None:  # noqa: N802
        parts = [part for part in self.path.split("/") if part]
        if len(parts) == 1:
            STATE.delete_index(parts[0])
            self._json_response({"acknowledged": True})
            return
        self._json_response({"error": "not_found"}, status=404)

    def do_PUT(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        parts = [part for part in parsed.path.split("/") if part]
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))

        if len(parts) == 1:
            index_name = parts[0]
            index = STATE.get_index(index_name)
            payload = _load_json(body)
            mappings = _normalize_properties(payload.get("mappings", {}))
            if mappings:
                index.mappings = mappings
            settings = payload.get("settings")
            if isinstance(settings, dict):
                index.settings = settings
            self._json_response({"acknowledged": True})
            return

        if len(parts) == 2 and parts[1] == "_settings":
            index = STATE.get_index(parts[0])
            payload = _load_json(body)
            if isinstance(payload, dict):
                index.settings.update(payload.get("index", {}))
            self._json_response({"acknowledged": True})
            return

        # Single-document index with explicit id.
        if len(parts) >= 2 and parts[1] == "_doc":
            index_name = parts[0]
            doc_id = parts[2] if len(parts) >= 3 else None
            if doc_id is None:
                self._json_response({"error": "missing document id"}, status=400)
                return
            index = STATE.get_index(index_name)
            doc_body = _load_json(body)
            error = _validate_against_mapping(index, doc_body)
            if error is not None:
                err_type, err_reason = error
                payload = {
                    "error": {"type": err_type, "reason": err_reason},
                    "status": 400,
                }
                self._json_response(payload, status=400)
                return
            with index.lock:
                version = index.docs.get(doc_id).version + 1 if doc_id in index.docs else 1
                STATE.global_order += 1
                index.docs[doc_id] = _IndexDoc(doc_body, version, STATE.global_order)
            payload = {
                "_index": index_name,
                "_type": "_doc",
                "_id": doc_id,
                "result": "created" if version == 1 else "updated",
                "_version": version,
                "_shards": {"total": 1, "successful": 1, "failed": 0},
                "status": 201 if version == 1 else 200,
            }
            self._json_response(payload, status=payload["status"])
            return

        self._json_response({"error": "not_found"}, status=404)

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        parts = [part for part in parsed.path.split("/") if part]
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))

        if parts and parts[-1] == "_bulk":
            self._handle_bulk(body)
            return

        if len(parts) >= 2 and parts[1] == "_doc":
            index_name = parts[0]
            doc_id = parts[2] if len(parts) >= 3 else None
            index = STATE.get_index(index_name)
            doc_body = _load_json(body)
            error = _validate_against_mapping(index, doc_body)
            if error is not None:
                err_type, err_reason = error
                payload = {
                    "error": {"type": err_type, "reason": err_reason},
                    "status": 400,
                }
                self._json_response(payload, status=400)
                return
            with index.lock:
                if doc_id is None:
                    doc_id = str(index.next_id)
                    index.next_id += 1
                existing = doc_id in index.docs
                version = index.docs[doc_id].version + 1 if existing else 1
                STATE.global_order += 1
                index.docs[doc_id] = _IndexDoc(doc_body, version, STATE.global_order)
            payload = {
                "_index": index_name,
                "_type": "_doc",
                "_id": doc_id,
                "result": "created" if version == 1 else "updated",
                "_version": version,
                "_shards": {"total": 1, "successful": 1, "failed": 0},
                "status": 201 if version == 1 else 200,
            }
            self._json_response(payload, status=payload["status"])
            return

        self._json_response({"error": "not_found"}, status=404)

    # Bulk helpers --------------------------------------------------------------
    def _handle_bulk(self, body: bytes) -> None:
        text = body.decode("utf-8") if body else ""
        lines = [line for line in text.splitlines() if line.strip()]
        if len(lines) % 2 != 0:
            self._json_response({"error": "malformed bulk request"}, status=400)
            return

        items: List[Dict[str, object]] = []
        errors = False

        for idx in range(0, len(lines), 2):
            header = json.loads(lines[idx])
            action, meta = next(iter(header.items()))
            doc_line = lines[idx + 1] if action != "delete" else None
            index_name = meta.get("_index")
            if not index_name:
                items.append({action: {"status": 400, "error": {"type": "invalid_index"}}})
                errors = True
                continue
            index_state = STATE.get_index(index_name)
            doc_id = meta.get("_id")
            status: int
            result = "created"
            error_info: Optional[Dict[str, object]] = None

            if action == "delete":
                with index_state.lock:
                    if doc_id and doc_id in index_state.docs:
                        del index_state.docs[doc_id]
                        status = 200
                        result = "deleted"
                    else:
                        status = 404
                        result = "not_found"
                item = {
                    action: {
                        "_index": index_name,
                        "_type": "_doc",
                        "_id": doc_id,
                        "status": status,
                        "result": result,
                    }
                }
                if status >= 400:
                    errors = True
                items.append(item)
                continue

            doc = json.loads(doc_line or "{}")
            validation_error = _validate_against_mapping(index_state, doc)
            with index_state.lock:
                existing = doc_id and doc_id in index_state.docs
                if validation_error is not None:
                    err_type, err_reason = validation_error
                    status = 400
                    error_info = {"type": err_type, "reason": err_reason}
                elif action == "create" and existing:
                    status = 409
                    result = "conflict"
                    error_info = {
                        "type": "version_conflict_engine_exception",
                        "reason": "document already exists",
                    }
                else:
                    if doc_id is None:
                        doc_id = str(index_state.next_id)
                        index_state.next_id += 1
                    version = index_state.docs.get(doc_id).version + 1 if existing else 1
                    STATE.global_order += 1
                    index_state.docs[doc_id] = _IndexDoc(doc, version, STATE.global_order)
                    status = 201 if version == 1 else 200
                    result = "created" if version == 1 else "updated"

            item = {
                action: {
                    "_index": index_name,
                    "_type": "_doc",
                    "_id": doc_id,
                    "status": status,
                    "result": result,
                }
            }
            if error_info is not None:
                item[action]["error"] = error_info
            if status >= 400:
                errors = True
            items.append(item)

        payload = {"took": 1, "errors": errors, "items": items}
        self._json_response(payload, status=200 if not errors else 400)


def main() -> None:
    parser = argparse.ArgumentParser(description="Mock Elasticsearch server for tests")
    parser.add_argument("-p", "--port", type=int, default=0, help="listen port (0 for auto)")
    parser.add_argument("--port-file", type=str, default="", help="write bound port to file")
    parser.add_argument("-i", "--interface", type=str, default="127.0.0.1", help="listen interface")
    args = parser.parse_args()

    httpd = HTTPServer((args.interface, args.port), MockHandler)
    actual_port = httpd.server_address[1]
    if args.port_file:
        with open(args.port_file, "w", encoding="utf-8") as handle:
            handle.write(str(actual_port))
    print(
        f"starting mock elasticsearch server at {args.interface}:{actual_port}",
        flush=True,
    )
    httpd.serve_forever()


if __name__ == "__main__":
    main()
