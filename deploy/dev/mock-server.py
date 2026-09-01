#!/usr/bin/env python3
"""Dependency-free provider fixtures for the local integration topology.

The fixture records request shape, ordering, and redacted headers. It is not a
GameAP implementation and must not be used as evidence for a real panel.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit


KIND = os.environ.get("MOCK_KIND", "gameap")
PORT = int(os.environ.get("PORT", "8080"))
ROOT = Path(os.environ.get("MOCK_STATE_ROOT", "/var/lib/mock"))
STATE_PATH = ROOT / "state.json"
LOG_PATH = ROOT / "requests.jsonl"
LOCK = threading.Lock()
SENSITIVE = (
    "token",
    "secret",
    "password",
    "api_key",
    "authorization",
    "cookie",
    "idempotency",
)
BACKUP_KINDS = {
    "change-snapshot",
    "world",
    "service-consistent",
    "external-database-reference",
}
BACKUP_MAX_TEXT_BYTES = 4096


def valid_backup_text(value: object, maximum: int = BACKUP_MAX_TEXT_BYTES) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        if len(value.encode()) > maximum:
            return False
    except UnicodeEncodeError:
        return False
    return not any(ord(character) < 32 or ord(character) == 127 for character in value)


def initial_state() -> dict:
    state = {
        "kind": KIND,
        "fault": {"outage": False, "partial": False},
        "sequence": 0,
        "events": [],
    }
    if KIND == "gameap":
        state["servers"] = {"6": {"processActive": False}}
        state["files"] = {
            "6": {
                "configs/example.conf": "fixture=true\n",
                "server.properties": "online-mode=false\n",
            }
        }
    elif KIND == "tcpshield":
        state["sets"] = {
            "1/42": {
                "id": 42,
                "name": "fixture-backends",
                "backends": ["old.example.invalid:25565"],
                "proxy_protocol": False,
                "vulcan_ac_enabled": False,
                "load_balancing_mode": 0,
            }
        }
    elif KIND == "artifact":
        state["artifacts"] = {"fixture.sha256": "kitsunebi fixture artifact\n"}
    elif KIND == "backup":
        state["backup"] = {
            "provider": "fixture-backup",
            "reference": "fixture-backup-1",
            "manifest_digest": "a" * 64,
            "verified": True,
            "active_connections": 0,
        }
        state["backup_idempotency"] = {"create": {}, "restore": {}}
    elif KIND == "dns":
        state["records"] = {"proxy.example.invalid": ["127.0.0.1"]}
    elif KIND == "monitoring":
        state["monitoring"] = {
            "active": 0,
            "observed": True,
            "evidence_hash": "a" * 64,
            "sequence": [],
        }
    return state


def load_state() -> dict:
    ROOT.mkdir(parents=True, exist_ok=True)
    if not STATE_PATH.exists():
        state = initial_state()
        save_state(state)
        return state
    try:
        return json.loads(STATE_PATH.read_text())
    except (OSError, json.JSONDecodeError):
        state = initial_state()
        save_state(state)
        return state


def save_state(state: dict) -> None:
    ROOT.mkdir(parents=True, exist_ok=True)
    temporary = STATE_PATH.with_suffix(".tmp")
    temporary.write_text(json.dumps(state, sort_keys=True) + "\n")
    temporary.replace(STATE_PATH)


def safe_value(value):
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if any(word in key.lower() for word in SENSITIVE) else safe_value(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [safe_value(item) for item in value]
    return value


def body_record(body: bytes) -> dict:
    result = {"size": len(body), "sha256": hashlib.sha256(body).hexdigest()}
    if body:
        try:
            result["json"] = safe_value(json.loads(body))
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass
    return result


def request_record(handler: BaseHTTPRequestHandler, body: bytes) -> dict:
    parsed = urlsplit(handler.path)
    query = parse_qs(parsed.query, keep_blank_values=True)
    redacted_query = {
        key: ["[REDACTED]"] if any(word in key.lower() for word in SENSITIVE) else values
        for key, values in query.items()
    }
    headers = {}
    for key in (
        "Authorization",
        "X-API-Key",
        "Content-Type",
        "Upgrade",
        "Origin",
        "Idempotency-Key",
        "If-Match",
        "X-Request-Hash",
    ):
        value = handler.headers.get(key)
        if value is not None:
            normalized = key.lower().replace("-", "_")
            redacted = normalized in SENSITIVE or normalized.endswith("_api_key")
            headers[key.lower()] = "[REDACTED]" if redacted else value
    return {
        "method": handler.command,
        "path": parsed.path,
        "query": redacted_query,
        "headers": headers,
        "body": body_record(body),
    }


def log_request(record: dict, state: dict) -> None:
    state["sequence"] += 1
    record["sequence"] = state["sequence"]
    state["events"].append(record)
    with LOG_PATH.open("a") as output:
        output.write(json.dumps(record, sort_keys=True) + "\n")


def json_bytes(value) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


class FixtureHandler(BaseHTTPRequestHandler):
    server_version = "kitsunebi-fixture/1"

    def _read_body(self) -> bytes:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        return self.rfile.read(max(0, min(length, 64 * 1024 * 1024)))

    def _respond(self, status: int, body: bytes, content_type: str = "application/json") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _request(self, body: bytes) -> tuple[dict, dict]:
        state = load_state()
        record = request_record(self, body)
        with LOCK:
            log_request(record, state)
            save_state(state)
        return state, record

    def _faulted(self, state: dict) -> bool:
        if state.get("fault", {}).get("outage"):
            self._respond(503, json_bytes({"error": "injected provider outage"}))
            return True
        return False

    def do_GET(self):  # noqa: N802
        if self.headers.get("Upgrade", "").lower() == "websocket":
            self._websocket()
            return
        state, _ = self._request(b"")
        if self.path.startswith("/__mock/state"):
            self._respond(200, json_bytes(state))
            return
        if self.path.startswith("/__mock/log"):
            try:
                body = LOG_PATH.read_bytes()
            except OSError:
                body = b""
            self._respond(200, body, "application/x-ndjson")
            return
        if self._faulted(state):
            return
        parsed = urlsplit(self.path)
        path = parsed.path
        query = parse_qs(parsed.query, keep_blank_values=True)
        if path in ("/health", "/live"):
            self._respond(200, json_bytes({"status": "ok", "kind": KIND}))
            return
        if KIND == "gameap":
            self._gameap_get(state, path, query)
        elif KIND == "tcpshield":
            self._tcpshield_get(state, path)
        elif KIND == "artifact":
            self._artifact_get(state, path)
        elif KIND == "backup":
            self._backup_get(state, path)
        elif KIND == "dns":
            self._dns_get(state, query)
        else:
            self._respond(404, json_bytes({"error": "not found"}))

    def do_HEAD(self):  # noqa: N802
        state, _ = self._request(b"")
        if self._faulted(state):
            return
        path = urlsplit(self.path).path
        if KIND == "gameap" and re.fullmatch(r"/api/file-manager/[^/]+/content", path):
            self._respond(200, b"", "application/octet-stream")
        else:
            self._respond(404, b"")

    def do_POST(self):  # noqa: N802
        body = self._read_body()
        state, _ = self._request(body)
        parsed = urlsplit(self.path)
        path = parsed.path
        if path == "/__mock/reset":
            with LOCK:
                state = initial_state()
                save_state(state)
            self._respond(200, json_bytes({"reset": True, "kind": KIND}))
            return
        if path == "/__mock/fault":
            try:
                update = json.loads(body or b"{}")
            except json.JSONDecodeError:
                update = {}
            with LOCK:
                state.setdefault("fault", {}).update(
                    {
                        key: bool(value)
                        for key, value in update.items()
                        if key in (
                            "outage",
                            "partial",
                            "unverified",
                            "restore_failure",
                            "oversize",
                            "monitoring_unobserved",
                        )
                    }
                )
                save_state(state)
            self._respond(200, json_bytes(state["fault"]))
            return
        if path == "/__mock/batch":
            try:
                batch = json.loads(body or b"{}")
            except json.JSONDecodeError:
                batch = {}
            changes = batch.get("changes")
            if not isinstance(changes, list) or not changes:
                self._respond(400, json_bytes({"error": "changes must be a non-empty array"}))
                return
            idem = self.headers.get("Idempotency-Key")
            seen = state.setdefault("idempotency", {})
            if idem and idem in seen:
                state["events"][-1]["batch_count"] = seen[idem]
                state["events"][-1]["idempotent_replay"] = True
                state["batch_replays"] = state.get("batch_replays", 0) + 1
                save_state(state)
                self._respond(200, json_bytes({"accepted": seen[idem], "replayed": True}))
                return
            state["events"][-1]["batch_count"] = len(changes)
            state["batch_requests"] = state.get("batch_requests", 0) + 1
            if idem:
                seen[idem] = len(changes)
            save_state(state)
            self._respond(200, json_bytes({"accepted": len(changes)}))
            return
        if self._faulted(state):
            return
        if KIND == "gameap":
            self._gameap_post(state, path, body)
        elif KIND == "backup":
            self._backup_post(state, path, body)
        elif KIND == "monitoring":
            self._monitoring_post(state, path, body)
        else:
            self._respond(404, json_bytes({"error": "not found"}))

    def do_PATCH(self):  # noqa: N802
        body = self._read_body()
        state, _ = self._request(body)
        if self._faulted(state):
            return
        if KIND == "tcpshield":
            self._tcpshield_patch(state, urlsplit(self.path).path, body)
        else:
            self._respond(404, json_bytes({"error": "not found"}))

    def do_DELETE(self):  # noqa: N802
        body = self._read_body()
        state, _ = self._request(body)
        if self._faulted(state):
            return
        if KIND == "gameap":
            server = self._match(self.path, r"/api/servers/([^/]+)$")
            if server:
                state.get("servers", {}).pop(server[0], None)
                save_state(state)
                self._respond(200, json_bytes({"status": "deleted"}))
                return
        self._respond(404, json_bytes({"error": "not found"}))

    def _gameap_get(self, state: dict, path: str, query: dict) -> None:
        if path == "/api/servers":
            self._respond(200, json_bytes({"items": list(state.get("servers", {}).values())}))
            return
        server = self._match(path, r"/api/servers/([^/]+)/status$")
        if server:
            self._respond(200, json_bytes(state["servers"].get(server[0], {"processActive": False})))
            return
        node = self._match(path, r"/api/nodes/([^/]+)/daemon$")
        if node:
            self._respond(200, json_bytes({"id": 1, "name": node[0], "connection_type": "http", "version": None}))
            return
        file_match = re.match(r"/api/file-manager/([^/]+)/content$", path)
        if file_match:
            self._gameap_file_get(state, file_match.group(1), query.get("path", ["."])[0])
            return
        initialize = self._match(path, r"/api/file-manager/([^/]+)/initialize$")
        if initialize:
            self._respond(200, json_bytes({"status": "ready", "server": initialize[0]}))
            return
        download = self._match(path, r"/api/file-manager/([^/]+)/download$")
        if download:
            value = state.get("files", {}).get(download[0], {}).get(query.get("path", [""])[0])
            if value is None:
                self._respond(404, json_bytes({"error": "file not found"}))
                return
            self._respond(200, value.encode(), "application/octet-stream")
            return
        self._respond(404, json_bytes({"error": "not found"}))

    def _gameap_file_get(self, state: dict, server: str, path: str) -> None:
        files = state.get("files", {}).get(server, {})
        if path in ("", "."):
            items = [
                {"name": name, "type": "file", "size": len(content.encode()), "modified": None}
                for name, content in sorted(files.items())
            ]
            self._respond(200, json_bytes({"type": "directory", "items": items}))
        elif path in files:
            self._respond(200, json_bytes({"type": "file", "content": files[path]}))
        else:
            self._respond(404, json_bytes({"error": "file not found"}))

    def _gameap_post(self, state: dict, path: str, body: bytes) -> None:
        try:
            value = json.loads(body) if body else {}
        except json.JSONDecodeError:
            value = {}
        plugin = self._match(path, r"/api/plugins/([^/]+)/observe$")
        if plugin:
            node_id = value.get("node_id") if isinstance(value, dict) else None
            if not isinstance(node_id, int) or node_id <= 0:
                self._respond(400, json_bytes({"error": "node_id is required"}))
                return
            self._respond(
                200,
                json_bytes(
                    {
                        "node_id": node_id,
                        "process_manager": "docker",
                        "evidence_hash": "a" * 64,
                        "version": "1",
                        "timestamp": int(time.time()),
                    }
                ),
            )
            return
        if path == "/api/servers":
            state.setdefault("servers", {})["created"] = {"processActive": False}
            save_state(state)
            self._respond(201, json_bytes({"message": "created", "result": {"taskId": 1, "serverId": 1}}))
            return
        action = self._match(path, r"/api/servers/([^/]+)/(start|stop|restart)$")
        if action:
            server, command = action
            state.setdefault("servers", {}).setdefault(server, {"processActive": False})
            state["servers"][server]["processActive"] = command != "stop"
            state["events"][-1]["action"] = command
            save_state(state)
            self._respond(200, json_bytes({"task_id": 1}))
            return
        if path == "/api/auth/short-lived-token":
            self._respond(200, json_bytes({"token": "glst_fixture", "expires_in": 5}))
            return
        update = self._match(path, r"/api/file-manager/([^/]+)/update-file$")
        if update:
            state.setdefault("files", {}).setdefault(update[0], {})[value.get("path", "")] = value.get("content", "")
            save_state(state)
            self._respond(200, json_bytes({"status": "updated"}))
            return
        upload = self._match(path, r"/api/file-manager/([^/]+)/upload$")
        if upload:
            state["events"][-1]["action"] = "upload"
            save_state(state)
            self._respond(200, json_bytes({"status": "uploaded"}))
            return
        rename = self._match(path, r"/api/file-manager/([^/]+)/rename$")
        if rename:
            files = state.setdefault("files", {}).setdefault(rename[0], {})
            kind = value.get("type")
            old = value.get("oldName")
            new = value.get("newName")
            if kind not in ("file", "dir") or not isinstance(old, str) or not isinstance(new, str):
                self._respond(400, json_bytes({"error": "type, oldName, and newName are required"}))
                return
            if old == new or new in files:
                self._respond(409, json_bytes({"error": "rename destination already exists"}))
                return
            if kind == "file":
                if old not in files:
                    self._respond(404, json_bytes({"error": "file not found"}))
                    return
                else:
                    files[new] = files.pop(old)
            else:
                prefix = old.rstrip("/") + "/"
                entries = [(name, content) for name, content in files.items() if name.startswith(prefix)]
                if not entries:
                    self._respond(404, json_bytes({"error": "directory not found"}))
                    return
                for name, content in entries:
                    files.pop(name)
                    files[new.rstrip("/") + name[len(old.rstrip("/")):]] = content
            state["events"][-1]["action"] = "rename"
            save_state(state)
            self._respond(200, json_bytes({"status": "renamed"}))
            return
        delete = self._match(path, r"/api/file-manager/([^/]+)/delete$")
        if delete:
            files = state.setdefault("files", {}).setdefault(delete[0], {})
            for item in value.get("items", []):
                files.pop(item, None)
            save_state(state)
            self._respond(200, json_bytes({"status": "deleted"}))
            return
        self._respond(404, json_bytes({"error": "not found"}))

    def _tcpshield_get(self, state: dict, path: str) -> None:
        key = self._match(path, r"/networks/(\d+)/backendSets(?:/(\d+))?$")
        if not key:
            self._respond(404, json_bytes({"error": "not found"}))
            return
        if len(key) == 1 or key[1] is None:
            values = [value for composite, value in state.get("sets", {}).items() if composite.startswith(key[0] + "/")]
            self._respond(200, json_bytes(values))
        else:
            value = state.get("sets", {}).get("/".join(key))
            self._respond(200 if value else 404, json_bytes(value or {"error": "not found"}))

    def _tcpshield_patch(self, state: dict, path: str, body: bytes) -> None:
        key = self._match(path, r"/networks/(\d+)/backendSets/(\d+)$")
        if not key:
            self._respond(404, json_bytes({"error": "not found"}))
            return
        try:
            value = json.loads(body) if body else {}
        except json.JSONDecodeError:
            value = {}
        current = state.setdefault("sets", {}).setdefault("/".join(key), {"id": int(key[1])})
        current.update({"name": value.get("name", current.get("name", "fixture")), "backends": value.get("backends", [])})
        state["events"][-1]["action"] = "patch"
        save_state(state)
        self._respond(200, json_bytes(current))

    def _artifact_get(self, state: dict, path: str) -> None:
        name = path.rsplit("/", 1)[-1]
        body = state.get("artifacts", {}).get(name)
        self._respond(200 if body is not None else 404, (body or "").encode(), "application/octet-stream")

    def _backup_get(self, state: dict, path: str) -> None:
        if path == "/backup/observe":
            self._respond(200, json_bytes(state.get("backup", {})))
        else:
            self._respond(404, json_bytes({"error": "not found"}))

    def _backup_post(self, state: dict, path: str, body: bytes) -> None:
        try:
            value = json.loads(body) if body else {}
        except json.JSONDecodeError:
            self._respond(400, json_bytes({"error": "invalid JSON"}))
            return
        backup = state.get("backup", {})
        if path == "/v1/backups":
            if (
                not isinstance(value, dict)
                or value.get("kind") not in BACKUP_KINDS
                or not valid_backup_text(value.get("target"))
            ):
                self._respond(400, json_bytes({"error": "kind and target are required"}))
                return
            idempotency_key = self.headers.get("Idempotency-Key")
            if (
                not idempotency_key
                or len(idempotency_key.encode()) > 256
                or any(ord(character) < 32 or ord(character) == 127 for character in idempotency_key)
            ):
                self._respond(400, json_bytes({"error": "Idempotency-Key is required"}))
                return
            request_hash = hashlib.sha256(body).hexdigest()
            seen = state.setdefault("backup_idempotency", {}).setdefault("create", {})
            previous = seen.get(idempotency_key)
            if previous is not None:
                if previous["request_hash"] != request_hash:
                    self._respond(409, json_bytes({"error": "idempotency key conflict"}))
                    return
                state["backup_create_replays"] = state.get("backup_create_replays", 0) + 1
                state["events"][-1]["action"] = "create-replay"
                save_state(state)
                self._respond(201, json_bytes(previous["response"]))
                return
            response = {
                "provider": backup.get("provider", "fixture-backup"),
                "reference": backup.get("reference", "fixture-backup-1"),
                "manifest_digest": backup.get("manifest_digest", "a" * 64),
                "verified": not state.get("fault", {}).get("unverified", False),
            }
            if state.get("fault", {}).get("oversize", False):
                response["padding"] = "x" * (1024 * 1024)
            state["events"][-1]["action"] = "create"
            state["backup_create_count"] = state.get("backup_create_count", 0) + 1
            seen[idempotency_key] = {"request_hash": request_hash, "response": response}
            save_state(state)
            self._respond(201, json_bytes(response))
            return
        if path == "/v1/backups/verify":
            if not isinstance(value, dict) or not value.get("reference"):
                self._respond(400, json_bytes({"error": "reference is required"}))
                return
            state["events"][-1]["action"] = "verify"
            save_state(state)
            self._respond(
                200,
                json_bytes(
                    {
                        "manifest_digest": backup.get("manifest_digest", "a" * 64),
                        "observed_at": 42,
                        "verified": not state.get("fault", {}).get("unverified", False),
                    }
                ),
            )
            return
        if path == "/v1/restores/apply":
            if (
                not isinstance(value, dict)
                or not valid_backup_text(value.get("plan_ref"))
                or not valid_backup_text(value.get("reference"))
                or not valid_backup_text(value.get("target"))
            ):
                self._respond(400, json_bytes({"error": "plan_ref, reference and target are required"}))
                return
            idempotency_key = self.headers.get("Idempotency-Key")
            if (
                not idempotency_key
                or len(idempotency_key.encode()) > 256
                or any(ord(character) < 32 or ord(character) == 127 for character in idempotency_key)
            ):
                self._respond(400, json_bytes({"error": "Idempotency-Key is required"}))
                return
            request_hash = hashlib.sha256(body).hexdigest()
            seen = state.setdefault("backup_idempotency", {}).setdefault("restore", {})
            previous = seen.get(idempotency_key)
            if previous is not None:
                if previous["request_hash"] != request_hash:
                    self._respond(409, json_bytes({"error": "idempotency key conflict"}))
                    return
                state["backup_restore_replays"] = state.get("backup_restore_replays", 0) + 1
                state["events"][-1]["action"] = "restore-apply-replay"
                save_state(state)
                self._respond(200, json_bytes(previous["response"]))
                return
            identity = hashlib.sha256(
                (idempotency_key + "\0" + request_hash).encode()
            ).hexdigest()[:32]
            response = {
                "invocation_ref": f"fixture-restore-{identity}",
                "accepted": not state.get("fault", {}).get("restore_failure", False),
            }
            state["events"][-1]["action"] = "restore-apply"
            state["backup_restore_count"] = state.get("backup_restore_count", 0) + 1
            seen[idempotency_key] = {"request_hash": request_hash, "response": response}
            state.setdefault("backup_restore_invocations", {})[response["invocation_ref"]] = {
                "manifest_digest": backup.get("manifest_digest", "a" * 64),
            }
            save_state(state)
            self._respond(200, json_bytes(response))
            return
        if path == "/v1/restores/verify":
            if not isinstance(value, dict) or not valid_backup_text(value.get("invocation_ref")):
                self._respond(400, json_bytes({"error": "invocation_ref is required"}))
                return
            invocation = state.get("backup_restore_invocations", {}).get(value["invocation_ref"])
            if invocation is None:
                self._respond(404, json_bytes({"error": "invocation not found"}))
                return
            state["events"][-1]["action"] = "restore-verify"
            save_state(state)
            self._respond(
                200,
                json_bytes(
                    {
                        "observed_manifest_digest": invocation["manifest_digest"],
                        "observed_at": 42,
                        "verified": not state.get("fault", {}).get("unverified", False),
                    }
                ),
            )
            return
        if path in ("/backup/verify", "/drain/observe"):
            self._respond(200, json_bytes(state.get("backup", {"verified": True, "active_connections": 0})))
        else:
            self._respond(404, json_bytes({"error": "not found"}))

    def _monitoring_post(self, state: dict, path: str, body: bytes) -> None:
        if path == "/__mock/monitoring":
            try:
                update = json.loads(body or b"{}")
            except json.JSONDecodeError:
                update = {}
            current = state.setdefault("monitoring", initial_state()["monitoring"])
            if isinstance(update, dict):
                if isinstance(update.get("active"), int) and update["active"] >= 0:
                    current["active"] = update["active"]
                if isinstance(update.get("observed"), bool):
                    current["observed"] = update["observed"]
                if isinstance(update.get("evidence_hash"), str):
                    current["evidence_hash"] = update["evidence_hash"]
                if isinstance(update.get("sequence"), list) and all(
                    isinstance(item, dict)
                    and isinstance(item.get("active"), int)
                    and item["active"] >= 0
                    and isinstance(item.get("observed"), bool)
                    and isinstance(item.get("evidence_hash"), str)
                    for item in update["sequence"]
                ):
                    current["sequence"] = update["sequence"]
            save_state(state)
            self._respond(200, json_bytes(current))
            return
        if path != "/v1/connections/observe":
            self._respond(404, json_bytes({"error": "not found"}))
            return
        try:
            value = json.loads(body or b"{}")
        except json.JSONDecodeError:
            self._respond(400, json_bytes({"error": "invalid JSON"}))
            return
        target = value.get("target") if isinstance(value, dict) else None
        if not isinstance(target, str) or not target or any(character in target for character in "\r\n"):
            self._respond(400, json_bytes({"error": "target is required"}))
            return
        monitoring = state.setdefault("monitoring", initial_state()["monitoring"])
        next_observation = monitoring.get("sequence", [])
        if next_observation:
            observation = next_observation.pop(0)
        else:
            observation = monitoring
        state["events"][-1]["action"] = "observe"
        state["events"][-1]["target"] = target
        save_state(state)
        self._respond(
            200,
            json_bytes(
                {
                    "active": observation.get("active", 0),
                    "observed": observation.get("observed", True)
                    and not state.get("fault", {}).get("monitoring_unobserved", False),
                    "evidence_hash": observation.get("evidence_hash", "a" * 64),
                }
            ),
        )

    def _dns_get(self, state: dict, query: dict) -> None:
        host = query.get("host", [""])[0]
        values = state.get("records", {}).get(host, [])
        if state.get("fault", {}).get("partial"):
            self._respond(206, json_bytes({"host": host, "addresses": values[:1], "partial": True}))
            return
        self._respond(200 if values else 404, json_bytes({"host": host, "addresses": values}))

    @staticmethod
    def _match(value: str, pattern: str):
        match = re.fullmatch(pattern, urlsplit(value).path)
        return match.groups() if match else None

    def log_message(self, _fmt, *_args):
        return

    def _websocket(self) -> None:
        state, _ = self._request(b"")
        if self._faulted(state):
            return
        key = self.headers.get("Sec-WebSocket-Key", "")
        accept = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
        self.send_response(101, "Switching Protocols")
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.end_headers()
        payload = json_bytes({"type": "console.output", "payload": {"text": "fixture"}, "ts": int(time.time())})
        frame = bytes([0x81, len(payload)]) + payload
        self.connection.sendall(frame)


HTTPServer(("0.0.0.0", PORT), FixtureHandler).serve_forever()
