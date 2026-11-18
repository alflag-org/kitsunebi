#!/usr/bin/env python3
"""Routine operation regression against the disposable Compose controller."""
import json
import os
import uuid
from urllib.error import HTTPError
from urllib.request import Request, urlopen

CONTROLLER = os.environ.get("CONTROLLER_URL", "http://127.0.0.1:18080")
MOCK = os.environ.get("GAMEAP_MOCK_URL", "http://127.0.0.1:18081")
ACTOR = "00000000-0000-4000-8000-0000000000aa"
LIMITED = "00000000-0000-4000-8000-0000000000ab"


def call(base, path, value=None, *, actor=ACTOR, csrf="", key=None, expected=200):
    headers = {"Content-Type": "application/json", "Origin": CONTROLLER,
               "X-Kitsunebi-Local-Subject": actor, "X-CSRF-Token": csrf,
               "Idempotency-Key": key or str(uuid.uuid4())}
    request = Request(base + path, data=None if value is None else json.dumps(value).encode(), headers=headers)
    try:
        response = urlopen(request, timeout=30)
    except HTTPError as error:
        response = error
    body = json.load(response)
    assert response.status == expected, (path, response.status, expected, body)
    return body


def events():
    return call(MOCK, "/__mock/state")["events"]


def mutations():
    return [e for e in events() if e["path"].endswith(("/start", "/stop", "/restart"))]


csrf = call(CONTROLLER, "/api/v1/session", {})["csrf_token"]
limited_csrf = call(CONTROLLER, "/api/v1/session", {}, actor=LIMITED)["csrf_token"]
call(MOCK, "/__mock/reset", {})
call(MOCK, "/__mock/fault", {"plugin_absent": True})
health = call(CONTROLLER, "/api/v1/health/providers")
assert health["backup"]["status"] == "not_configured"
assert health["monitoring"]["status"] == "not_configured"
assert call(CONTROLLER, "/api/v1/services")
units = call(CONTROLLER, "/api/v1/execution-units")
assert any(unit.get("name") and unit["id"] == "6" for unit in units)

before = len(events())
listing = call(CONTROLLER, "/api/v1/execution-units/6/files?path=.")
assert listing and all(entry["digest"] is None for entry in listing)
file_requests = [e for e in events()[before:] if "/file-manager/" in e["path"]]
assert len(file_requests) == 1 and "/content" in file_requests[0]["path"], file_requests
call(CONTROLLER, "/api/v1/execution-units/6/files/read?path=configs%2Fexample.conf")

for actor, token, unit, status in [(LIMITED, limited_csrf, "6", 404), (ACTOR, csrf, "7", 404)]:
    count = len(mutations())
    call(CONTROLLER, f"/api/v1/execution-units/{unit}/lifecycle/prepare", {"action": "start"}, actor=actor, csrf=token, expected=status)
    assert len(mutations()) == count


def prepare(action):
    return call(CONTROLLER, "/api/v1/execution-units/6/lifecycle/prepare", {"action": action}, csrf=csrf)


def execute(preview, key, expected=200):
    return call(CONTROLLER, f'/api/v1/change-sessions/{preview["session_id"]}/execute-lifecycle',
                {"plan_id": preview["plan_id"], "plan_hash": preview["plan_hash"]}, csrf=csrf, key=key, expected=expected)


for action in ["start", "restart", "stop"]:
    preview = prepare(action)
    key = str(uuid.uuid4())
    count = len(mutations())
    result = execute(preview, key)
    assert result["status"] == "accepted", result
    assert len(mutations()) == count + 1
    replay = execute(preview, key)
    assert replay["id"] == result["id"] and replay["status"] == "accepted"
    assert len(mutations()) == count + 1

preview = prepare("start")
call(MOCK, "/api/servers/6/start", {})  # external state changes after confirmation
count = len(mutations())
execute(preview, str(uuid.uuid4()), expected=409)
assert len(mutations()) == count

preview = prepare("restart")
call(MOCK, "/__mock/fault", {"lifecycle_failure": True})
key = str(uuid.uuid4())
execute(preview, key, expected=502)
count = len(mutations())
assert execute(preview, key)["status"] == "failed"
assert len(mutations()) == count
print("routine lifecycle, replay, scope, approval, drift, listing and disabled-provider assertions passed")
