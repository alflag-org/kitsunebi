#!/bin/sh
set -eu

# Exercise the controller's canonical persisted plan flow against the local
# fixture. Provider endpoints are inspected only as external evidence.
controller=${CONTROLLER_URL:-http://127.0.0.1:18080}
gameap=${GAMEAP_MOCK_URL:-http://127.0.0.1:18081}
python=${PYTHON:-python3}
actor=${KITSUNEBI_FIXTURE_ACTOR:-00000000-0000-4000-8000-0000000000aa}
origin=${KITSUNEBI_FIXTURE_ORIGIN:-http://127.0.0.1:18080}
service=00000000-0000-4000-8000-0000000000a1
cluster=00000000-0000-4000-8000-0000000000a2
unit=${KITSUNEBI_FIXTURE_EXECUTION_A:-6}
binding=00000000-0000-4000-8000-0000000000a3
expiry=$(($(date +%s) + 1800))

tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM
body_file=$tmp_dir/body
header_file=$tmp_dir/headers

request() {
  request_context=unknown
  for argument do
    request_context=$argument
  done
  response_status=$(curl --silent --show-error --retry 3 --retry-delay 1 --retry-connrefused \
    --max-time 20 --output "$body_file" --dump-header "$header_file" \
    --write-out '%{http_code}' "$@")
}
expect_status() {
  [ "$response_status" = "$1" ] || {
    echo "unexpected HTTP status for $request_context: expected $1, got $response_status" >&2
    sed -n '1,80p' "$body_file" >&2
    exit 1
  }
}
expect_field() {
  "$python" - "$body_file" "$1" "$2" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
for part in sys.argv[2].split("."):
    value = value[part]
expected = sys.argv[3]
if expected in ("true", "false", "null") or expected.isdigit():
    expected = json.loads(expected)
assert value == expected, (sys.argv[2], value, expected)
PY
}
json_field() { "$python" - "$body_file" "$1" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
for part in sys.argv[2].split("."):
    value = value[part]
print(value)
PY
}
auth() {
  request -H "X-Kitsunebi-Local-Subject: $actor" -H "Origin: $origin" \
    -H "X-CSRF-Token: ${csrf_token:-dev-csrf-token}" "$@"
}
hash_payload() { printf '%s' "$1" | sha256sum | cut -d' ' -f1; }
envelope() {
  "$python" - "$1" "$2" "$3" "$4" "$5" <<'PY'
import json, sys
print(json.dumps({"command":sys.argv[1], "action":sys.argv[2],
                  "request_hash":sys.argv[3], "expires_at":int(sys.argv[4]),
                  "target_revision":None, "payload":json.loads(sys.argv[5])},
                 separators=(",", ":")))
PY
}
mutation() {
  command=$1; action=$2; key=$3; if_match=$4; path=$5; payload_json=$6
  # X-Request-Hash binds this command's typed payload. After planning, If-Match
  # independently carries the persisted plan hash as the apply CAS token.
  request_hash=${7:-$if_match}
  auth -X POST -H 'Content-Type: application/json' -H "Idempotency-Key: $key" \
    -H "If-Match: $if_match" -H "X-Request-Hash: $request_hash" \
    --data "$(envelope "$command" "$action" "$request_hash" "$expiry" "$payload_json")" \
    "$controller$path"
}
payload() {
  "$python" - "$@" <<'PY'
import hashlib, json, sys
kind = sys.argv[1]
if kind == "plan":
    session, service, cluster, binding, expiry, staged_digest, staged_size, execution_unit = sys.argv[2:]
    assert execution_unit.isdigit() and int(execution_unit) > 0
    fields = (execution_unit, "1", "cluster:" + cluster)
    encoded = b"".join(len(value.encode()).to_bytes(8, "big") + value.encode() for value in fields)
    binding_hash = hashlib.sha256(encoded).hexdigest()
    observed = hashlib.sha256(b"false").hexdigest()
    before_digest = hashlib.sha256(b"fixture=true\n").hexdigest()
    value = {"session_id":session, "service_id":service,
             "target":{"kind":"cluster", "value":cluster}, "domain_revision":0,
             "observed_state_hashes":[observed, before_digest],
             "expected_file_hashes":[before_digest],
             "steps":[
                 {"action":{"kind":"execution_lifecycle", "value":{
                     "binding_id":binding, "action":"start",
                     "expected_binding_hash":binding_hash, "expected_state_hash":observed,
                     "domain_revision":0}}},
                 {"action":{"kind":"file_write", "value":{
                     "binding_id":binding, "path":"configs/example.conf",
                     "expected_binding_hash":binding_hash, "domain_revision":0,
                     "expected_before_digest":before_digest,
                     "content":{"digest":staged_digest, "size":int(staged_size)},
                     "classification":"mutable_config"}}}
             ], "backup_required":False, "expires_at":int(expiry)}
elif kind == "approve":
    value = {"session_id":sys.argv[2], "plan_id":sys.argv[3], "plan_hash":sys.argv[4]}
elif kind == "apply":
    value = {"session_id":sys.argv[2], "plan_id":sys.argv[3]}
elif kind == "verify":
    value = {"session_id":sys.argv[2], "operation_id":sys.argv[3]}
elif kind == "accept":
    value = {"session_id":sys.argv[2], "operation_id":sys.argv[3]}
else:
    raise SystemExit("unknown payload kind")
tag = {"plan":"change-plan", "approve":"change-approve", "apply":"change-apply",
       "verify":"change-verify", "accept":"change-accept"}[kind]
print(json.dumps({"kind":tag, "value":value}, separators=(",", ":")))
PY
}

echo "public controller boundary"
request "$controller/live"; expect_status 200; expect_field status live
request "$controller/health"; expect_status 200; expect_field status healthy
request "$controller/ready"; expect_status 200; expect_field status ready
expect_field checks.controller_database ready
request "$controller/api/v1/unknown"; expect_status 404; expect_field error not_found
request "$controller/"; expect_status 200
request "$controller/api/v1/services"; expect_status 401; expect_field error unauthorized
request -X POST "$gameap/__mock/reset"; expect_status 200

echo "authenticated observe-plan-approve-apply-verify-accept flow"
request -X POST -H "X-Kitsunebi-Local-Subject: $actor" -H "Origin: $origin" \
  "$controller/api/v1/session"
expect_status 200
csrf_token=$(json_field csrf_token)
[ -n "$csrf_token" ]
auth -X POST -H 'Content-Type: application/json' -H 'Idempotency-Key: integration-begin-1' \
  --data "{\"service_id\":\"$service\",\"cluster_id\":\"$cluster\"}" \
  "$controller/api/v1/change-sessions"
expect_status 200
session_id=$(json_field id)
session_version=$(json_field version)
case "$session_version" in
  ''|*[!0-9]*) echo "invalid change-session version" >&2; exit 1 ;;
esac
[ "$session_version" -gt 0 ] || { echo "change-session version must be positive" >&2; exit 1; }
session_etag=\"$session_version\"

staged_file=$tmp_dir/staged-config
printf 'fixture=true\n# staged by change session\n' > "$staged_file"
auth -X POST -H 'Content-Type: application/octet-stream' \
  -H 'X-Kitsunebi-Classification: mutable_config' \
  -H "If-Match: $session_etag" \
  -H 'Idempotency-Key: integration-stage-content-1' \
  --data-binary "@$staged_file" \
  "$controller/api/v1/change-sessions/$session_id/staged-content"
expect_status 200
staged_digest=$(json_field digest)
staged_size=$(json_field size)
"$python" - "$staged_file" "$staged_digest" "$staged_size" <<'PY'
import hashlib, pathlib, sys
body = pathlib.Path(sys.argv[1]).read_bytes()
assert hashlib.sha256(body).hexdigest() == sys.argv[2]
assert len(body) == int(sys.argv[3])
PY
# Replaying the same staged bytes with the same key is part of the staging
# contract. The controller must return the original content reference rather
# than creating a second record or accepting different bytes.
auth -X POST -H 'Content-Type: application/octet-stream' \
  -H 'X-Kitsunebi-Classification: mutable_config' \
  -H "If-Match: $session_etag" \
  -H 'Idempotency-Key: integration-stage-content-1' \
  --data-binary "@$staged_file" \
  "$controller/api/v1/change-sessions/$session_id/staged-content"
expect_status 200
expect_field digest "$staged_digest"
expect_field size "$staged_size"

plan_payload=$(payload plan "$session_id" "$service" "$cluster" "$binding" "$expiry" "$staged_digest" "$staged_size" "$unit")
mutation plan change integration-plan-1 "$session_etag" \
  "/api/v1/change-sessions/$session_id/plan" "$plan_payload" "$(hash_payload "$plan_payload")"
expect_status 200
plan_id=$(json_field plan_id)
plan_hash=$(json_field plan_hash)

approve_payload=$(payload approve "$session_id" "$plan_id" "$plan_hash")
approve_request_hash=$(hash_payload "$approve_payload")
mutation approve change integration-approve-1 "$plan_hash" \
  "/api/v1/change-sessions/$session_id/approve" "$approve_payload" "$approve_request_hash"
expect_status 200; expect_field state ready

apply_payload=$(payload apply "$session_id" "$plan_id")
apply_request_hash=$(hash_payload "$apply_payload")
mutation apply change integration-apply-1 "$plan_hash" \
  "/api/v1/change-sessions/$session_id/apply" "$apply_payload" "$apply_request_hash"
expect_status 200; expect_field status verifying
operation_id=$(json_field id)

verify_payload=$(payload verify "$session_id" "$operation_id")
verify_request_hash=$(hash_payload "$verify_payload")
mutation verify change integration-verify-1 "$plan_hash" \
  "/api/v1/change-sessions/$session_id/verify" "$verify_payload" "$verify_request_hash"
expect_status 200; expect_field status verified

accept_payload=$(payload accept "$session_id" "$operation_id")
accept_request_hash=$(hash_payload "$accept_payload")
mutation accept change integration-accept-1 "$plan_hash" \
  "/api/v1/change-sessions/$session_id/accept" "$accept_payload" "$accept_request_hash"
expect_status 200; expect_field status accepted

request "$gameap/__mock/state"; expect_status 200
"$python" - "$body_file" <<'PY'
import json, sys
state = json.load(open(sys.argv[1], encoding="utf-8"))
events = [event for event in state["events"] if event.get("path", "").endswith("/start")]
assert len(events) == 1, len(events)
updates = [event for event in state["events"] if event.get("path", "").endswith("/update-file")]
assert len(updates) == 1, len(updates)
assert updates[0]["body"]["json"]["path"] == "configs/example.conf"
assert updates[0]["body"]["json"]["content"] == "fixture=true\n# staged by change session\n"
PY
echo "integration assertions passed"
