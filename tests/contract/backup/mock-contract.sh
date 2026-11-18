#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../../.." && pwd)
state_dir=$(mktemp -d "${TMPDIR:-/tmp}/kitsunebi-backup-fixture.XXXXXX")
port=$(/usr/bin/python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')
server_pid=
cleanup() {
  if [ -n "$server_pid" ]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -rf "$state_dir"
}
trap cleanup EXIT HUP INT TERM

MOCK_KIND=backup MOCK_STATE_ROOT="$state_dir" PORT="$port" \
  /usr/bin/python3 "$repo_root/deploy/dev/mock-server.py" >/dev/null 2>&1 &
server_pid=$!
base="http://127.0.0.1:$port"
until curl --fail --silent "$base/health" >/dev/null 2>&1; do
  kill -0 "$server_pid" 2>/dev/null || exit 1
  sleep 0.05
done

create_body='{"kind":"external-database-reference","target":"fixture-external-db"}'
create_one=$(curl --fail --silent --show-error \
  -H 'Authorization: Bearer fixture-secret' \
  -H 'Idempotency-Key: create-1' \
  -H 'Content-Type: application/json' \
  --data "$create_body" "$base/v1/backups")
create_two=$(curl --fail --silent --show-error \
  -H 'Authorization: Bearer fixture-secret' \
  -H 'Idempotency-Key: create-1' \
  -H 'Content-Type: application/json' \
  --data "$create_body" "$base/v1/backups")
test "$create_one" = "$create_two"

create_conflict=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -H 'Idempotency-Key: create-1' -H 'Content-Type: application/json' \
  --data '{"kind":"world","target":"different-world"}' "$base/v1/backups")
test "$create_conflict" = 409

backup_verify=$(curl --fail --silent --show-error \
  -H 'Content-Type: application/json' \
  --data '{"reference":"fixture-backup-1"}' "$base/v1/backups/verify")
echo "$backup_verify" | /usr/bin/python3 -c '
import json, sys
response = json.load(sys.stdin)
assert response == {"manifest_digest": "a" * 64, "observed_at": 42, "verified": True}
'

restore_body='{"plan_ref":"plan-1","reference":"fixture-backup-1","target":"fixture-world"}'
restore_one=$(curl --fail --silent --show-error \
  -H 'Idempotency-Key: restore-1' -H 'Content-Type: application/json' \
  --data "$restore_body" "$base/v1/restores/apply")
restore_two=$(curl --fail --silent --show-error \
  -H 'Idempotency-Key: restore-1' -H 'Content-Type: application/json' \
  --data "$restore_body" "$base/v1/restores/apply")
test "$restore_one" = "$restore_two"
restore_invocation=$(echo "$restore_one" | /usr/bin/python3 -c '
import json, sys
response = json.load(sys.stdin)
assert response["invocation_ref"].startswith("fixture-restore-")
print(response["invocation_ref"])
')

restore_other=$(curl --fail --silent --show-error \
  -H 'Idempotency-Key: restore-2' -H 'Content-Type: application/json' \
  --data '{"plan_ref":"plan-1","reference":"fixture-backup-1","target":"fixture-world"}' \
  "$base/v1/restores/apply")
test "$restore_other" != "$restore_one"

restore_conflict=$(curl --silent --output /dev/null --write-out '%{http_code}' \
  -H 'Idempotency-Key: restore-1' -H 'Content-Type: application/json' \
  --data '{"plan_ref":"plan-1","reference":"fixture-backup-1","target":"different-world"}' \
  "$base/v1/restores/apply")
test "$restore_conflict" = 409

verify=$(curl --fail --silent --show-error \
  -H 'Content-Type: application/json' \
  --data "{\"invocation_ref\":\"$restore_invocation\"}" \
  "$base/v1/restores/verify")
echo "$verify" | /usr/bin/python3 -c '
import json, sys
response = json.load(sys.stdin)
assert response == {"observed_at": 42, "observed_manifest_digest": "a" * 64, "verified": True}
'

curl --fail --silent "$base/__mock/state" |
  /usr/bin/python3 -c '
import json, sys
state = json.load(sys.stdin)
assert state["backup_create_count"] == 1
assert state["backup_create_replays"] == 1
assert state["backup_restore_count"] == 2
assert state["backup_restore_replays"] == 1
assert all("fixture-secret" not in json.dumps(event) for event in state["events"])
'

curl --fail --silent --data '{"reset":true}' "$base/__mock/reset" >/dev/null
curl --fail --silent --data '{"unverified":true}' "$base/__mock/fault" >/dev/null
curl --fail --silent --show-error \
  -H 'Idempotency-Key: unverified-1' -H 'Content-Type: application/json' \
  --data "$create_body" "$base/v1/backups" |
  /usr/bin/python3 -c '
import json, sys
assert json.load(sys.stdin)["verified"] is False
'

curl --fail --silent --data '{"reset":true}' "$base/__mock/reset" >/dev/null
curl --fail --silent --data '{"oversize":true}' "$base/__mock/fault" >/dev/null
curl --fail --silent --output "$state_dir/oversize.json" --write-out '%{http_code}' \
  -H 'Idempotency-Key: oversize-1' -H 'Content-Type: application/json' \
  --data "$create_body" "$base/v1/backups" | /usr/bin/grep -qx '201'
/usr/bin/python3 -c '
from pathlib import Path
assert Path("'"$state_dir"'/oversize.json").stat().st_size > 1024 * 1024
'
echo "backup provider idempotency contract passed"
