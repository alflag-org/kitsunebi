#!/bin/sh
set -eu

if [ "${KITSUNEBI_REAL_GAMEAP:-}" != 1 ]; then
  echo "real GameAP contract checks skipped (set KITSUNEBI_REAL_GAMEAP=1)"
  exit 0
fi
: "${GAMEAP_BASE_URL:?GAMEAP_BASE_URL is required}"
: "${GAMEAP_PAT:?GAMEAP_PAT is required by the secret resolver}"
: "${GAMEAP_TEST_SERVER_ID:?GAMEAP_TEST_SERVER_ID is required}"
: "${GAMEAP_TEST_NODE_ID:?GAMEAP_TEST_NODE_ID is required}"
: "${GAMEAP_LIFECYCLE_CONSENT:?set GAMEAP_LIFECYCLE_CONSENT=I_UNDERSTAND_DISPOSABLE_LIFECYCLE}"
: "${GAMEAP_DISPOSABLE_SERVER_ID:?GAMEAP_DISPOSABLE_SERVER_ID must name the disposable server}"

command -v curl >/dev/null 2>&1 || {
  echo "curl is required for the real GameAP probe" >&2
  exit 2
}

if [ "$GAMEAP_LIFECYCLE_CONSENT" != I_UNDERSTAND_DISPOSABLE_LIFECYCLE ]; then
  echo "invalid lifecycle consent" >&2
  exit 2
fi
if [ "$GAMEAP_DISPOSABLE_SERVER_ID" != "$GAMEAP_TEST_SERVER_ID" ]; then
  echo "GAMEAP_TEST_SERVER_ID must equal the explicitly disposable server ID" >&2
  exit 2
fi
case "$GAMEAP_BASE_URL" in
  https://*) ;;
  http://127.0.0.1:*|http://localhost:*) ;;
  *) echo "GAMEAP_BASE_URL must use HTTPS (HTTP is allowed only for localhost fixtures)" >&2; exit 2 ;;
esac
command -v jq >/dev/null 2>&1 || {
  echo "jq is required to verify lifecycle status postconditions" >&2
  exit 2
}

case "$GAMEAP_TEST_SERVER_ID:$GAMEAP_TEST_NODE_ID" in
  *[!0-9:]*|:*) echo "server and node IDs must be numeric" >&2; exit 2 ;;
esac
if [ "$GAMEAP_TEST_SERVER_ID" = 0 ] || [ "$GAMEAP_TEST_NODE_ID" = 0 ]; then
  echo "server and node IDs must be positive integers" >&2
  exit 2
fi

auth="Authorization: Bearer $GAMEAP_PAT"
base=${GAMEAP_BASE_URL%/}
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT

status_is() {
  curl --fail --silent --show-error --header "$auth" \
    "$base/api/servers/$GAMEAP_TEST_SERVER_ID/status" >"$tmp"
  if [ "$1" = true ]; then
    jq -e '.processActive == true' "$tmp" >/dev/null
  else
    jq -e '.processActive == false' "$tmp" >/dev/null
  fi
}
wait_status() {
  expected=$1
  i=0
  while [ "$i" -lt 30 ]; do
    if status_is "$expected"; then return 0; fi
    i=$((i + 1))
    sleep 2
  done
  echo "lifecycle status did not reach processActive=$expected" >&2
  return 1
}
lifecycle() {
  action=$1
  curl --fail --silent --show-error --header "$auth" --request POST \
    "$base/api/servers/$GAMEAP_TEST_SERVER_ID/$action" >/dev/null
}

# Read-only probes establish access and prove that the disposable node is
# enrolled through the GameAP 4 gRPC daemon. A successful HTTP response alone
# is not enough: legacy or disconnected nodes cannot execute this contract.
curl --fail --silent --show-error --header "$auth" \
  "$base/api/nodes/$GAMEAP_TEST_NODE_ID/daemon" >"$tmp"
jq -e --arg node "$GAMEAP_TEST_NODE_ID" '
  type == "object" and
  (.id | tostring) == $node and
  .connection_type == "grpc" and
  (.version | type == "object") and
  (.version.version | type == "string" and test("^4\\."))
' "$tmp" >/dev/null || {
  echo "GameAP node is not connected through a GameAP 4.x gRPC daemon" >&2
  exit 1
}

curl --fail --silent --show-error --header "$auth" \
  "$base/api/file-manager/$GAMEAP_TEST_SERVER_ID/initialize" >"$tmp"
jq -e 'type == "object" and (.path | type == "string" and length > 0)' "$tmp" >/dev/null || {
  echo "GameAP file manager did not initialize the disposable server" >&2
  exit 1
}

curl --fail --silent --show-error --header "$auth" \
  "$base/api/servers/$GAMEAP_TEST_SERVER_ID/status" >"$tmp"
original=$(jq -er '.processActive | select(type == "boolean")' "$tmp")
restore() {
  if [ "$original" = true ]; then
    lifecycle start || return 1
    wait_status true
  else
    lifecycle stop || return 1
    wait_status false
  fi
}
exit_status=0
trap 'exit_status=$?; trap - EXIT; if ! restore; then echo "FAILED: could not restore original running state" >&2; exit_status=1; fi; rm -f "$tmp"; exit "$exit_status"' EXIT

if [ "$original" = true ]; then
  lifecycle stop
  wait_status false
  lifecycle start
  wait_status true
else
  lifecycle start
  wait_status true
  # Exercise restart while the disposable server is running.  A restart on a
  # stopped server is not a valid lifecycle contract probe.
  lifecycle restart
  wait_status true
  lifecycle stop
  wait_status false
fi
if [ "$original" = true ]; then
  lifecycle restart
  wait_status true
fi
echo "KITSUNEBI_GAMEAP_LIFECYCLE_ATTESTED=1"
echo "real GameAP 4.x lifecycle contract passed; disposable server restored"
