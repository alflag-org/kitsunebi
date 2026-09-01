#!/bin/sh
set -eu

if [ "${KITSUNEBI_REAL_GAMEAP:-}" != 1 ]; then
  echo "real GameAP plugin checks skipped (set KITSUNEBI_REAL_GAMEAP=1)"
  exit 0
fi

: "${GAMEAP_BASE_URL:?GAMEAP_BASE_URL is required}"
: "${GAMEAP_PAT:?GAMEAP_PAT is required}"
: "${GAMEAP_TEST_SERVER_ID:?GAMEAP_TEST_SERVER_ID is required}"
: "${GAMEAP_TEST_NODE_ID:?GAMEAP_TEST_NODE_ID is required}"
: "${GAMEAP_DISPOSABLE_SERVER_ID:?GAMEAP_DISPOSABLE_SERVER_ID is required}"
: "${GAMEAP_DISPOSABLE_NODE_ID:?GAMEAP_DISPOSABLE_NODE_ID is required}"
: "${GAMEAP_PLUGIN_CONSENT:?GAMEAP_PLUGIN_CONSENT is required}"

if [ "$GAMEAP_PLUGIN_CONSENT" != I_UNDERSTAND_DISPOSABLE_PLUGIN_INSTALL ]; then
  echo "refusing real plugin install: set GAMEAP_PLUGIN_CONSENT=I_UNDERSTAND_DISPOSABLE_PLUGIN_INSTALL" >&2
  exit 1
fi
if [ "$GAMEAP_DISPOSABLE_SERVER_ID" != "$GAMEAP_TEST_SERVER_ID" ]; then
  echo "refusing real plugin install: disposable server ID must equal test server ID" >&2
  exit 1
fi
if [ "$GAMEAP_DISPOSABLE_NODE_ID" != "$GAMEAP_TEST_NODE_ID" ]; then
  echo "refusing real plugin install: disposable node ID must equal test node ID" >&2
  exit 1
fi
case "$GAMEAP_TEST_NODE_ID" in
  ''|*[!0-9]*) echo "GAMEAP_TEST_NODE_ID must be a positive integer" >&2; exit 1 ;;
esac
if [ "$GAMEAP_TEST_NODE_ID" = 0 ]; then
  echo "GAMEAP_TEST_NODE_ID must be a positive integer" >&2
  exit 1
fi
case "$GAMEAP_TEST_SERVER_ID" in
  ''|*[!0-9]*) echo "GAMEAP_TEST_SERVER_ID must be a numeric ID" >&2; exit 1 ;;
esac

case "$GAMEAP_BASE_URL" in
  https://*) ;;
  http://127.0.0.1:*|http://localhost:*) ;;
  *) echo "GAMEAP_BASE_URL must use HTTPS (HTTP is allowed only for localhost fixtures)" >&2; exit 1 ;;
esac

command -v cargo >/dev/null 2>&1 || { echo "cargo is required" >&2; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "curl is required" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "jq is required" >&2; exit 1; }

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../../.." && pwd)
plugin_manifest="$repo_root/integrations/gameap-plugin/Cargo.toml"
target_dir=${GAMEAP_PLUGIN_TARGET_DIR:-/tmp/kitsunebi-gameap-plugin-target}
plugin_id=${GAMEAP_PLUGIN_ID:-pmobserve2j7d}
wasm_path=${GAMEAP_PLUGIN_WASM:-$target_dir/wasm32-wasip1/release/kitsunebi_gameap_process_manager_plugin.wasm}
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/kitsunebi-gameap-plugin.XXXXXX")
trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM

# The plugin is a separately installed artifact. Building it here makes the
# exact SDK revision in its manifest part of the operator's proof.
CARGO_TARGET_DIR="$target_dir" cargo build \
  --manifest-path "$plugin_manifest" \
  --target wasm32-wasip1 \
  --release \
  >/dev/null
test -s "$wasm_path" || { echo "plugin build did not produce the expected WASM artifact" >&2; exit 1; }

auth_header="Authorization: Bearer $GAMEAP_PAT"
base=${GAMEAP_BASE_URL%/}

# Do not install a plugin when the node is not actually enrolled. The plugin
# can only reach gameap-nodecmd through the daemon's authenticated gRPC stream.
curl --fail --silent --show-error --max-time 30 \
  -H "$auth_header" \
  "$base/api/nodes/$GAMEAP_TEST_NODE_ID/daemon" >"$tmp_dir/daemon.json"
jq -e --arg node "$GAMEAP_TEST_NODE_ID" '
  type == "object" and
  (.id | tostring) == $node and
  .connection_type == "grpc" and
  (.version | type == "object") and
  (.version.version | type == "string" and test("^4\\."))
' "$tmp_dir/daemon.json" >/dev/null || {
  echo "GameAP node is not connected through a GameAP 4.x gRPC daemon" >&2
  exit 1
}

# Do not print either response: an administrator error can contain panel
# details. curl reports only its generic transport error on failure.
curl --fail --silent --show-error --max-time 30 \
  -H "$auth_header" \
  -F "file=@$wasm_path;type=application/wasm" \
  "$base/api/admin/plugins/upload/dry-run" >"$tmp_dir/dry-run.json"
jq -e --arg plugin_id "$plugin_id" '
  type == "object" and .is_valid == true and .errors == [] and .id == $plugin_id
' "$tmp_dir/dry-run.json" >/dev/null || {
  echo "GameAP rejected the process-manager plugin dry-run" >&2
  exit 1
}

curl --fail --silent --show-error --max-time 30 \
  -H "$auth_header" \
  -F "file=@$wasm_path;type=application/wasm" \
  "$base/api/admin/plugins/upload/install" >"$tmp_dir/install.json"
jq -e --arg plugin_id "$plugin_id" '
  type == "object" and (.status == "active" or .status == "installed")
' "$tmp_dir/install.json" >/dev/null || {
  echo "GameAP did not report an active process-manager plugin" >&2
  exit 1
}

printf '{"node_id":%s}\n' "$GAMEAP_TEST_NODE_ID" |
  curl --fail --silent --show-error --max-time 30 \
    -H "$auth_header" \
    -H 'Content-Type: application/json' \
    --data-binary @- \
    "$base/api/plugins/$plugin_id/observe" >"$tmp_dir/observe.json"
jq -e --argjson node "$GAMEAP_TEST_NODE_ID" '
  type == "object" and
  ([keys[]] | sort) == ["evidence_hash", "node_id", "process_manager", "timestamp", "version"] and
  .node_id == $node and
  (.process_manager | IN("systemd", "docker", "podman", "unknown")) and
  (.evidence_hash | type == "string" and test("^[0-9a-f]{64}$")) and
  .version == "1" and
  (.timestamp | type == "number" and . > 0)
' "$tmp_dir/observe.json" >/dev/null || {
  echo "GameAP returned an invalid process-manager observation" >&2
  exit 1
}

echo "KITSUNEBI_GAMEAP_PLUGIN_ATTESTED=1"
