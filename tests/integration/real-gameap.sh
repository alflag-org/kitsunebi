#!/bin/sh
set -eu

if [ "${KITSUNEBI_REAL_GAMEAP:-}" != 1 ]; then
  echo "real GameAP checks skipped (set KITSUNEBI_REAL_GAMEAP=1)"
  exit 0
fi
: "${GAMEAP_BASE_URL:?GAMEAP_BASE_URL is required}"
: "${GAMEAP_PAT:?GAMEAP_PAT is required}"

# The integration entry point is the mutating lifecycle contract. Its harness
# requires explicit consent and a disposable-server ID before it sends
# start/stop/restart requests. It prints only the postcondition assertion.
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec "$script_dir/../contract/gameap/real.sh"
