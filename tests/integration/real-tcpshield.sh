#!/bin/sh
set -eu

if [ "${KITSUNEBI_REAL_TCPSHIELD:-}" != 1 ]; then
  echo "real TCPShield checks skipped (set KITSUNEBI_REAL_TCPSHIELD=1)"
  exit 0
fi
: "${TCPSHIELD_BASE_URL:?TCPSHIELD_BASE_URL is required}"
: "${TCPSHIELD_API_KEY:?TCPSHIELD_API_KEY is required}"
: "${TCPSHIELD_NETWORK_ID:?TCPSHIELD_NETWORK_ID is required}"
: "${TCPSHIELD_BACKEND_SET_ID:?TCPSHIELD_BACKEND_SET_ID is required}"

command -v curl >/dev/null 2>&1 || {
  echo "curl is required for the real TCPShield probe" >&2
  exit 2
}

case "$TCPSHIELD_NETWORK_ID" in ''|*[!0-9]*) echo "TCPShield network ID must be numeric" >&2; exit 2 ;; esac
case "$TCPSHIELD_BACKEND_SET_ID" in ''|*[!0-9]*) echo "TCPShield backend-set ID must be numeric" >&2; exit 2 ;; esac
case "$TCPSHIELD_BASE_URL" in
  https://*) ;;
  *)
    echo "real TCPShield probe requires an HTTPS base URL" >&2
    exit 2
    ;;
esac
case "$TCPSHIELD_BASE_URL" in
  *\?*|*\#*|https://*@*)
    echo "TCPShield base URL must not contain credentials, query, or fragment" >&2
    exit 2
    ;;
esac

base=${TCPSHIELD_BASE_URL%/}
# These are read-only GETs. They intentionally do not infer backend state when
# the provider omits the `backends` field from BackendSetResponse.
curl --fail --silent --show-error --max-time 15 --max-filesize 1048576 \
  --proto '=https' --tlsv1.2 \
  --header "X-API-Key: $TCPSHIELD_API_KEY" \
  --output /dev/null \
  "$base/networks/$TCPSHIELD_NETWORK_ID/backendSets"

curl --fail --silent --show-error --max-time 15 --max-filesize 1048576 \
  --proto '=https' --tlsv1.2 \
  --header "X-API-Key: $TCPSHIELD_API_KEY" \
  --output /dev/null \
  "$base/networks/$TCPSHIELD_NETWORK_ID/backendSets/$TCPSHIELD_BACKEND_SET_ID"
echo "real TCPShield read-only backend-set probe passed"
