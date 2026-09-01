# GameAP integration

The adapter is pinned to GameAP `4.4.2` (`crates/kitsunebi-gameap`) and carries
the checked schema digest in code. It uses the public HTTP API and WebSocket
only. The client models execution-unit provision/delete, lifecycle, status,
node/resource status, console, file operations, short-lived token, and
capability diagnostics. Provision, delete, and lifecycle are dispatched only
from a persisted typed plan after the controller resolves the domain
`GameAPBinding` and validates its fingerprint and compare-and-set material.

The PAT is server-side and never enters a browser. Console relay obtains a
short-lived token. File paths reject absolute paths, `..`, and percent-encoded
input; API uploads are limited to 50 MiB and adapter transfers to 512 MiB by
default. File metadata hashes are calculated by Kitsunebi after a download;
they are not a GameAP-provided hash.

Capability handling is conservative: unknown execution, lifecycle, placement,
deletion, or process-manager capabilities deny mutation. `Capabilities.version`
is empty by default because the public v4 API has no explicit version
operation; `GAMEAP_API_VERSION` is only an operator-supplied assertion, and
provisioning additionally requires `GAMEAP_ALLOW_CREATION=true`. Lifecycle is
supported only after the opt-in real v4.4.2 harness exercises start, stop, and
restart against an explicitly disposable server and restores its original
state. The harness emits `KITSUNEBI_GAMEAP_LIFECYCLE_ATTESTED=1`; a read-only
status probe is not an attestation. Process-manager placement is obtained from
the official plugin/client observation endpoint and persisted as a typed
`NodeCapabilityObservation`; absent, unknown, or mismatched observations block
mutation. File quarantine is a typed, reversible move into the controller's
`.kitsunebi-quarantine` namespace, guarded by path classification, observed
hashes, and the binding compare-and-set check. It never uses delete as a
quarantine substitute. A real panel is required to prove these external
contracts. The local Compose fixture may enable the attestation gate solely to
exercise deterministic request plumbing; that is not external GameAP proof.

Resources are versioned under `/api/v1`: networks, services, clusters,
revisions, worlds, proxy pools and instances, execution units, runtime
profiles, artifacts, config, endpoints, access policies, change sessions,
operations, backups, and audit events.
`openapi/openapi.json` is checked in and the API crate emits OpenAPI 3.1.
