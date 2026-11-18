# GameAP contract tests

`crates/kitsunebi-gameap/tests/contract.rs` is the deterministic mock contract suite. It asserts
the v4.4.2 operation paths, methods, request bodies, PAT header handling, `glst_` token JSON and
download query usage, fail-closed capability defaults, error redaction, and console relay shape.

The real-panel entry point is intentionally opt-in:

```sh
GAMEAP_BASE_URL=https://panel.example.invalid \
GAMEAP_PAT=resolved-server-side-secret \
GAMEAP_TEST_SERVER_ID=6 \
GAMEAP_TEST_NODE_ID=1 \
GAMEAP_DISPOSABLE_SERVER_ID=6 \
GAMEAP_LIFECYCLE_CONSENT=I_UNDERSTAND_DISPOSABLE_LIFECYCLE \
KITSUNEBI_REAL_GAMEAP=1 ./tests/contract/gameap/real.sh
```

The real test requires two explicit lifecycle gates and an ID that is declared disposable. It
requires the node status to report a connected GameAP 4.x gRPC daemon, initializes the file
manager, then exercises start, stop, and restart on that server, checks the `processActive` postcondition after
each mutation, and restores the original running/stopped state. Restoration failure fails the
harness. It never creates or deletes a server. `GAMEAP_PAT` is populated by a deployment secret
resolver and is never printed or persisted. The harness prints
`KITSUNEBI_GAMEAP_LIFECYCLE_ATTESTED=1` only after all checks and restoration pass. Read-only
probes do not establish lifecycle support; mock tests do not prove real-panel behavior.

For the local real-panel profile, start `gameap-real` from `deploy/dev/compose.yaml`, create the
administrator account and a disposable node in the panel, then run the panel-generated daemon
enrollment command on that node. The daemon connects to the panel's published gRPC port
(`18088` by default); the profile does not manufacture a daemon credential or certificate.

The process-manager capability extension has its own one-shot gate because
installation changes panel state. With the same disposable server/node IDs as
the lifecycle proof, run `real-plugin.sh` with
`GAMEAP_PLUGIN_CONSENT=I_UNDERSTAND_DISPOSABLE_PLUGIN_INSTALL`. It builds the
pinned `wasm32-wasip1` plugin, performs the official 4.x dry-run and install
routes, and then verifies the authenticated `/api/plugins/{id}/observe` response
contains only the typed node, closed manager value, version, timestamp, and
64-hex evidence hash. It never uninstalls the plugin or creates/deletes a
server. The script emits an attestation only after all three operations pass.
