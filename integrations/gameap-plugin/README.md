# GameAP process-manager capability extension

This is a small, separately installed WASM plugin for the GameAP `4.4.2`
panel. It exists because the public node/API contract does not expose the
daemon's resolved `process_manager.name`.

The plugin registers an authenticated, administrator-only `POST /observe`
route. Its body is exactly `{ "node_id": <positive integer> }`. The plugin
uses the official `gameap-nodecmd` host service with the fixed command
`cat /etc/gameap-daemon/gameap-daemon.yaml`; no request value is interpolated
into the command. It parses only the documented `process_manager.name` field.
The response has exactly these fields:

```json
{
  "node_id": 42,
  "process_manager": "systemd",
  "evidence_hash": "<64 hex characters>",
  "version": "1",
  "timestamp": 1720000000
}
```

The only resolved values are `systemd`, `docker`, and `podman`. Unsupported,
missing, unreadable, or non-zero command results return `unknown`; the plugin
never infers a manager from the operating system and never returns daemon
configuration, command output, errors, or secrets. The hash commits to the
node ID, observed bytes, and resolved closed-set value without exposing the
bytes.

The default config path is an explicit upstream convention. Deployments using
a custom daemon config path will receive `unknown` until upstream exposes a
safe, typed capability for reading the resolved manager. The plugin has no
network, filesystem, environment, or arbitrary-shell access; `nodecmd` is the
single fixed host call.

Build and validate with the pinned SDK source revision:

```sh
cargo test
cargo build --target wasm32-wasip1 --release
```

Install the resulting `.wasm` only through an administrator-controlled GameAP
plugin installation flow. The plugin is an extension contract, not a claim
that Kitsunebi is integrated into the GameAP product.
