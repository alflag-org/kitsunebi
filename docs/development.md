# Development

The workspace is a Rust project with domain, application, storage, API, GameAP,
TCPShield, artifacts, controller, and CLI crates. Use `rust-toolchain.toml`,
then run:

```sh
cargo fmt --all -- --check
cargo test --workspace --all-features
cargo test --test mysql-migrations --package kitsunebi-storage
```

The MySQL test is skipped unless `DATABASE_URL` is set; it checks first and
second migration plus domain persistence. The web application uses npm and
must be built before serving static assets:

```sh
npm --prefix web ci --no-audit --no-fund
npm --prefix web run check
npm --prefix web test
npm --prefix web run build
```

Keep `openapi/openapi.json` aligned with the versioned router and OpenAPI 3.1
output. Regenerate and verify the snapshot with the canonical exporter:

```sh
tmp_openapi=$(mktemp)
cargo run -p kitsunebi-api --example export_openapi > "$tmp_openapi" && cmp "$tmp_openapi" openapi/openapi.json
rm -f "$tmp_openapi"
```

Integration tests must be explicitly environment-gated and must not
use guessed credentials. Local tests do not prove a real GameAP process
manager, backup invocation, proxy drain signal, Cloudflare Access, or
production connectivity.

The local topology is defined by `deploy/dev/compose.yaml` and is started with:

```sh
docker compose -f deploy/dev/compose.yaml up --build
```

It includes MySQL and HTTP fixtures for GameAP, TCPShield, and DNS/endpoint
flows. The GameAP fixture reports a mock version and cannot prove GameAP 4
compatibility. The optional `real-gameap` profile starts the pinned official
GameAP 4.4.2 panel and exposes its gRPC enrollment port; an administrator must
enroll a disposable daemon and create a disposable server before the real
harness can pass. The controller still requires its exact validated configuration
(`KITSUNEBI_LISTEN_ADDR`, `DATABASE_URL`, `GAMEAP_BASE_URL`, `GAMEAP_PAT`,
`KITSUNEBI_ARTIFACT_ROOT`, `KITSUNEBI_WEB_STATIC_ROOT`,
`KITSUNEBI_ALLOWED_ORIGINS`); missing values fail closed. Production also
requires `CLOUDFLARE_ACCESS_ISSUER`, `CLOUDFLARE_ACCESS_AUDIENCE`, and
`CLOUDFLARE_ACCESS_JWKS_URL`. The Compose image enables the `local-auth`
feature and uses `KITSUNEBI_MODE=local`; direct local-auth runs must do the
same and set `KITSUNEBI_LOCAL_AUTH=true`. Local requests use exactly one
canonical UUID in `X-Kitsunebi-Local-Subject` and no Access assertion. The
real profile is opt-in and has no enrolled node or lifecycle attestation in
the repository, so mock and real integration gates remain separately
identified rather than represented as passed.

`tests/integration/run-mock.sh` exercises the same persisted API sequence used
by the controller: it creates a session, posts binary bytes to the
session-scoped `staged-content` endpoint, stores a typed plan with per-step
observations, and then approves, applies, verifies, and accepts it. The
fixture plan includes an execution lifecycle action and a staged mutable
configuration write. Durable step evidence makes an in-progress operation
resumable. Failed operations require explicit rollback and are not blindly
retried; the fixture still does not prove external GameAP, SFTP, backup, or
proxy-drain behavior. Run `tests/integration/real-gameap.sh` only with the
explicit
disposable-server consent and after daemon enrollment; it emits an attestation
only after a connected GameAP 4.x daemon and lifecycle restoration pass.
