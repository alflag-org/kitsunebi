# kitsunebi

kitsunebi is the MCPlayNetwork management plane. It records services, clusters,
worlds, revisions, proxies, access policy, changes, artifacts, endpoints, and
backups. GameAP 4.4.2 remains the execution plane for process lifecycle,
console, files, node status, and resource status.

Kitsunebi does not manage Minecraft processes directly, expose GameAP
credentials to browsers, or treat a GameAP server/node as a domain object.

## Local start

Build the static UI before starting the controller:

```sh
npm --prefix web ci --no-audit --no-fund
npm --prefix web run build
```

The local fixture topology is started with:

```sh
docker compose -f deploy/dev/compose.yaml up --build
```

After `/ready` is healthy, load the deterministic policy fixture and run the
persisted typed controller flow:

```sh
docker compose -f deploy/dev/compose.yaml exec -T mysql \
  mysql --protocol=TCP -ukitsunebi -pdev-password kitsunebi \
  < tests/integration/seed-local.sql
tests/integration/run-mock.sh
```

This checks observe, plan, approve, apply, verify, and accept through the API;
provider fixtures are not production compatibility proof.

For a direct production controller start, MySQL and all required configuration
must be present: `KITSUNEBI_LISTEN_ADDR`, `DATABASE_URL`, `GAMEAP_BASE_URL`,
`GAMEAP_PAT`, `KITSUNEBI_ARTIFACT_ROOT`, `KITSUNEBI_WEB_STATIC_ROOT`,
`KITSUNEBI_ALLOWED_ORIGINS`, `CLOUDFLARE_ACCESS_ISSUER`,
`CLOUDFLARE_ACCESS_AUDIENCE`, and `CLOUDFLARE_ACCESS_JWKS_URL`.
Local mode omits the Cloudflare variables and requires
`KITSUNEBI_MODE=local`, `KITSUNEBI_LOCAL_AUTH=true`,
`KITSUNEBI_CSRF_TOKEN`, and a controller build with the `local-auth` feature.
Requests then use exactly one canonical UUID in
`X-Kitsunebi-Local-Subject`; the Cloudflare assertion header must be absent.
Local auth is rejected in production. `TCPSHIELD_BASE_URL`,
`TCPSHIELD_API_KEY`, and `TCPSHIELD_NETWORK_ID` are an optional all-or-nothing
group. `GAMEAP_ALLOW_CREATION` is disabled by default.

```sh
cargo test
cargo run -p kitsunebi-controller
```

The API exposes `/live`, `/health`, `/ready`, `/metrics`, versioned resources
under `/api/v1`, operation event SSE, and the execution-unit console WebSocket.
The CLI requires `KITSUNEBI_API_URL` and either the Cloudflare Access service
token pair `CF_ACCESS_CLIENT_ID`/`CF_ACCESS_CLIENT_SECRET` or
`CF_ACCESS_JWT_ASSERTION`. A service-token subject must already be registered
as a persisted Service actor identity and granted access by the stored policy;
the CLI and server never infer roles or service scopes from JWT claims. Local
HTTP requires
`KITSUNEBI_ALLOW_INSECURE_LOCALHOST=1`.

## Core workflows

Read resources through the API or CLI, then mutate through a ChangeSession with
a typed request hash, a persisted plan hash, future expiry, `Idempotency-Key`,
and `If-Match`. File and artifact bytes are first posted to the session's
`staged-content` endpoint and plans carry only their digest and size. The
application layer records the operation, per-step invocation/evidence, and
audit evidence. Changes follow plan, apply, verify, accept, or explicit
rollback; a failed operation is never retried automatically because the
provider may have applied the side effect before reporting an error.
Reusing an idempotency key with the same typed request returns the persisted
result; changing the request under that key is rejected.

Access-policy changes are service-owned: every desired grant must name the
target service explicitly. A missing or another service's scope is rejected.

GameAP mutations are allowed only when required capabilities are advertised.
The adapter uses a PAT server-side and obtains a short-lived token for console
relay. TCPShield backend-set changes use its isolated adapter.

## Documentation

- [Architecture](docs/architecture.md)
- [Domain model](docs/domain-model.md)
- [GameAP integration](docs/gameap.md)
- [Operations](docs/operations.md)
- [Deployment](docs/deployment.md)
- [Security](docs/security.md)
- [Development](docs/development.md)

## External proof status

Unit and static checks are local. A real GameAP, TCPShield, MySQL, Cloudflare
Access/Tunnel, backup, and proxy-drain environment is not present in this
workspace, so those integration gates remain unrun. The public GameAP process
manager contract and backup invocation contract are external inputs.
