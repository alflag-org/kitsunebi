# Deployment

The storage crate uses MySQL through SQLx and migration
`migrations/0001_initial.sql`. Supply `DATABASE_URL`; MySQL and replication
remain external. Backup execution is optional: configure
`KITSUNEBI_BACKUP_BASE_URL` and `KITSUNEBI_BACKUP_TOKEN` together to use the
typed HTTP provider, or leave both unset to report backup as disabled and fail
closed for backup-required plans. The controller binary is
`kitsunebi-controller`.
Static assets are built in `web` with `npm --prefix web run build` and served from the
configured `KITSUNEBI_WEB_STATIC_ROOT`; they call `/api/v1` from the same origin.

The initial migration creates invariant-enforcing triggers, so the `DATABASE_URL`
identity must be allowed to run schema DDL and `CREATE TRIGGER`. On a server with
binary logging enabled, use an appropriately privileged migration path or configure
`log_bin_trust_function_creators=ON` for the migration, then restore it to `OFF`
immediately afterward. Runtime-only credentials are not sufficient for initial
schema setup.

The controller requires `KITSUNEBI_LISTEN_ADDR`, `DATABASE_URL`,
`GAMEAP_BASE_URL`, `GAMEAP_PAT`, `KITSUNEBI_ARTIFACT_ROOT`,
`KITSUNEBI_WEB_STATIC_ROOT`, `KITSUNEBI_ALLOWED_ORIGINS`,
`CLOUDFLARE_ACCESS_ISSUER`, `CLOUDFLARE_ACCESS_AUDIENCE`, and
`CLOUDFLARE_ACCESS_JWKS_URL`. Production also requires
`KITSUNEBI_CSRF_SECRET`, supplied by the deployment secret manager and at
least 32 non-whitespace bytes. `deploy/systemd/kitsunebi.env.example` is an
unset-value example and `deploy/systemd/kitsunebi.service` is the host unit.
When proxy draining is enabled, configure
`KITSUNEBI_MONITORING_BASE_URL` and `KITSUNEBI_MONITORING_TOKEN` together;
partial configuration is rejected. Provider outages are reported by the
authenticated `/api/v1/health/providers` detail endpoint; public `/health` and
`/ready` remain shallow controller probes, with `/ready` representing only the
controller database.
Local mode is feature-gated and cannot be enabled in production.

Browser clients first call the authenticated `POST /api/v1/session` endpoint
with the allowed Origin to receive a short-lived CSRF token. State-changing
browser requests send that token and the same Origin. Local development uses
`KITSUNEBI_CSRF_TOKEN` with the explicit `local-auth` feature/mode gates;
production uses the HMAC synchronizer token from `KITSUNEBI_CSRF_SECRET`.

Put the API behind Cloudflare Access and, where required, a Cloudflare Tunnel.
The API requires one `Cf-Access-Jwt-Assertion` header, validates the RS256
assertion against the HTTPS Access JWKS endpoint, and maps the verified subject
through the persisted actor identity and MySQL access policy. Before using CLI
automation, register the Access service-token subject as a Service actor in
that persisted identity table and grant its service-scoped permissions through
policy. The CLI reaches that boundary with `CF_ACCESS_CLIENT_ID` and
`CF_ACCESS_CLIENT_SECRET`; it does not send a GameAP token and does not derive
authorization from JWT claims. Store GameAP PATs, Access material, TCPShield
API keys, and
database credentials in a deployment secret manager, never in Git or domain
rows.

For a real GameAP 4 integration check, the opt-in `real-gameap` profile in
`deploy/dev/compose.yaml` runs the pinned panel and publishes its gRPC port.
Create a disposable node in the panel and run the one-use daemon enrollment
command on that node; the daemon API key and mTLS certificates stay on the
node. Then run `tests/integration/real-gameap.sh` with a deployment-resolved
PAT and explicit disposable-server consent. The mock Compose fixture and the
panel health check are not lifecycle proof.

A systemd unit may supervise the controller, but its exact unit and host policy
are deployment-owned. Monitor `/health`, `/ready`, `/metrics`, operation
events, adapter failures, MySQL, capability diagnostics, endpoint resolution,
proxy health, and backup verification. No real credentials or production proof
is included here.
