# Development topology

Start the secret-free local fixtures with:

```sh
docker compose -f deploy/dev/compose.yaml up --build
```

The topology contains Kitsunebi, MySQL, and separate HTTP fixtures for GameAP,
TCPShield, artifact download, backup/monitoring observation, and DNS/external
endpoints. The controller is exposed on port `18080`; provider fixtures use
ports `18081` through `18085` and `18087`. The GameAP fixture is not GameAP 4
and cannot prove GameAP compatibility. It exposes deterministic provider
observations, including the process-manager plugin response used by the
controller's capability gate. The controller still accepts only persisted
typed actions and session-scoped staged-content references; this fixture does
not provide external lifecycle, file-manager, SFTP, or process-manager proof.
The controller listens on `http://127.0.0.1:18080`; its validated local
configuration uses `KITSUNEBI_LISTEN_ADDR`, `DATABASE_URL`, `GAMEAP_BASE_URL`,
`GAMEAP_PAT`, `KITSUNEBI_ARTIFACT_ROOT`, and `KITSUNEBI_WEB_STATIC_ROOT`.
The backup fixture is available on port `18084` for the separate provider
contract test. The controller leaves backup disabled in this topology;
production configures
`KITSUNEBI_BACKUP_BASE_URL` and `KITSUNEBI_BACKUP_TOKEN` together. Monitoring
uses the same paired configuration rule when enabled.
Production mode additionally requires `CLOUDFLARE_ACCESS_ISSUER`,
`CLOUDFLARE_ACCESS_AUDIENCE`, and `CLOUDFLARE_ACCESS_JWKS_URL`. Local mode
also enables the feature-gated
`KITSUNEBI_LOCAL_AUTH`; the TCPShield URL, API key, and network ID are an
all-or-nothing optional group. The local controller leaves that optional group
unset because the adapter only permits HTTP fixtures on loopback; the
TCPShield fixture is tested directly on port `18082`.
Local browser mutations use the fixed `KITSUNEBI_CSRF_TOKEN` development value;
production deployments must provide `KITSUNEBI_CSRF_SECRET` instead.
The authenticated integration flow uses the fixed, secret-free fixture in
`tests/integration/seed-local.sql`. Wait for `http://127.0.0.1:18080/ready`,
apply that SQL to the MySQL container, and then run
`tests/integration/run-mock.sh`. The script submits the persisted typed
observe/plan/approve/apply/verify/accept flow; direct lifecycle, file, and
backup resource mutations are not part of the controller integration path.
The seed grants the fixture actor access to service A and deliberately leaves
service B outside its scope. The integration script stages bytes with the
session `staged-content` endpoint and checks resumable per-step evidence; file
quarantine remains a controller-owned reversible move, not a fixture delete.
Run the real GameAP lifecycle contract only against a disposable server. It is
mutating, requires explicit consent and disposable-ID gates, and prints
`KITSUNEBI_GAMEAP_LIFECYCLE_ATTESTED=1` only after postconditions and state
restoration pass:

```sh
KITSUNEBI_REAL_GAMEAP=1 GAMEAP_BASE_URL=https://panel.example.invalid \
  GAMEAP_PAT=... GAMEAP_TEST_SERVER_ID=6 GAMEAP_TEST_NODE_ID=1 \
  GAMEAP_DISPOSABLE_SERVER_ID=6 \
  GAMEAP_LIFECYCLE_CONSENT=I_UNDERSTAND_DISPOSABLE_LIFECYCLE \
  tests/integration/real-gameap.sh
```

An optional `real-gameap` profile starts the official `gameap/gameap:4.4.2`
panel with its isolated PostgreSQL and Redis services and publishes the
panel's gRPC port on `18088`. GameAP's daemon is installed on the dedicated
server, not in the panel container. In the panel, create the disposable node
under Administration → Dedicated Servers, copy the one-use enrollment command,
and run it on that host. The command writes the daemon API key and mTLS
certificates; do not put either in this repository. The default external
address is `127.0.0.1:18088`, suitable for a daemon on the same machine. Set
`GAMEAP_GRPC_EXTERNAL_HOST` and `GAMEAP_GRPC_EXTERNAL_PORT` before starting the
profile when the daemon is on another host:

```sh
docker compose -f deploy/dev/compose.yaml --profile real-gameap up -d gameap-real
# Complete the panel's administrator setup and daemon enrollment before probing.
KITSUNEBI_REAL_GAMEAP=1 GAMEAP_BASE_URL=http://127.0.0.1:18086 \
  GAMEAP_PAT=... GAMEAP_TEST_SERVER_ID=6 GAMEAP_TEST_NODE_ID=1 \
  GAMEAP_DISPOSABLE_SERVER_ID=6 \
  GAMEAP_LIFECYCLE_CONSENT=I_UNDERSTAND_DISPOSABLE_LIFECYCLE \
  tests/integration/real-gameap.sh
```

The profile pins the [official `gameap/gameap:4.4.2` image](https://hub.docker.com/r/gameap/gameap/tags/4.4.2)
and follows its upstream environment, health-check, and gRPC enrollment shape
([upstream `.env.example`](https://raw.githubusercontent.com/gameap/gameap/v4.4.2/.env.example),
[upstream compose](https://raw.githubusercontent.com/gameap/gameap/v4.4.2/docker-compose.yml)).
Its database and signing keys are local fixtures only. Create one disposable
GameAP server bound to the enrolled daemon before probing it. This profile is
not proof of a Kitsunebi/GameAP integration: the controller intentionally stays
attached to `mock-gameap`, and no production credential is present here. The
real harness is the only source of the lifecycle attestation.

The lifecycle harness is the mutating proof and requires the consent and
disposable-ID gates shown above. The process-manager extension is a separate,
administrator-only installation and observation proof. Build, install, and
probe it only after the disposable node is enrolled:

```sh
GAMEAP_PLUGIN_CONSENT=I_UNDERSTAND_DISPOSABLE_PLUGIN_INSTALL \
GAMEAP_DISPOSABLE_NODE_ID=1 \
GAMEAP_PLUGIN_ID=pmobserve2j7d \
KITSUNEBI_REAL_GAMEAP=1 \
GAMEAP_BASE_URL=http://127.0.0.1:18086 \
GAMEAP_PAT=... GAMEAP_TEST_SERVER_ID=6 GAMEAP_TEST_NODE_ID=1 \
GAMEAP_DISPOSABLE_SERVER_ID=6 \
tests/contract/gameap/real-plugin.sh
```

The plugin is pinned to the official `gameap-proto` SDK revision in its
manifest and uses only the authenticated `gameap-nodecmd` host service. It
reports the closed process-manager set (`systemd`, `docker`, `podman`) or
`unknown`; it does not expose daemon configuration or arbitrary commands.
