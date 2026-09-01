# Integration checks

The local integration check is `run-mock.sh`. It drives the public controller
API through one persisted ChangeSession:

```
observe -> plan (typed steps and per-step hashes) -> approve -> apply
  -> verify (controller re-observation) -> accept
```

Start `deploy/dev/compose.yaml`, wait for `/ready`, and seed the fixture policy
before running it:

```sh
docker compose -f deploy/dev/compose.yaml up --build --detach --wait
docker compose -f deploy/dev/compose.yaml exec -T mysql \
  mysql --protocol=TCP -ukitsunebi -pdev-password kitsunebi \
  < tests/integration/seed-local.sql
tests/integration/run-mock.sh
```

The script authenticates with the development-only local subject, stages bytes
through the session-scoped `POST /api/v1/change-sessions/{id}/staged-content`
contract, then submits a typed cluster plan containing a numeric GameAP node
binding and observed state hash. The plan action vocabulary covers
`execution_provision`, `execution_delete`, `execution_lifecycle`,
`service_lifecycle_transition`, `cluster_revision_create`,
`route_policy_update`, `artifact_register`, binding-aware `artifact_activate`,
file changes, proxy rollout, world/endpoint/access updates, backup, archive,
and purge; each action carries its typed compare-and-set material. The local
flow exercises the lifecycle action and process-manager observation while
keeping the staged-content reference session-scoped. Apply records resumable
per-step invocation/evidence and verify re-observes before accept. There are
no direct lifecycle, file-manager, or backup mutations in this flow.

Rollback is the explicit alternative at
`POST /api/v1/change-sessions/{id}/rollback`; it uses the stored operation
evidence and compare-and-set checks rather than an automatic compensating
path.

The provider containers are deterministic request-shape fixtures, not proof of
GameAP, TCPShield, monitoring, DNS, artifact, backup, or proxy-drain behavior.
They do not establish a real SFTP endpoint, external database, Cloudflare
Access policy, or connection-drain signal. Safe file quarantine and staged
artifact/file bytes are represented as typed request data; the mock flow
exercises staged file bytes, while quarantine remains a controller-owned
reversible move rather than a fixture delete. No fixture claim substitutes for
provider evidence.
The backup provider contract is tested separately by
`tests/contract/backup/mock-contract.sh`; it uses the typed
`external-database-reference` kind and explicit restore apply/verify phases.
Real probes are opt-in and must use disposable resources and explicit gates:

```sh
KITSUNEBI_REAL_GAMEAP=1 GAMEAP_BASE_URL=https://panel.example.invalid \
  GAMEAP_PAT=... GAMEAP_TEST_SERVER_ID=6 GAMEAP_TEST_NODE_ID=1 \
  GAMEAP_DISPOSABLE_SERVER_ID=6 \
  GAMEAP_LIFECYCLE_CONSENT=I_UNDERSTAND_DISPOSABLE_LIFECYCLE \
  tests/integration/real-gameap.sh
KITSUNEBI_REAL_TCPSHIELD=1 TCPSHIELD_BASE_URL=https://api.example.invalid \
  TCPSHIELD_API_KEY=... TCPSHIELD_NETWORK_ID=1 \
  TCPSHIELD_BACKEND_SET_ID=42 tests/integration/real-tcpshield.sh
```

These probes do not print credentials. A local fixture pass does not establish
production provider compatibility, backup evidence, proxy connection draining,
or Cloudflare Access behavior.
