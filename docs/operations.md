# Operations

## Routine lifecycle operations

In Execution units or Change sessions, choose the named target and Start,
Stop, or Restart, then review and confirm. Stop and restart disconnect players.
The CLI uses the same server workflow: `kitsunebi server list`, followed by
`kitsunebi server restart 'Service name / cluster-key'`. It asks for confirmation;
`--yes` explicitly confirms an automated request. Duplicate names are rejected
by the CLI rather than selecting an arbitrary binding.
File commands use the same target names, for example
`kitsunebi files read 'Service name / cluster-key' --path server.properties`.

`POST /api/v1/execution-units/{id}/lifecycle/prepare` resolves the persisted
binding, current revision, and provider status and returns a persisted plan
with a five-minute expiry. `POST /api/v1/change-sessions/{id}/execute-lifecycle`
confirms that exact plan. Clients retain the returned identifiers internally;
operators do not enter hashes or revisions. Both requests require an
`Idempotency-Key` and the normal authentication/CSRF checks. The execution
request requires planning, approval, apply, verify, accept, and the selected
lifecycle permission. It never grants approval rights implicitly.

The controller records the existing change and operation evidence, verifies
provider state, and accepts only verified results. Repeating the same
confirmation returns the stored operation and does not repeat a completed or
failed provider mutation. A conflict requires inspecting operation history
and preparing a newly confirmed change. A lost connection does not imply the
provider operation failed. Advanced changes and explicit recovery remain in
the expandable section of Change sessions.

## Change control

All mutations use a persisted ChangeSession. The controller observes the
current state, stores a typed plan with an expiry, per-step observed hashes,
typed targets/actions, and staged content, then requires an explicit approval.
Apply loads that plan and session and executes it through application ports.
Verify re-observes each step and records provider evidence. Only a verified
operation can be accepted. Rollback is an explicit operation and is also
guarded by the stored revision, hashes, idempotency key, and `If-Match` value.
Caller-supplied provider IDs or observation hashes are not authoritative.

Unknown capability, missing provider evidence, stale revision, hash mismatch,
expiry, timeout, rate limit, partial response, or rollback conflict fails
closed. A failed or ambiguous external mutation remains unaccepted and is
reported in operation and audit evidence.

An idempotency key is bound to the exact typed request and its actor, service,
target, and session. An exact replay returns the persisted result; reusing the
key for a different request is rejected.

## Typed actions and staged content

The plan action set is closed and typed. It includes `execution_provision`,
`execution_delete`, `service_lifecycle_transition`, `cluster_revision_create`,
`execution_lifecycle`, file write/move/quarantine/batch, artifact
stage/`artifact_register` and binding-aware `artifact_activate`, proxy rollout,
world-writer cutover, endpoint rollout, access-policy update,
`route_policy_update`, backup create/restore, service archive, and service
purge. Each action names a domain object and contains the expected revision,
version, binding fingerprint, digest, or postcondition needed for a fresh
observation. Provider IDs are resolved from persisted bindings; they are not
accepted as plan authority.

File and artifact bytes are staged before planning with
`POST /api/v1/change-sessions/{id}/staged-content` using
`Content-Type: application/octet-stream`. The response is only a
content-addressed SHA-256 digest and byte size. The session and actor own that
reference until the plan expires, and the plan carries the reference rather
than embedding bytes. Size, digest, classification, and expiry are checked
again when the application loads the plan.

File quarantine is a safe, reversible operation. A managed or mutable-config
relative path is observed and moved into the controller-owned
`.kitsunebi-quarantine` namespace with its original hash recorded. Rollback
moves the same object back only when the binding and compare-and-set evidence
still match. Unknown, generated, state, and secret files are observe-only or
blocked; their reads expose metadata and digests only. They are never returned
as content, overwritten, or silently deleted.

Apply records a durable invocation and evidence entry for every step before it
advances. An in-progress operation can resume from those entries, while
retaining partial failure evidence. Once an operation is `failed`, automatic
retry is rejected: the provider may have taken effect before returning an
error, so the operator must inspect the durable evidence and request explicit
rollback. Verify performs a fresh provider observation and compares it with
the stored per-step evidence;
the caller cannot supply a replacement observation hash. Acceptance is
available only after that re-observation reaches `Verified`.

Access-policy updates replace grants for one persisted service policy. Every
desired grant must carry that same service's explicit scope; unscoped and
cross-service grants are rejected before planning. Service actors are usable
only for their persisted service binding; browser actors have no service
binding.

## Proxy rolling update

The plan stores the `TcpShieldBackendSet` and each `ProxyInstanceBinding`.
Execution creates the target GameAP execution unit when needed, writes its
owned staged mutable configuration and verifies each digest, then starts it
and verifies running status and backend health. Only then is the target added
to the stored TCPShield set. Removing the old backend disables new edge
assignments; monitoring only proves that active connections have reached zero.
The old GameAP execution is stopped only after that proof, and stopped status
is verified. Every provider response is checked against the stored binding and
set evidence. If any postcondition fails, compensation first restores and
verifies the old execution, then restores the prior backend set and cleans up
the target's effects. Explicit rollback uses the same order, so traffic is not
returned to an unready old execution. A configured monitoring connection-drain
signal is therefore a required dependency; if it is absent, ambiguous, or
stale, the controller fails closed and leaves the operation unaccepted.

## Worlds, clusters, artifacts, and configuration

World ownership is persisted on the service/cluster/world model and checked
with the expected domain revision. A world cutover is a planned typed action;
it is not a direct GameAP or filesystem mutation. Cluster revisions are
immutable. Artifact discovery, download, SHA-256 verification, and staging are
separate typed steps, and activation is bound to the change session and
revision. Managed configuration carries its owner, path classification,
expected digest, and staged bytes; secrets are never ordinary configuration.

File listings return provider names, sizes, and directory flags, with `digest:
null` for content that has not been read. Browsing a directory does not download
its entries. Read, diff, and write verification fetch the selected file; writes
still compare the expected pre-change digest, including for empty files.

SFTP is an operator-controlled path using OpenSSH credentials outside the
controller. A scan records GameAP file hashes before and after an explicit
change and stores the endpoint and session evidence. It makes no SFTP-server or
realtime-audit claim. Unknown files are observe-only; generated/state files are
not overwritten by configuration sync.

Endpoint updates resolve the target through the DNS adapter, compare the
expected record and revision, and verify endpoint health after the change.
DNS/TCPShield/monitoring unavailability or external drift blocks acceptance.

## Optional integrations

Backup and connection monitoring are optional configuration groups. Their
absence does not block resource lists, status, files, or ordinary lifecycle
operations. Authenticated `/api/v1/health/providers` reports each as
`not_configured` or `configured`; configuration is not evidence of health or
successful integration. The backup and proxy screens show missing configuration.

Backup-required operations still need verified backup evidence. Proxy rollout
requires configured connection monitoring before any rollout effects and fresh
zero-connection evidence before stopping the old runtime. TCP reachability is
not proof of drained connections. Provider timeouts and incomplete observations
remain errors. See the backup and monitoring crate READMEs for the existing
HTTP contracts; these contracts do not provision an external service.

## Backup and restore

Backup steps use a typed `BackupReference`; the external provider contract uses
the exact `external-database-reference` kind when the reference points at an
external database. Create and restore requests are idempotent and persist the
provider invocation. Restore apply records the provider's invocation and
expected manifest digest; restore verify re-observes that digest. Caller
evidence cannot turn an unverified restore into an accepted operation. If the
configured backup HTTP provider is absent or unavailable, backup-required
plans fail closed and health reports the backup dependency separately.

## Sunset, archive, and purge

Sunsetting is a planned lifecycle transition. The archive sequence must stop
new joins, stop the route, verify the final world and external-database
references, stop the execution unit, revoke access, and persist archive
evidence. Each stage is independently observed and can be rolled back only
where the external provider supplies a safe compensating action.

Purge is a separate action allowed only for an already archived service. It
creates a tombstone while preserving audit history and operation evidence; it
does not reuse the archive or lifecycle path and never purges an active or
sunsetting service.

## Failure handling and health

`/health` and `/ready` are shallow controller probes and do not fan out to
providers. Authenticated operators can use `/api/v1/health/providers` for
GameAP panel/node/process-manager, backup, monitoring, DNS, and TCPShield
detail. Operation event streams re-authorize the actor on every poll, so a
revoked policy closes an open stream. A GameAP panel outage does not prove
that daemon-managed processes stopped, and a controller outage does not stop
running processes or proxies. Operators should inspect operation events,
adapter evidence, revision conflicts, endpoint resolution, proxy health, and
backup verification before retrying a failed change.
