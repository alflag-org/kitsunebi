# Architecture

Kitsunebi is the management plane; GameAP is the execution plane.

```text
browser / CLI -> Cloudflare Access -> Kitsunebi API (/api/v1)
                    |
            application + domain + MySQL
                    |
             ExecutionBackend
                    |
           GameAP HTTP / WebSocket
                    |
       process, console, files, node state
```

The domain owns MCPlayNetwork, Service, GameCluster, immutable
ClusterRevision, World, RuntimeProfile, ProxyPool/ProxyInstance, Route,
AccessPolicy, ArtifactSet, ConfigBaseline, ExternalEndpoint and bindings,
ChangeSession, Operation, BackupReference, LifecycleDecision, and GameAP
bindings. GameAP `server` and `node` objects are never domain truth.

Crates communicate through ports. Unknown capabilities or unavailable adapters
deny mutation. Public `/health` and `/ready` are shallow controller probes;
authenticated `/api/v1/health/providers` exposes detailed dependency health,
and `/metrics` exposes the scrape signal. Deployment supplies real dependency
health. Immutable revisions, change
sessions, backup references, optimistic `If-Match`, idempotency keys, and
adapter rollback keep failures independently observable and non-accepted.

Controller outage makes the management interface and new mutations unavailable,
but does not stop already-running GameAP processes, proxies, worlds, or player
sessions. Conversely, a GameAP panel outage does not imply that daemon-managed
processes stopped. Health output must keep these conditions distinct and does
not copy full metrics or logs into Kitsunebi storage.

The controller serves the built web assets as the same-origin fallback. The CLI
contains only HTTP transport and DTO construction; lifecycle, authorization,
and external calls stay behind the API and application ports.
