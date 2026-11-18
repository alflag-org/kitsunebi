# Domain model

`MCPlayNetwork` is the deployment root. A `Service` describes what players are
offered. A `GameCluster` is an execution environment updated and switched as a
unit. Its immutable `ClusterRevision` fixes runtime profile, Minecraft version,
Java requirement, artifacts, config baseline, world and endpoint bindings,
placement/resource requirements, health checks, and startup parameters.

```text
Service -> current ClusterRevision -> World -> execution-unit binding
                                  -> ExternalEndpointBinding
ProxyPool -> ProxyInstance -> Route -> Service
```

`World` is persistent state, not a process. Its write mode and current writer
are explicit; ordinary worlds use one writer. `RuntimeProfile` describes the
family/build, artifact digest, Java requirement, and startup/console/health/
world-execution capabilities. `ProxyPool` contains instances in preparing,
ready, accepting, draining, stopped, or failed state. `Route` is Kitsunebi
policy, not a proxy runtime registry.

`ExternalEndpoint` stores a logical hostname, port, kind, and role; it does not
manage the database server. `AccessPolicy` grants role permissions within
service scopes. `ChangeSession` contains Operations and moves through open,
editing, ready, applying, verifying, accepted, rolled_back, aborted, or
conflicted. `BackupReference` and audit events link observations, hashes,
outcomes, and masked evidence.
