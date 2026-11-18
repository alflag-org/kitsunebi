# Backup provider adapter

`kitsunebi-backup` is an external HTTP provider adapter. It is not a storage
engine and does not claim integration with any organization-specific backup
service.

Production wiring uses:

```rust
let provider = kitsunebi_backup::BackupHttpProvider::new(
    "https://backup.example.invalid/",
    configured_bearer_secret,
)?;
```

The base URL must be HTTPS, contain no URL credentials/query/fragment, and the
provider is contacted without redirects. Responses are limited to 1 MiB and
the client has a bounded timeout. `new_localhost_for_tests` is the only HTTP
localhost constructor.

`BackupHttpProvider` implements the application `BackupProvider` port. The
typed create contract accepts only `change-snapshot`, `world`,
`service-consistent`, or `external-database-reference`. The application
`BackupRequest` supplies the `ChangeSessionId`, typed `BackupTarget`, request
hash, and caller idempotency key. The adapter sends only the provider wire
shape `{kind,target}` plus `Idempotency-Key`; the provider must return a
verified, non-empty opaque reference and a 64-character SHA-256 manifest
digest. The returned domain `BackupReference` retains the session, kind, and
target and remains unverified until the separate application verification
call supplies provider evidence.

The application `BackupProvider::verify` call uses
`POST /v1/backups/verify`. The provider must return `verified`, the observed
manifest digest, and an observation timestamp. Caller-supplied digests are
only compared with this provider observation; they are not evidence.

Restore is explicitly split into three phases:

```rust
let request = kitsunebi_application::BackupRestoreRequest {
    session_id,
    plan_id,
    plan_expiry,
    idempotency_key,
    reference: backup,
    target,
};
let invocation = application_backup_service.restore(&request, actor, service).await?;
```

Restore applies one idempotent mutation-bearing `POST /v1/restores/apply` and
returns a typed opaque invocation. The later change-session verification calls
`BackupProvider::verify_restore`, which observes provider postconditions through
`POST /v1/restores/verify`. A timeout is never retried internally; the caller
must re-observe using its durable operation state and treat the outcome as
ambiguous. Only the provider-returned target digest is accepted as restore
evidence.
