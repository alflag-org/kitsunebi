# Backup provider contract fixture

`mock-contract.sh` starts the task-owned `MOCK_KIND=backup` HTTP fixture and
checks the external provider contract without using a real backup service. It
uses the typed `external-database-reference` kind, requires an
`Idempotency-Key` for create and restore, replays the same payload without
creating a second provider operation, and returns conflict for a different
payload under the same key. Restore uses the explicit
`/v1/backups/verify`, `/v1/restores/apply`, and `/v1/restores/verify` phases;
the fixture returns the target manifest digest and observation timestamp from
verification rather than accepting caller evidence. Restore invocations are
deterministic per request identity: same-key replays match, conflicting
payloads fail, and different keys receive distinct invocation references.
Service-consistent create requests additionally carry a sorted `components` array containing the
same-session verified world references and exactly one verified external-database reference; the
fixture accepts this typed field while continuing to validate the common provider contract.
The fixture records only redacted request metadata and never contains a
provider secret.

Run it with:

```sh
tests/contract/backup/mock-contract.sh
```
