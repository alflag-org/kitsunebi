# TCPShield contract fixtures

These fixtures cover the official OpenAPI 1.0 backend-set resource:

`GET`/`PATCH /networks/{networkId}/backendSets/{setId}`

Reference: <https://raw.githubusercontent.com/TCPShield/api-docs/development/tcpshield-api.yaml>

The published `BackendSetResponse` omits `backends`, even though the PATCH
request accepts it. The adapter therefore treats an omitted field as an
incomplete observation and never hashes it as an empty set. The API has no
ETag/idempotency/CAS or connection-drain endpoint: apply and rollback are
serialized per adapter instance, re-observe after PATCH, and return an
ambiguous/conflict result when the outcome cannot be proven. A separate
connection observer is required before declaring a drain complete.
