# TCPShield adapter

References (checked 2026-08-31):

- [TCPShield API overview](https://docs.tcpshield.com/miscellaneous/tcpshield-api)
- [Official OpenAPI 1.0](https://raw.githubusercontent.com/TCPShield/api-docs/development/tcpshield-api.yaml)

The adapter uses `X-API-Key` (Pro or higher) and the documented whole-backend-set
`PATCH /networks/{networkId}/backendSets/{setId}` payload (`name`, `backends`). It
observes and hashes normalized state, rejects external drift immediately before
mutation, and verifies the result. A response without `backends` is rejected as
incomplete rather than treated as an empty set, because the public
`BackendSetResponse` schema does not document that field and therefore cannot prove
the state hash needed for a safe mutation. The public API provides no ETag,
idempotency key, atomic CAS, or connection-draining proof; callers must supply
connection signals and must not treat an unknown signal as drain completion.
`Client::production` and `ReqwestTransport::new` accept HTTPS URLs only, reject
userinfo/query/fragment components, disable redirects, and enforce bounded
timeouts/responses. `Client::localhost_test` is the only HTTP exception and is
restricted to loopback hosts. Provider error bodies are discarded rather than
propagated into adapter errors.
