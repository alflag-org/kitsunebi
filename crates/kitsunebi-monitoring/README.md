# Kitsunebi monitoring adapter

This crate is an external observer adapter. It does not implement a monitoring
product or claim integration with an organization's monitoring system.

`MonitoringHttpObserver::new` accepts only an explicitly configured HTTPS base
URL. It queries `POST /v1/connections/observe` with `{ "target": "..." }` and
expects `{ "active": 0, "observed": true, "evidence_hash": "<64 hex>" }`.
The bearer credential is sent to the provider but is never included in the
adapter's `Debug` output or provider error messages.

The adapter polls at the configured interval until the configured deadline. It
returns as soon as the provider reports `active == 0` and `observed == true`.
At the deadline it returns the last valid observation, including active
connections, so the application workflow can fail closed. It never retries an
HTTP request internally. The POST is query transport only; the adapter performs
no provider mutation.

`new_localhost_for_tests` is the test-only constructor that permits HTTP for a
localhost fixture. Production configuration should pass the deployment's HTTPS
base URL and a bearer secret:

```rust
let observer = kitsunebi_monitoring::MonitoringHttpObserver::new(
    monitoring_url,
    monitoring_bearer,
    std::time::Duration::from_secs(2),
    std::time::Duration::from_secs(30),
)?;
```

The application service can inject this value wherever it accepts its
`kitsunebi_application::ConnectionObserver` port; no controller or provider
implementation is included here.
