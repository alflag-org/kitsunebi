# Security

Protected requests require one `Cf-Access-Jwt-Assertion` containing a Cloudflare
Access RS256 JWT. The API validates issuer, audience, `exp`/`nbf`/`iat`, key id,
and the HTTPS Access JWKS before mapping the subject through MySQL policy.
Roles are PlatformAdmin, Operator, ServiceMaintainer, and Auditor, with
service-scoped permissions. State-changing browser requests require one
allowed Origin and a CSRF token; service actors use the explicit originless
Cloudflare Access service-token path. Responses set `nosniff`, `DENY`, and
no-referrer headers. Mutations require the exact typed request hash, a
persisted plan hash where applicable, future expiry, `Idempotency-Key`, and
`If-Match`.

Cloudflare Access service-token subjects are not authorization data. An
administrator must register the subject in the persisted actor identity table
as a Service actor and grant its permissions through the stored access policy
before automation can use the CLI. Roles and service scopes are never inferred
from JWT claims.

The API rejects absolute, parent-traversal, and percent-encoded file paths and
limits JSON bodies to 1 MiB and uploads to 50 MiB. Archive and purge use the
application lifecycle and archived state, not direct filesystem operations.
The archive-validation helper rejects traversal and symlink-like entries;
there is no archive extraction implementation in the current controller.
Concurrency uses optimistic tags and adapter checks; dangerous mutations are
limited to 30 per verified actor per 60 seconds. External timeout and
rate-limit failures remain failures.

Secrets use redacting wrappers and are excluded from audit previews. GameAP
PATs stay server-side; console uses short-lived tokens. Audit records preserve
actor, target, action, hashes, backup references, outcomes, and masked evidence.
Unknown capabilities and missing authentication/authorization fail closed.
Unknown, state, and secret file classes are metadata-only for reads; content
and mutation paths reject them.

Local authentication is enabled only by a controller build with the
`local-auth` feature, `KITSUNEBI_MODE=local`, and `KITSUNEBI_LOCAL_AUTH=true`;
production rejects that combination. Local requests must contain exactly one
canonical UUID in `X-Kitsunebi-Local-Subject` and no Cloudflare assertion;
the subject is the only value passed to the normal database-backed identity
mapper. Browser actors obtain a short-lived synchronizer token from the
authenticated `POST /api/v1/session` route. Production signs tokens with the
required `KITSUNEBI_CSRF_SECRET` (at least 32 non-whitespace bytes), binding
each token to the verified actor subject and rejecting malformed, expired, or
cross-actor tokens. The response is not cached and no token state is
persisted. Service actors retain the explicit originless mutation path and do
not send CSRF or Origin headers. Local mode uses the fixed development token
only when the `local-auth` build feature, `KITSUNEBI_MODE=local`, and
`KITSUNEBI_LOCAL_AUTH=true` are all active.
