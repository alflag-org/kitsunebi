# kitsunebi-artifacts

This crate stores binary artifacts by their lowercase SHA-256 digest. Uploads are size-limited,
hashed while streaming, written to a task-local temporary file, synced, and atomically renamed.
Existing content is returned idempotently. Provider discovery is metadata-only: it never stages or
activates a production update.

The concrete reqwest/rustls transport enforces a timeout, maximum response size, HTTPS by default,
an explicit host allowlist, and at most one redirect whose HTTPS and host are revalidated. Initial
URLs reject userinfo, query, and fragment components; a provider redirect may carry its own
short-lived query while remaining restricted to the allowlist and is never persisted. `DirectUrl`
accepts HTTPS only; a localhost test transport must be explicitly supplied by the caller. Download
bytes are streamed into a bounded buffer and hashed with SHA-256 before CAS insertion.

## Official provider references

URLs and behavior checked 2026-08-31:

- [Modrinth v2 Get version](https://docs.modrinth.com/api/operations/getversion/) — version files
  expose `sha1`/`sha512` hashes, URL, filename, and size. The adapter retains those as upstream
  metadata, never labels either as SHA-256, and computes the Kitsunebi SHA-256 after download.
- [GitHub Releases REST API](https://docs.github.com/en/rest/releases) and [release assets](https://docs.github.com/en/rest/releases/assets) — latest release assets include `browser_download_url`, size, and (when supplied) `sha256:<digest>`; requests send `Accept: application/vnd.github+json`, `X-GitHub-Api-Version: 2022-11-28`, and a User-Agent.
- [PaperMC Fill v3](https://fill.papermc.io/) — discovery uses
  `/v3/projects/paper/versions/{version}/builds` and `downloads["server:default"]`; requests send
  a User-Agent and retain the upstream SHA-256 digest and size before download.
- [Hangar API](https://hangar.papermc.io/api-docs/) — provider discovery uses the official v1
  `https://hangar.papermc.io/api/v1/projects/{project}/versions` endpoint, parses its
  `{pagination,result}` envelope, and sends a User-Agent.

Rate-limit responses are mapped to `RateLimited`; non-2xx responses are typed errors. Credentials
and response bodies are not logged by this crate.
