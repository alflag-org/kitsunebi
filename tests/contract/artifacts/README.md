# Artifact provider fixtures

These fixtures mirror the provider response shapes checked on 2026-08-31:

- [Modrinth Get version](https://docs.modrinth.com/api/operations/getversion/) — v2 version
  files and their `sha1`/`sha512` metadata.
- [PaperMC Fill v3](https://fill.papermc.io/) — `/v3/projects/paper/versions/{version}/builds`
  and the `downloads["server:default"]` object.
- [Hangar API](https://hangar.papermc.io/api-docs/) — the v1 `{pagination,result}` envelope.
- [GitHub Releases](https://docs.github.com/en/rest/releases) — latest release assets and their
  optional `sha256:` digest.

The fixtures are test inputs, not claims that a provider's upstream data is immutable.
