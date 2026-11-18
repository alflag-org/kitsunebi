# GameAP API snapshot

This adapter targets GameAP `v4.4.2` (tag commit `7a94e0be672d5681e3b62d31881a0a695f6380df`).
`openapi-v4.4.2.yaml` is the official snapshot fetched from
`https://raw.githubusercontent.com/gameap/gameap/v4.4.2/openapi/openapi.yaml`.
Its SHA-256 is `e4225e17edba528a07cb808422af832bf89410fc8f88d2759b199ac92862363e`.
The public references used for this typed subset are the [API and Tokens](https://docs.gameap.com/api.html),
[WebSocket and Metrics](https://docs.gameap.com/websocket.html), and the official
[GameAP repository](https://github.com/gameap/gameap/tree/v4.4.2). Rust types in
`crates/kitsunebi-gameap/src/lib.rs` intentionally cover only the operations Kitsunebi uses.

The typed subset is: `POST /api/servers`, `DELETE /api/servers/{id}`, server
`start`/`stop`/`restart`/`status`, `GET /api/nodes/{id}/daemon`,
`POST /api/auth/short-lived-token`, server console and metrics WebSockets, and the
file-manager `content`, `update-file`, `upload`, `download`, `rename`, and `delete`
operations. Hashes are calculated from the download stream because the public file API has no
hash operation. Quarantine is intentionally not represented as a supported operation because
the public schema has no quarantine endpoint.

PATs remain server-side `Authorization` headers. WebSocket and file transfer operations use a
`glst_` short-lived token (10 seconds). The public Node schema does not expose `process_manager`,
and there is no explicit public version endpoint; both are reported as unknown rather than inferred.
