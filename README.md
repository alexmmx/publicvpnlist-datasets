# PublicVPNList API and dataset tooling

This is the official public repository for the schemas, examples and validation
tooling used by the [PublicVPNList API](https://publicvpnlist.com/api/) and
bulk export pipeline.

The listed VPN servers are operated by third parties. PublicVPNList checks
technical reachability and measures speed, latency and freshness. It does not
verify privacy, identity, ownership, logging practices, anonymity or operator
trust. Endpoint state can change after a snapshot is published.

## Download and API

- API v1: https://publicvpnlist.com/api/
- Canonical JSON, CSV, TXT and XML downloads: https://publicvpnlist.com/exports/
- Methodology: https://publicvpnlist.com/methodology/
- Dataset schemas: [`schema/`](schema/)
- Request examples: [`examples/`](examples/)

Check `generated_at`, `expires_at` and each `last_checked_at` before using a
record obtained from the API or canonical exports.

## Repository scope

This initial publication intentionally contains no endpoint dataset, raw
`.ovpn` profile or ZIP bundle. Source-by-source redistribution rights and a
separate dataset license must be confirmed before data is mirrored to GitHub.
Until then, use the canonical API and exports linked above.

If dataset mirroring is approved later, snapshots will be validated before
publication, updated only for meaningful changes and kept out of unbounded Git
history. Immutable versions and large bundles will use GitHub Releases with an
explicit retention policy.

## Reporting and takedown

Report an incorrect, unwanted or non-working listing through
https://publicvpnlist.com/contacts/. Do not include credentials or private keys
in an issue. Security reports should follow [SECURITY.md](SECURITY.md).

See [DATA-LICENSE.md](DATA-LICENSE.md), [ATTRIBUTION.md](ATTRIBUTION.md) and
[CHANGELOG.md](CHANGELOG.md) before reusing data.
