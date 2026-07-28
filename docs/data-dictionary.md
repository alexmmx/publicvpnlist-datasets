# PublicVPNList data dictionary

Schema version: `1.0`

The canonical current model is
[`schema/servers.schema.json`](../schema/servers.schema.json). It describes
technical metadata, not a ready-to-use VPN profile. Measurements do not
establish privacy, ownership, operator identity, logging policy or trust.

## Response envelope

Collection and object endpoints use `data`, `meta` and, except for the compact
health response, `links`. Errors contain `error.code`, a safe
`error.message`, an optional `error.parameter` and `error.request_id`.

`meta` identifies the represented snapshot with `schema_version`,
`dataset_version`, `snapshot_id`, `generated_at` and `expires_at`. Paginated
responses additionally expose `total`, `page`, `per_page` and `pages`.

## Snapshot metadata

| Field | Type | Meaning |
|---|---|---|
| `dataset_version` | string | Immutable `YYYYMMDDTHHMMSSZ-hash` version |
| `snapshot_id` | string | Opaque public snapshot identifier |
| `generated_at` | date-time | Snapshot build time |
| `expires_at` | date-time | Time after which clients treat it as stale |
| `next_update_at` | date-time | Planned next build |
| `record_count` | integer | Number of eligible records |
| `fresh_count` / `stale_count` | integer | Freshness partition; sum equals record count |
| `countries_count` | integer | Number of distinct non-null country codes |
| `source_count` | integer | Number of distinct approved source names |
| `protocols` | unique array | Protocols actually present |
| `protocols_count` | integer | Number of distinct protocols |
| `checksum_sha256` | string | Lowercase snapshot integrity digest |
| `source_url` | URI | Canonical catalog page |
| `documentation_url` | URI | API documentation |
| `license_url` | URI | Applicable data terms |
| `methodology_url` | URI | Measurement methodology |
| `score_notice` | string | Required limitation of the technical score |

## Current OpenVPN server

| Field | Type | Meaning |
|---|---|---|
| `id` | string | Stable `pvl_` plus 24 lowercase hex public ID |
| `country_code` / `country_name` / `city` | nullable | Display location metadata |
| `hostname` | hostname or null | Remote DNS name |
| `ip` | IPv4, IPv6 or null | Remote address |
| `protocol` | `openvpn` | Protocol discriminator |
| `transport` | `tcp` or `udp` | OpenVPN transport |
| `port` | integer 1–65535 | Remote port |
| `speed_mbps` / `upload_mbps` | non-negative or null | Measured throughput |
| `latency_ms` / `jitter_ms` | non-negative or null | Measured delay |
| `packet_loss_percent` | 0–100 or null | Measured loss |
| `uptime_percent_24h/7d/30d` | 0–100 or null | Complete-window uptime |
| `technical_quality_score` | integer 0–100 | Network quality only, never privacy |
| `last_checked_at` | date-time or null | Most recent check attempt |
| `last_success_at` | date-time or null | Most recent successful check |
| `first_seen_at` | date-time or null | First catalog observation |
| `freshness_status` | enum | `fresh`, `recent` or `stale` |
| `availability_status` | enum | State at the last check |
| `source_name` / `source_url` | string / URI | Provenance |
| `source_license` | string or null | Recorded source permission or terms |
| `redistribution_allowed` | boolean, optional | Explicit configuration permission |
| `server_page_url` | URI | Public metadata page |
| `config_download_url` | URI or null | Allowed only with explicit permission |
| `config_sha256` | SHA-256 or null | Integrity identifier, not config content |
| `risk_flags` | unique array | Machine-readable limitations |

Protocol-neutral design terms map to established API names:

| Design term | API field |
|---|---|
| `public_id` | `id` |
| `endpoint_host` | `hostname` |
| `endpoint_ip` | `ip` |
| `endpoint_port` | `port` |
| `ping_ms` | `latency_ms` |
| `download_mbps` | `speed_mbps` |

## Future WireGuard metadata

[`schema/wireguard-metadata.schema.json`](../schema/wireguard-metadata.schema.json)
is separate because protocol-specific state should not create dozens of
meaningless nulls in OpenVPN records. It allows a server public key only when
source rights permit it and validates that key as 32 decoded bytes.

Client private or preshared keys, complete client interfaces, provisioning
tokens, assigned internal addresses, raw profiles, credential-bearing QR
codes, SSH credentials and checker-internal URLs are not schema properties and
are rejected as unknown fields.

## Compatibility

API v1 field names remain stable. Additive optional fields are allowed and are
recorded in [CHANGELOG.md](../CHANGELOG.md). A removal or incompatible rename
requires a new versioned API path and a migration note.
