# PublicVPNList data dictionary

Schema version: `1.0`

Canonical API documentation: https://publicvpnlist.com/api/

PublicVPNList measures technical reachability and connection quality for
third-party public VPN endpoints. These fields do not establish privacy,
operator identity, ownership, logging policy, anonymity or trust.

## Response envelope

Collection endpoints return:

| Field | Type | Meaning |
|---|---|---|
| `data` | array or object | Endpoint-specific records |
| `meta` | object | Snapshot identity and lifecycle |
| `links` | object | Current, next, previous and documentation URLs |

Errors use:

| Field | Type | Meaning |
|---|---|---|
| `error.code` | string | Stable machine-readable error code |
| `error.message` | string | Safe human-readable explanation |
| `error.parameter` | string, optional | Invalid query parameter |
| `error.request_id` | string | Identifier for support and diagnostics |

## Snapshot metadata

| Field | Type | Unit or format | Meaning |
|---|---|---|---|
| `schema_version` | string | semantic contract version | Current public schema, `1.0` |
| `dataset_version` | string | `YYYYMMDDTHHMMSSZ-hash` | Immutable snapshot identity |
| `snapshot_id` | string | opaque | Canonical catalog snapshot identifier |
| `generated_at` | string | UTC ISO 8601 | When the dataset was generated |
| `expires_at` | string | UTC ISO 8601 | When clients should treat it as stale |
| `next_update_at` | string | UTC ISO 8601 | Planned next rebuild |
| `record_count` | integer | records | Eligible public records |
| `fresh_count` | integer | records | Records checked within the fresh window |
| `stale_count` | integer | records | Non-fresh records retained as recent |
| `countries_count` | integer | countries | Distinct country codes represented |
| `protocols` | array | protocol names | Currently contains `openvpn` |
| `checksum_sha256` | string | lowercase SHA-256 | Dataset integrity identifier |
| `source_url` | string | HTTPS URL | Canonical catalog |
| `documentation_url` | string | HTTPS URL | API documentation |
| `license_url` | string | HTTPS URL | Applicable data terms |
| `methodology_url` | string | HTTPS URL | Measurement methodology |
| `score_notice` | string | text | Required technical-score warning |

## Server record

| Field | Type | Unit or format | Nullability and meaning |
|---|---|---|---|
| `id` | string | `pvl_` + 24 hex | Stable public identifier; not a Bitrix ID |
| `country_code` | string | ISO 3166-1 alpha-2 | May be `null` when unknown |
| `country_name` | string | display name | May be `null` |
| `city` | string | display name | Currently `null` until verified data exists |
| `hostname` | string | DNS name | `null` for IP-only records |
| `ip` | string | IPv4 or IPv6 | May be `null` when only a hostname is known |
| `protocol` | string | protocol | Currently `openvpn` |
| `transport` | string | `tcp` or `udp` | OpenVPN transport |
| `port` | integer | 1–65535 | Remote service port |
| `speed_mbps` | number | Mbps | Representative measured speed; may be `null` |
| `latency_ms` | number | milliseconds | Representative measured latency; may be `null` |
| `uptime_percent_7d` | number | percent | Currently `null` until a complete window exists |
| `uptime_hours` | number | hours | Currently `null` until supported |
| `sessions` | integer | sessions | Currently `null` until supported |
| `technical_quality_score` | integer | 0–100 | Network measurements only; not a trust score |
| `score_label` | string | display label | Human-readable technical score band |
| `last_checked_at` | string | UTC ISO 8601 | Last successful technical check; may be `null` |
| `first_seen_at` | string | UTC ISO 8601 | First catalog observation; may be `null` |
| `config_updated_at` | string | UTC ISO 8601 | Currently `null` until verified |
| `freshness_status` | string | `fresh` or `recent` | Age relative to the generated snapshot |
| `availability_status` | string | status | `online_at_last_check` is not a future guarantee |
| `source_name` | string | source label | Upstream source or submission channel |
| `source_url` | string | HTTPS URL | Attribution or source information |
| `server_page_url` | string | HTTPS URL | Public API record URL |
| `config_download_url` | string | HTTPS URL | `null` in bulk data; live checks remain required |
| `risk_flags` | array | string flags | Required third-party and uncertainty warnings |
| `config_sha256` | string | lowercase SHA-256 | May be `null`; does not publish config contents |

## Compatibility

Additive fields may appear within API v1. Clients should ignore unknown fields.
Breaking changes require a new versioned API path and a documented migration
window.
