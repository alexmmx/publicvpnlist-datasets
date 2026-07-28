# Metadata exporter operations

The exporter is a local CLI for producing a rights-gated metadata snapshot from
the PublicVPNList Bitrix `vpn_servers` IBlock. It does not expose an HTTP
endpoint, publish to GitHub, build VPN configuration archives, or modify the
database.

## Publication gate

[`config/dataset_sources.json`](../config/dataset_sources.json) is the
canonical source registry. An internal source label is normalized and resolved
through its `aliases`. Missing aliases are denied.

A record is eligible only when its source has all of the following:

- `review_status` equal to `approved`;
- `metadata_export_allowed` equal to `true`;
- non-empty `source_name`, `source_url`, and `source_license`;
- a completed review identity, review time, and HTTPS evidence URL.

`redistribution_allowed` and `config_redistribution_allowed` are separate,
explicit decisions. Neither is inferred from metadata approval. The exporter
always sets `config_download_url` and `config_sha256` to `null` and never reads
profile content into the public transformation.

To approve a source, retain reviewable evidence of current upstream terms or
direct permission, document the exact metadata covered, required attribution,
scope, date, reviewer, and evidence URL, then update the registry in review.
Do not approve an aggregator merely because its input can be downloaded.

The production registry currently has no approved real source. A production
dry-run should therefore report zero accepted records until a documented
source review is completed.

No IBlock migration is required for this stage. Existing `SOURCE` labels map
reliably through aliases, while source rights live in the reviewed registry.
The bridge derives first-seen and last-success timestamps from existing fields
and does not alter any IBlock property.

## Eligibility and normalization

The read-only PHP bridge locates the IBlock by code, selects active elements,
and returns only the metadata required by the transformer. It reuses the
site's canonical visibility, downloadability, endpoint, measurement, and
technical-score helpers. The exporter then applies a stricter configurable
freshness gate.

Defaults in [`config/exporter.json`](../config/exporter.json) are:

- last check succeeded, failure streak is zero, and checker status is one of
  `checked`, `ok`, `passed`, or `tunnel_ok`;
- canonical visibility and downloadability are both true;
- a real configuration file is available to the site, but neither its path
  nor content is exported;
- the check is no older than 3,600 seconds, matching the site's `fresh`
  classification; the site's broader `recent` window is not exported;
- the endpoint is a global IPv4/IPv6 address or a valid normalized hostname;
- protocol is OpenVPN and transport is TCP or UDP;
- country is a two-letter uppercase code;
- speed and latency are positive measured values;
- the source passes the publication gate.

Documentation-only address ranges are accepted solely by test fixtures.
Unknown status, private/reserved production addresses, stale checks, failed
checks, unsafe records, missing measurements, and invalid ports are rejected.

Duplicates use `protocol + transport + normalized hostname-or-IP + port`.
The most recently checked record wins, then the more complete record, then a
stable content-derived tie-breaker. Counts and rejection reasons are reported
without endpoint values.

## Public IDs and the HMAC secret

The public ID is:

```text
pvl_ + first 24 hexadecimal characters of
HMAC-SHA256(protocol|transport|normalized-endpoint|port)
```

Set `PVL_DATASET_HMAC_SECRET` from an operator-controlled secret store or
environment file outside Git. At least 32 bytes are required. The value is
never logged or written to a snapshot.

Changing the secret changes every public ID. Do not rotate it in place. Plan a
versioned ID migration or a temporary old-to-new mapping outside the public
dataset, update API references, and switch only after consumers can tolerate
the change. Restore the existing secret when continuity is required.

## Dry-run and local publication

Use a Python 3.12 environment with the repository's pinned dependencies.
Supply the site root explicitly or through `PVL_SITE_ROOT`.

```sh
python tools/export_public_dataset.py \
  --dry-run \
  --site-root /path/to/publicvpnlist-site \
  --report var/public-dataset/dry-run-report.json
```

The command requires `PVL_DATASET_HMAC_SECRET`. Dry-run reads the production
database but performs no database write, Git operation, publication, or
`current` switch. With the current unapproved registry, zero records and
guardrail violations are the expected result.

After source approval and review of a successful dry-run, create an atomic
local snapshot:

```sh
python tools/export_public_dataset.py \
  --publish-local \
  --site-root /path/to/publicvpnlist-site \
  --report var/public-dataset/export-report.json
```

`--limit`, `--source`, and `--protocol` create a partial snapshot and are
blocked in local publication mode unless `--allow-partial` is explicit.
`--override-guardrails` is an operator-only emergency option and must never be
placed in cron.

Validate a saved version independently:

```sh
python tools/export_public_dataset.py \
  --validate-only var/public-dataset/versions/VERSION
python scripts/validate.py
python -m pytest
python -m ruff check .
python -m ruff format --check .
```

## Bundle, atomicity, and rollback

All four representations are generated from one canonical in-memory record
list:

- `servers.json` is the canonical schema envelope;
- `servers.csv` uses a fixed schema-derived column order and rejects
  spreadsheet formula prefixes;
- `servers.txt` is the existing UTF-8 TSV format with its documented comment
  header and fixed columns;
- `servers.xml` uses `publicvpnlist_dataset`, disables DTD/entity content, and
  round-trips to the same records.

All files are UTF-8 with LF endings. The exporter validates schema, semantics,
secret scanning, cross-format round trips, file sets, manifest fields, sizes,
and checksums inside a private staging directory. A successful local
publication renames staging into `versions/VERSION` and atomically replaces
the `current` symlink. A failed build leaves the prior `current` unchanged.

`manifest.json` records both the existing `path`/`bytes` fields and the
explicit `filename`, `content_type`, `size_bytes`, and per-format
`record_count`. `SHA256SUMS` covers the four formats, manifest, and sanitized
export report. It does not checksum itself, avoiding a cycle.

To roll back, first validate the selected retained version with
`--validate-only`. Then atomically repoint `current` to that exact
`versions/VERSION` directory using the host's controlled deployment tooling.
Never delete or rewrite a version to perform rollback.

The retention pass runs only after successful activation, keeps the current
version and at least one prior valid version, and removes only version-named
directories below the configured output root.

## Guardrails and monitoring

The default guardrails block:

- an empty dataset;
- fewer than one represented country;
- a drop greater than 30 percent from the active version;
- more than 25 percent rejected input records.

The count minima are only non-empty publication safeguards; they are not an
invented estimate of currently approved volume. Tune them only after an
approved-source baseline exists.

The JSON report contains records read/accepted/rejected, duplicate count,
aggregate rejection reasons, generated formats, validation result, output
version, guardrail decisions, and duration. It never contains source rows,
endpoints, paths, profile material, or secrets.

## Scheduler template (not installed)

The site advertises a five-minute snapshot update interval, so scheduling more
frequently is not useful. Do not enable a scheduler until at least one source
is approved and a local publication has been reviewed.

Example cron shape, with environment loading and alert handling supplied by
the operator:

```cron
*/5 * * * * timeout 4m /path/to/venv/bin/python /path/to/repository/tools/export_public_dataset.py --publish-local --site-root /path/to/site >>/path/to/private-log 2>&1
```

The exporter already uses an `flock`-backed lock with timeout. For systemd,
use a oneshot service with `TimeoutStartSec=4m`, a five-minute timer,
`Persistent=true`, `RandomizedDelaySec=30`, an environment file outside Git,
and a failure notification unit. If retries are required, cap them at two and
retain the exporter lock; never add the guardrail override.

## Prohibited output

The exporter never emits profile content, ready-to-use client configuration,
private or preshared keys, certificates, passwords, authentication directives,
tokens, cookies, sessions, internal element IDs, absolute paths, checker URLs,
raw checker responses, logs, QR codes, administrator notes, SSH data, or
personal user data. No ZIP or other configuration archive is created.

Manual transfer to another checkout must copy only a bundle that passes
`--validate-only`, `scripts/validate.py`, the test suite, lint, format, and
secret checks. Git publication, tags, releases, and real snapshots remain a
separate explicitly authorized operation.
