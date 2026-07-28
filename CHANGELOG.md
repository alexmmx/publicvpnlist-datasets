# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project follows semantic versioning for its API and schema contracts.

## Unreleased

### Added

- Strict Draft 2020-12 schemas and a metadata-only WireGuard model.
- Offline semantic, manifest, CSV, ZIP and credential-leak validation.
- Positive and negative contract, security and mock-client tests.
- Reproducible dependency pins and Python lint/format checks.
- A local-only rights-gated metadata exporter, source registry, read-only
  Bitrix bridge, atomic snapshot lifecycle, guardrails, and operator guide.

### Changed

- Made the canonical JSON Schema the OpenAPI `Server` source of truth.
- Completed typed OpenAPI responses, errors, parameters, examples and cache
  behavior for all seven public endpoints.
- Replaced the indeterminate code license with MIT while retaining a separate
  data-rights publication gate.
- Hardened the Python client with bounded responses, retries and pagination.

### Security

- Added checks for path traversal, Unicode archive names, symlinks, encrypted
  and duplicate ZIP entries, compression bombs and embedded VPN credentials.
- Added Unicode-aware CSV formula-injection rejection.
- Added HMAC-derived public IDs, deny-by-default source approval, cross-format
  round trips, bundle checksums, output path containment, and export locking.

## 1.0.0 - 2026-07-28

### Added

- Initial API schema, examples, collections, synthetic fixtures and validation
  tooling.
- Read-only push and scheduled repository validation.
