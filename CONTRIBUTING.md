# Contributing

Use issues for schema bugs, attribution corrections and reproducible dataset
validation failures. Do not submit real third-party `.ovpn`, WireGuard `.conf`,
client profiles, QR codes, keys, passwords or tokens.

Do not submit endpoint datasets while DATA-LICENSE.md marks publication as
pending. Schema and tooling changes must keep the canonical JSON Schema and
OpenAPI reference synchronized, preserve stable public IDs, pass secret/ZIP/CSV
checks and include positive and negative tests. Run the Quick Start validation
commands from [README.md](README.md) before opening a change.

After editing the canonical OpenAPI contract, refresh its documentation mirror
with:

```sh
cp openapi/openapi.json docs/openapi.json
```
