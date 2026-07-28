# Data publication and licensing

The [MIT license](LICENSE) applies to PublicVPNList-authored source code,
schemas, documentation and synthetic examples. It does **not** automatically
grant permission to use or redistribute metadata or configuration material
obtained from third-party VPN sources.

No real endpoint snapshot is currently published in this repository. Before a
future snapshot can be included, every record must identify its source,
applicable source license or permission, required attribution and whether
redistribution is explicitly allowed. Records without confirmed republication
rights must be excluded. The source review is tracked in
[ATTRIBUTION.md](ATTRIBUTION.md).

Public metadata snapshots never include ready-to-use OpenVPN `.ovpn` profiles,
WireGuard client `.conf` profiles, client private keys, preshared keys,
passwords, access or provisioning tokens, QR codes containing profiles, or
internal service endpoints. A configuration download link is permitted only
where the source explicitly allows redistribution and that permission is
recorded.

Technical reachability, latency, throughput, uptime and quality-score
measurements are observations at a point in time. They are not a guarantee of
security, confidentiality, operator identity, privacy practices or absence of
logging.

The canonical service may be governed by additional current terms published at
<https://publicvpnlist.com/license/>. This document records the repository
publication gate and is not legal advice.

The generator enforces these decisions through
[`config/dataset_sources.json`](config/dataset_sources.json). Source ingestion
or visibility on the website is not evidence of repository republication
permission.
