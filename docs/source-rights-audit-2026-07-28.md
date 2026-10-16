# PublicVPNList source-rights audit — 2026-07-28

This document records the legal-technical evidence reviewed before the first
real PublicVPNList metadata snapshot. It is an evidence log and risk
assessment, not legal advice or an approval to publish.

No endpoint, IP address, hostname, VPN profile, credential, checker response,
raw database row, or personal data was collected for this report. The
production database was queried read-only and only aggregate counts by the
exact `SOURCE` value and active state were retained.

## Decision

No observed real source is ready for automatic approval.

- Nine source values map to the current canonical registry. All remain
  `pending` or `unknown`, with `metadata_export_allowed=false`.
- Twelve historical source values are not registered. They are currently
  inactive and remain blocked by the exporter's unknown-source rule.
- `CynegeirusOVPN` is the strongest candidate for a manual review because its
  repository carries an MIT license. The provenance and the maintainer's
  authority to license the contained endpoint metadata still need confirmation.
- `OpenTunnel`, `HideSSH`, and `ServerSSH` publish terms that restrict copying,
  redistribution, public display, mirroring, or dissemination.
- Free access, a public API, or an open-source license on collector code does
  not by itself establish the right to republish the upstream dataset.

The deny-by-default publication gate must remain enabled until source-specific
evidence is reviewed.

## Repository state reviewed

| Item | Value |
|---|---|
| Branch | `main` |
| Baseline commit | `b13e1cc0e5c4b599193135f8ac5b73eb99a2a263` |
| Registry | `config/dataset_sources.json` |
| Production source field | Bitrix IBlock 4 `SOURCE` |
| Registry-approved real sources | 0 |

## Aggregate production inventory

The counts below are a point-in-time read-only aggregate. Production changes
continuously, so they are evidence of source coverage rather than a stable
snapshot.

| Exact `SOURCE` | Total | Active | Inactive | Registry mapping | Review status |
|---|---:|---:|---:|---|---|
| `AutoOVPN` | 11,598 | 3,511 | 8,087 | `auto-ovpn` | pending |
| `ComputerAndMobile` | 6 | 0 | 6 | none | unregistered |
| `CoopVPN` | 24 | 24 | 0 | `coop-vpn` | pending |
| `CynegeirusOVPN` | 88 | 9 | 79 | `cynegeirus-ovpn` | unknown |
| `FreeOpenVPN` | 53 | 0 | 53 | none | unregistered |
| `FreeVPN.me` | 4 | 0 | 4 | none | unregistered |
| `FreeVPN4You` | 12 | 0 | 12 | none | unregistered |
| `HideSSH` | 12 | 0 | 12 | none | unregistered |
| `IPSpeed` | 6,060 | 1,581 | 4,479 | `ip-speed` | pending |
| `IPSpeedArchive` | 111 | 0 | 111 | none | unregistered |
| `MYTAdityaOVPN` | 6 | 3 | 3 | `mytaditya-ovpn` | unknown |
| `OpenTunnel` | 12 | 0 | 12 | none | unregistered |
| `RiseupVPN` | 22 | 18 | 4 | `riseup-vpn` | pending |
| `ServerSSH` | 3 | 0 | 3 | none | unregistered |
| `Tain03OVPN` | 9 | 0 | 9 | none | unregistered |
| `TcpVPN` | 20 | 0 | 20 | none | unregistered |
| `UploadOVPN` | 35 | 6 | 29 | `user-upload` | pending |
| `VPNBook` | 40 | 0 | 40 | none | unregistered |
| `VPNGate` | 6,580 | 1,584 | 4,996 | `vpn-gate` | pending |
| `VPNJantit` | 218 | 0 | 218 | none | unregistered |
| `ZoultOVPN` | 204 | 19 | 185 | `zoult-ovpn` | pending |
| **Total** | **25,117** | **6,755** | **18,362** | **9 mapped** | **0 approved** |

The three largest active sources — `AutoOVPN`, `VPNGate`, and `IPSpeed` —
account for 6,676 of 6,755 active records (98.8%). Rights work should therefore
prioritize these three provenance chains.

The previous exporter dry-run read 6,739 records and rejected all 6,739 as
`source_not_approved`. The aggregate had increased to 6,755 active records
during this audit. The exporter was not rerun, but the unchanged registry
means a current dry-run is expected to accept zero records.

## Evidence and proposed decisions

The decisions below are proposals for human legal review. They do not modify
the canonical registry.

| `SOURCE` | Owner or operator identified | Evidence reviewed | Rights assessment | Proposed decision |
|---|---|---|---|---|
| `AutoOVPN` | GitHub maintainer 9xN; upstream VPN Gate | [AutoOVPN repository](https://github.com/9xN/auto-ovpn), including its AGPL-3.0 license and VPN Gate input | The code license does not establish rights to republish upstream VPN Gate data | HOLD — obtain upstream permission |
| `ComputerAndMobile` | ComputerAndMobile service operator; legal entity not disclosed | [Official service](https://vpn.computerandmobile.com/) | No metadata-redistribution license found | HOLD — request written permission |
| `CoopVPN` | CoopVPN cooperative / LEAP project | [Open-source licensing matrix](https://coopvpn.net/open_source/) and [service terms](https://coopvpn.net/tos/) | Published licenses cover software and documentation, not clearly the gateway dataset | HOLD — request data permission |
| `CynegeirusOVPN` | GitHub maintainer `cynegeirus` | [Canonical repository](https://github.com/cynegeirus/public-openvpn-servers) and MIT license | Strongest evidence found, but endpoint provenance and licensor authority require confirmation | MANUAL CANDIDATE — do not auto-approve |
| `FreeOpenVPN` | Historical service brand; current domain redirects to IPSpeed; imported through `gr33n37` | [Collector repository](https://github.com/gr33n37/ovpn) | Collector has no license and the upstream rights chain is unproven | HOLD — establish the complete rights chain |
| `FreeVPN.me` | FreeVPN.me service operator; legal entity not disclosed | [Official service](https://freevpn.me/) | Free access is offered, but no redistribution license was found | HOLD — request written permission |
| `FreeVPN4You` | Historical service brand; current domain redirects to IPSpeed; imported through `gr33n37` | [Collector repository](https://github.com/gr33n37/ovpn) | Collector has no license and the upstream rights chain is unproven | HOLD — establish the complete rights chain |
| `HideSSH` | HideSSH service operator | [Official terms](https://hidessh.com/page/terms-and-conditions) | Terms restrict republishing, copying, and redistribution | BLOCK — written exception required |
| `IPSpeed` | IPSpeed service operator; legal entity not disclosed | [About page](https://ipspeed.info/about.php) and [privacy policy](https://ipspeed.info/privacypolicy.php) | No metadata-redistribution license found | HOLD — request written permission |
| `IPSpeedArchive` | `gr33n37` collector; underlying IPSpeed service | [Collector repository](https://github.com/gr33n37/ovpn) | No license from the collector or upstream source | BLOCK — no established rights chain |
| `MYTAdityaOVPN` | GitHub account `MYTAditya`; endpoint operators unknown | [Configured repository](https://github.com/MYTAditya/OVPN-Collection) | Repository was unavailable and no current license evidence was found | HOLD — locate and verify the canonical source |
| `OpenTunnel` | OpenTunnel service operator | [Official terms](https://opentunnel.net/term-of-service) | Terms allow limited personal viewing and restrict copying, public display, transfer, and mirroring | BLOCK — written exception required |
| `RiseupVPN` | Riseup Collective | [VPN documentation](https://riseup.net/en/vpn) and [terms](https://riseup.net/tos) | Service terms do not clearly grant republication of gateway metadata | HOLD — request written permission |
| `ServerSSH` | ServerSSH service operator | [Official terms](https://serverssh.net/?q=terms) | Terms restrict dissemination without permission | BLOCK — written exception required |
| `Tain03OVPN` | GitHub maintainer `tain03`; underlying IPSpeed service | [Collector repository](https://github.com/tain03/ovpn) | No repository license or upstream permission chain was found | HOLD — establish the complete rights chain |
| `TcpVPN` | TcpVPN service operator; legal entity not disclosed | [Terms URL](https://tcpvpn.com/terms-of-service) | No usable redistribution grant was found; the service states that rights are reserved | HOLD — request written permission |
| `UploadOVPN` | Submitting user or endpoint operator per submission | [PublicVPNList source policy](https://publicvpnlist.com/sources/) | Upload or public reachability does not prove authority to sublicense metadata; no per-submission permission record was found | BLOCK — require affirmative per-submission evidence |
| `VPNBook` | VPNBook service operator; legal entity not disclosed | [Official service](https://www.vpnbook.com/) and [contact page](https://www.vpnbook.com/contact) | Free service access does not grant bulk metadata republication | HOLD — request written permission |
| `VPNGate` | VPN Gate Academic Experiment Project at the University of Tsukuba; individual relay volunteers | [Official project](https://www.vpngate.net/en/) and [project description](https://www.vpngate.net/en/about.aspx) | Client-application use of the CSV list is not an explicit public-mirror or dataset-redistribution grant | HOLD — obtain project permission |
| `VPNJantit` | VPN Jantit service operator | [Official terms](https://www.vpnjantit.com/terms-and-service) | Terms govern use of the service but do not clearly license data redistribution | HOLD — request written permission |
| `ZoultOVPN` | GitHub maintainer `Zoult`; several upstream VPN services | [Repository actually used by the importer](https://github.com/Zoult/.ovpn) | Repository has no license, lists third-party origins, and differs from the registry URL | HOLD — correct provenance and obtain upstream rights |

## Registry and provenance gaps

1. `ZoultOVPN`: the importer uses `Zoult/.ovpn`, while the registry identifies
   a different repository.
2. `CoopVPN`: the importer uses official CoopVPN/LEAP infrastructure, while the
   repository currently named in the registry is unavailable.
3. `AutoOVPN`: the registry records the immediate GitHub collector but not its
   VPN Gate API provenance.
4. `CynegeirusOVPN` and `MYTAdityaOVPN`: the registry uses the generic
   PublicVPNList sources page instead of canonical upstream evidence. The
   former repository exists and is MIT-licensed; the latter was unavailable.
5. The production source and license pages make broader claims about
   redistribution than the deny-by-default registry. PublicVPNList cannot
   sublicense third-party rights that it has not received.

Aliases must not combine records from different licensing or ownership chains.
Correcting a URL or adding a missing source to the registry must not
automatically change its permission flags.

## Legal context

The following general references informed the conservative evidence standard:

- [GitHub: Licensing a repository](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/licensing-a-repository)
  explains that a public repository without a license remains subject to
  ordinary copyright restrictions.
- [U.S. Copyright Office: databases](https://www.copyright.gov/register/tx-databases.html)
  distinguishes unprotected facts from potentially protected selection,
  coordination, and arrangement.
- [EU Directive 96/9/EC](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:31996L0009)
  provides database-related rights that can apply to extraction or reuse.

Applicability depends on jurisdiction, contracts, acquisition method, and the
exact fields published. Qualified counsel must make the final determination.

## Evidence required before approval

For each source, retain immutable review evidence covering:

1. the legal owner or authorized licensor;
2. the exact metadata fields that may be republished;
3. public mirroring and bulk redistribution;
4. commercial and non-commercial use;
5. update frequency and retention;
6. required attribution and notices;
7. takedown and suppression requirements;
8. permission date, reviewer, evidence URL, and evidence copy or permalink.

Only after that review may a separate change set `review_status=approved` and
`metadata_export_allowed=true`. Configuration redistribution must remain a
separate decision.

## Preconditions for the first real snapshot

1. Resolve rights for VPN Gate, IPSpeed, and the AutoOVPN provenance chain.
2. Complete the manual Cynegeirus review and pin its license evidence to a
   commit.
3. Add historical sources to the registry only as `unknown` or `rejected`
   until evidence exists.
4. Correct canonical upstream URLs without broadening permissions.
5. Align public source/license wording with the canonical registry.
6. Obtain legal sign-off, then run a fresh read-only dry-run.
7. Review aggregate rejection reasons and guardrails before separately
   authorizing any real snapshot build or publication.

Until these steps are complete, an accepted count of zero is the intended and
safe result.
