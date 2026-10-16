# PublicVPNList API: integrate checked VPN metadata

Published October 16, 2026 · [API documentation and access](https://publicvpnlist.com/api/)

Build a server browser, filter endpoints for your application, or monitor a
catalog without parsing website tables. PublicVPNList API v1 exposes structured
metadata, source attribution and timestamps for technical VPN observations.
This repository provides schemas, client examples and offline validators.

## Get access

Open the [API page](https://publicvpnlist.com/api/), complete the access check
and request a free key. Temporary access lasts 24 hours and must be renewed
manually. Permanent access requests are reviewed individually on the site.
Keep the key private and send it in an `Authorization: Bearer` header.

For example, set `PVL_API_KEY` locally to your own key, then request a small
page of recently checked VLESS records:

```sh
curl --fail-with-body --get \
  'https://publicvpnlist.com/api/v1/servers' \
  --oauth2-bearer "${PVL_API_KEY:?Set your private API key locally}" \
  --header 'Accept: application/json' \
  --data-urlencode 'protocol=vless' \
  --data-urlencode 'status=online' \
  --data-urlencode 'sort=last_checked' \
  --data-urlencode 'order=desc' \
  --data-urlencode 'per_page=10'
```

Never commit a real key or include it in public issues, screenshots or URLs.

## Choose the right endpoint

All paths below are relative to `https://publicvpnlist.com/api/v1`.

| Endpoint | Use |
|---|---|
| `GET /servers` | Filter, sort and paginate records |
| `GET /servers/{public_id}` | Retrieve one public record |
| `GET /countries` | Discover country coverage |
| `GET /protocols` | Discover published protocols |
| `GET /stats` | Read snapshot statistics |
| `GET /dataset` | Inspect dataset lifecycle and export locations |
| `GET /health` | Inspect snapshot health |

The live catalog documents nine protocol selectors; some may have no available
records. Counts change, so discover them at runtime. The omitted protocol
filter retains the OpenVPN default.

For bulk workflows, use the site's [exports](https://publicvpnlist.com/exports/).
Handle expired access (`401`) and rate limits (`429`) explicitly, and inspect
snapshot expiry and record check timestamps. An online observation is not a
promise that a server will still connect later.

Technical measurements do not establish operator trust or anonymity. Metadata
is not a complete connection profile. Respect the documented download flow
and source rights when retrieving or redistributing configurations.

See [repository examples](../examples/) and the
[OpenAPI contract](../openapi/openapi.json). For current access rules and
additive live fields, consult the linked website documentation.

## Desktop clients

Prefer a desktop interface? Read about the [Linux beta](vpn-app-linux.md) and
the [Windows test beta](vpn-app-windows.md).
