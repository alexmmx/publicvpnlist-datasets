# API integration guide

Base URL: `https://publicvpnlist.com/api/v1`

## Start with a small request

```sh
curl --fail --show-error --location \
  -H 'Accept: application/json' \
  'https://publicvpnlist.com/api/v1/servers?country=US&per_page=10'
```

Use `page` and `per_page` for pagination. Follow `links.next` rather than
constructing subsequent URLs when possible.

## Cache unchanged responses

Responses expose `ETag` and `Last-Modified`. Store either value and send
`If-None-Match` or `If-Modified-Since` on the next request. A `304 Not
Modified` response has no JSON body and means the cached representation is
still current.

```sh
etag=$(curl -fsSI 'https://publicvpnlist.com/api/v1/stats' |
  awk -F': ' 'tolower($1)=="etag"{gsub("\r","",$2); print $2}')
curl -i -H "If-None-Match: $etag" \
  'https://publicvpnlist.com/api/v1/stats'
```

## Handle limits and errors

General API traffic is limited per client. The health endpoint has a smaller
independent allowance. On `429 Too Many Requests`, read `Retry-After`, wait,
and retry with bounded exponential backoff. Do not retry validation errors
without changing the request.

Error responses include a stable `error.code` and `error.request_id`.
They never include stack traces, SQL, Bitrix IDs, filesystem paths or
infrastructure hostnames.

The maintained standard-library client applies a 15-second timeout, a 4 MiB
response cap and at most two retries for `429`, `502`, `503` or `504`:

```python
from publicvpnlist import PublicVPNListClient

client = PublicVPNListClient(timeout=10, max_response_bytes=2 * 1024 * 1024)
for server in client.iter_servers(country="US", per_page=50):
    print(server["id"])
```

Pass a requests-compatible object as `session=my_session`, or a custom object
implementing the documented `Transport` protocol, when the application owns
connection pooling. The test suite uses these interfaces to exercise all HTTP
behavior without network access.

## Select only required fields

The `fields` query parameter accepts a comma-separated allowlist:

```text
fields=id,country_code,transport,port,speed_mbps,latency_ms,last_checked_at
```

Unknown fields and repeated query parameters are rejected.

The canonical response uses established API names (`id`, `hostname`, `ip`,
`port`, `latency_ms` and `speed_mbps`). Protocol-neutral names in design
documents map to these fields; both aliases are not emitted together.

## Treat measurements correctly

`technical_quality_score`, speed, latency and freshness describe technical
measurements at a point in time. They do not verify privacy, identity,
ownership, logging practices, anonymity or operator trust. Re-check
`expires_at` and `last_checked_at` before acting on cached data.

See [the data dictionary](data-dictionary.md), the
[OpenAPI contract](../openapi/openapi.json) and the canonical
[API documentation](https://publicvpnlist.com/api/).
