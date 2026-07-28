from __future__ import annotations

import requests

url = "https://publicvpnlist.com/api/v1/servers"
params = {"country": "US", "per_page": 50, "page": 1}

while url:
    response = requests.get(url, params=params, timeout=15)
    if response.status_code == 429:
        raise RuntimeError(f"Rate limited; retry after {response.headers.get('Retry-After')}s")
    response.raise_for_status()
    payload = response.json()
    for record in payload["data"]:
        print(record["id"], record["transport"], record["port"])
    url = payload["links"]["next"]
    params = None
