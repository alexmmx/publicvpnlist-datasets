import requests

response = requests.get(
    "https://publicvpnlist.com/api/v1/servers",
    params={"country": "US", "per_page": 10},
    timeout=15,
)
response.raise_for_status()
print(response.json()["data"])
