from publicvpnlist import PublicVPNListClient

client = PublicVPNListClient(timeout=15, max_retries=2)
print(client.list_servers(country="US", per_page=10)["data"])
