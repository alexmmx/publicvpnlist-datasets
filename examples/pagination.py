from publicvpnlist import PublicVPNListClient

client = PublicVPNListClient(timeout=15, max_retries=2)
for record in client.iter_servers(country="US", per_page=50):
    print(record["id"], record["transport"], record["port"])
