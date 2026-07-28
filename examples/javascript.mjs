const response = await fetch(
  "https://publicvpnlist.com/api/v1/servers?country=US&per_page=10",
);
if (!response.ok) throw new Error(`HTTP ${response.status}`);
console.log((await response.json()).data);
