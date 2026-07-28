#!/usr/bin/env sh
set -eu
curl --fail --show-error --location \
  'https://publicvpnlist.com/api/v1/servers?country=US&per_page=10'
