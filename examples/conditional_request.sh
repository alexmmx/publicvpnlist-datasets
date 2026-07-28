#!/usr/bin/env sh
set -eu

url='https://publicvpnlist.com/api/v1/stats'
etag=$(
  curl --fail --silent --show-error --head "$url" |
    awk -F': ' 'tolower($1)=="etag"{gsub("\r","",$2); print $2}'
)

curl --include --fail --show-error \
  -H "If-None-Match: $etag" \
  "$url"
