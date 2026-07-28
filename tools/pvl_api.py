#!/usr/bin/env python3
"""Small dependency-free PublicVPNList API client."""

from __future__ import annotations

import argparse
import json
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

BASE_URL = "https://publicvpnlist.com/api/v1"
ENDPOINTS = {"servers", "countries", "protocols", "stats", "dataset", "health"}


def parse_param(value: str) -> tuple[str, str]:
    if "=" not in value:
        raise argparse.ArgumentTypeError("parameters must use KEY=VALUE")
    key, item = value.split("=", 1)
    if not key or not item:
        raise argparse.ArgumentTypeError("parameters must use non-empty KEY=VALUE")
    return key, item


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Fetch a PublicVPNList API v1 response.",
    )
    parser.add_argument("endpoint", choices=sorted(ENDPOINTS))
    parser.add_argument(
        "--param",
        action="append",
        default=[],
        type=parse_param,
        metavar="KEY=VALUE",
        help="query parameter; may be repeated",
    )
    parser.add_argument("--if-none-match", help="send an ETag from an earlier response")
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--compact", action="store_true", help="do not pretty-print JSON")
    args = parser.parse_args()

    query = urlencode(args.param)
    url = f"{BASE_URL}/{args.endpoint}" + (f"?{query}" if query else "")
    headers = {
        "Accept": "application/json",
        "User-Agent": "publicvpnlist-datasets-example/1.0",
    }
    if args.if_none_match:
        headers["If-None-Match"] = args.if_none_match

    try:
        with urlopen(Request(url, headers=headers), timeout=args.timeout) as response:
            payload = json.load(response)
            etag = response.headers.get("ETag")
            if etag:
                print(f"ETag: {etag}", file=sys.stderr)
    except HTTPError as error:
        if error.code == 304:
            print("Not modified", file=sys.stderr)
            return 0
        body = error.read().decode("utf-8", errors="replace")
        retry_after = error.headers.get("Retry-After")
        if retry_after:
            print(f"Retry-After: {retry_after}", file=sys.stderr)
        print(f"HTTP {error.code}: {body}", file=sys.stderr)
        return 2
    except (URLError, TimeoutError, json.JSONDecodeError) as error:
        print(f"Request failed: {error}", file=sys.stderr)
        return 2

    json.dump(
        payload,
        sys.stdout,
        ensure_ascii=False,
        separators=(",", ":") if args.compact else None,
        indent=None if args.compact else 2,
    )
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
