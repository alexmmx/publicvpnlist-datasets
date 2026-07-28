#!/usr/bin/env python3
"""Command-line wrapper for the bounded PublicVPNList client."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from publicvpnlist.client import (  # noqa: E402
    ClientError,
    NotModified,
    PublicVPNListClient,
)

ENDPOINTS = {"countries", "dataset", "health", "protocols", "servers", "stats"}


def parse_param(value: str) -> tuple[str, str]:
    if "=" not in value:
        raise argparse.ArgumentTypeError("parameters must use KEY=VALUE")
    key, item = value.split("=", 1)
    if not key or not item:
        raise argparse.ArgumentTypeError("parameters must use non-empty KEY=VALUE")
    return key, item


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Fetch a PublicVPNList API v1 JSON response.",
    )
    parser.add_argument("endpoint", choices=sorted(ENDPOINTS))
    parser.add_argument(
        "--public-id",
        help="get one server; valid only with the servers endpoint",
    )
    parser.add_argument(
        "--param",
        action="append",
        default=[],
        type=parse_param,
        metavar="KEY=VALUE",
        help="query parameter; may be repeated",
    )
    parser.add_argument("--if-none-match", help="send a previously returned ETag")
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--max-response-bytes", type=int, default=4 * 1024 * 1024)
    parser.add_argument("--max-retries", type=int, default=2)
    parser.add_argument("--compact", action="store_true", help="do not pretty-print JSON")
    args = parser.parse_args()

    if args.public_id and args.endpoint != "servers":
        parser.error("--public-id is valid only for servers")
    client = PublicVPNListClient(
        timeout=args.timeout,
        max_response_bytes=args.max_response_bytes,
        max_retries=args.max_retries,
    )
    path = f"/servers/{args.public_id}" if args.public_id else f"/{args.endpoint}"
    try:
        payload = client.get(
            path,
            params=dict(args.param),
            etag=args.if_none_match,
        )
    except NotModified:
        print("Not modified", file=sys.stderr)
        return 0
    except (ClientError, ValueError) as error:
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
