from __future__ import annotations

import ipaddress
import json
import subprocess
import sys
import unittest
from pathlib import Path

import jsonschema

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_PATHS = {
    "/servers",
    "/servers/{public_id}",
    "/countries",
    "/protocols",
    "/stats",
    "/dataset",
    "/health",
}


def load_json(path: str) -> dict:
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


class RepositoryContractTest(unittest.TestCase):
    def test_openapi_contract(self) -> None:
        contract = load_json("openapi/openapi.json")
        self.assertEqual(contract["openapi"], "3.1.0")
        self.assertEqual(contract["info"]["version"], "1.0.0")
        self.assertEqual(contract["servers"], [{"url": "https://publicvpnlist.com/api/v1"}])
        self.assertEqual(set(contract["paths"]), REQUIRED_PATHS)

    def test_pages_openapi_copy_matches(self) -> None:
        self.assertEqual(
            (ROOT / "openapi/openapi.json").read_bytes(),
            (ROOT / "docs/openapi.json").read_bytes(),
        )

    def test_synthetic_dataset_matches_schema(self) -> None:
        schema = load_json("schema/servers.schema.json")
        fixture = load_json("fixtures/dataset.synthetic.json")
        jsonschema.validate(fixture, schema)
        for record in fixture["records"]:
            address = ipaddress.ip_address(record["ip"])
            self.assertFalse(address.is_global)
            self.assertTrue(record["hostname"].endswith(".invalid"))

    def test_error_fixture_matches_openapi(self) -> None:
        contract = load_json("openapi/openapi.json")
        fixture = load_json("fixtures/error.synthetic.json")
        error_schema = contract["components"]["schemas"]["Error"]
        jsonschema.validate(fixture, error_schema)

    def test_postman_collection_covers_public_paths(self) -> None:
        collection = load_json(
            "collections/postman/PublicVPNList.postman_collection.json",
        )
        self.assertEqual(
            collection["variable"][0]["value"],
            "https://publicvpnlist.com/api/v1",
        )
        raw_urls = {item["request"]["url"]["raw"] for item in collection["item"]}
        for suffix in ("/servers", "/countries", "/protocols", "/stats", "/dataset", "/health"):
            self.assertTrue(any(suffix in raw for raw in raw_urls), suffix)

    def test_cli_help(self) -> None:
        result = subprocess.run(
            [sys.executable, str(ROOT / "tools/pvl_api.py"), "--help"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PublicVPNList API v1", result.stdout)


if __name__ == "__main__":
    unittest.main()
