from __future__ import annotations

import ipaddress
import json
import subprocess
import sys
from copy import deepcopy
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from openapi_spec_validator import validate_url

from publicvpnlist.models import Server
from publicvpnlist.validation import (
    ValidationFailure,
    schema_errors,
    validate_dataset_semantics,
    validate_schema,
    validate_wireguard_semantics,
)

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


def load_json(relative: str) -> dict:
    return json.loads((ROOT / relative).read_text(encoding="utf-8"))


@pytest.fixture()
def dataset() -> dict:
    return load_json("fixtures/dataset.synthetic.json")


@pytest.fixture()
def server_schema() -> dict:
    return load_json("schema/servers.schema.json")


def test_openapi_contract_and_external_schema_reference() -> None:
    contract = load_json("openapi/openapi.json")
    validate_url((ROOT / "openapi" / "openapi.json").as_uri())
    assert contract["openapi"] == "3.1.0"
    assert contract["info"]["version"] == "1.0.0"
    assert set(contract["paths"]) == REQUIRED_PATHS
    assert contract["components"]["schemas"]["Server"]["$ref"] == (
        "../schema/servers.schema.json#/$defs/OpenVpnServer"
    )


def test_documentation_openapi_copy_matches_canonical_file() -> None:
    assert (ROOT / "docs" / "openapi.json").read_bytes() == (
        ROOT / "openapi" / "openapi.json"
    ).read_bytes()


def test_client_model_required_and_common_fields_match_canonical_schema() -> None:
    definitions = load_json("schema/servers.schema.json")["$defs"]
    canonical = definitions["OpenVpnServer"]
    projection = definitions["OpenVpnServerProjection"]
    assert set(Server.__required_keys__) == set(canonical["required"])
    assert set(Server.__annotations__) == set(canonical["properties"])
    assert set(projection["properties"]) == set(canonical["properties"])


def test_all_schemas_are_draft_2020_12() -> None:
    for path in (ROOT / "schema").glob("*.schema.json"):
        schema = load_json(str(path.relative_to(ROOT)))
        assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        Draft202012Validator.check_schema(schema)


def test_legacy_manifest_fields_remain_schema_compatible() -> None:
    manifest = {
        "schema_version": "1.0",
        "dataset_version": "20260728T000000Z-000000000000",
        "snapshot_id": "synthetic-legacy",
        "generated_at": "2026-07-28T00:00:00Z",
        "expires_at": "2026-07-28T00:15:00Z",
        "record_count": 1,
        "score_notice": "Technical score does not assess privacy or operator trust.",
        "formats": [
            {
                "format": "json",
                "url": "https://example.invalid/servers.json",
                "bytes": 1,
                "sha256": "0" * 64,
            }
        ],
        "config_bundle": {
            "url": "https://example.invalid/configs.zip",
            "config_count": 0,
            "bytes": 1,
            "sha256": "0" * 64,
            "status": "not-published",
        },
        "archive_policy": {
            "cadence": "none",
            "interval_seconds": 300,
            "retention_days": 1,
        },
        "license_review": "Synthetic legacy contract test; no third-party data.",
    }
    validate_schema(
        manifest,
        load_json("schema/manifest.schema.json"),
        "legacy manifest",
    )


def test_valid_synthetic_openvpn_server(dataset: dict, server_schema: dict) -> None:
    validate_schema(dataset, server_schema, "dataset")
    validate_dataset_semantics(dataset)
    assert ipaddress.ip_address(dataset["records"][0]["ip"]) in ipaddress.ip_network(
        "192.0.2.0/24",
    )


def test_valid_synthetic_wireguard_metadata() -> None:
    record = load_json("fixtures/wireguard.synthetic.json")
    schema = load_json("schema/wireguard-metadata.schema.json")
    validate_schema(record, schema, "wireguard")
    validate_wireguard_semantics(record)
    assert ipaddress.ip_address(record["endpoint_ip"]) in ipaddress.ip_network(
        "2001:db8::/32",
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("ip", "999.1.1.1"),
        ("ip", "2001:db8:::1"),
        ("hostname", "bad\u0007host.invalid"),
        ("last_checked_at", "not-a-date"),
        ("source_url", "not a url"),
        ("port", 0),
        ("port", 65536),
        ("uptime_percent_7d", 100.1),
        ("speed_mbps", -0.1),
    ],
)
def test_invalid_server_formats_and_ranges(
    dataset: dict,
    server_schema: dict,
    field: str,
    value: object,
) -> None:
    invalid = deepcopy(dataset)
    invalid["records"][0][field] = value
    assert schema_errors(invalid, server_schema)


def test_unknown_field_is_rejected(dataset: dict, server_schema: dict) -> None:
    invalid = deepcopy(dataset)
    invalid["records"][0]["unknown_field"] = True
    assert any("additionalProperties" in item for item in schema_errors(invalid, server_schema))


def test_duplicate_risk_flags_are_rejected(dataset: dict, server_schema: dict) -> None:
    invalid = deepcopy(dataset)
    invalid["records"][0]["risk_flags"].append("third_party_server")
    assert any("uniqueItems" in item for item in schema_errors(invalid, server_schema))


def test_duplicate_public_id_is_rejected(dataset: dict) -> None:
    invalid = deepcopy(dataset)
    invalid["records"].append(deepcopy(invalid["records"][0]))
    invalid["metadata"]["record_count"] = 2
    invalid["metadata"]["fresh_count"] = 2
    with pytest.raises(ValidationFailure, match="duplicate public identifier"):
        validate_dataset_semantics(invalid)


def test_record_count_mismatch_is_rejected(dataset: dict) -> None:
    invalid = deepcopy(dataset)
    invalid["metadata"]["record_count"] = 2
    with pytest.raises(ValidationFailure, match="record_count"):
        validate_dataset_semantics(invalid)


def test_countries_count_mismatch_is_rejected(dataset: dict) -> None:
    invalid = deepcopy(dataset)
    invalid["metadata"]["countries_count"] = 2
    with pytest.raises(ValidationFailure, match="countries_count"):
        validate_dataset_semantics(invalid)


@pytest.mark.parametrize(
    ("target", "field", "value", "message"),
    [
        (
            "metadata",
            "expires_at",
            "2026-07-27T23:00:00Z",
            "generated_at must be earlier",
        ),
        (
            "record",
            "first_seen_at",
            "2026-07-28T00:00:00Z",
            "first_seen_at exceeds",
        ),
        (
            "record",
            "last_success_at",
            "2026-07-28T00:00:00Z",
            "last_success_at exceeds",
        ),
        (
            "record",
            "last_checked_at",
            "2026-07-28T00:01:00Z",
            "last_checked_at exceeds generated_at",
        ),
    ],
)
def test_time_ordering_is_enforced(
    dataset: dict,
    target: str,
    field: str,
    value: str,
    message: str,
) -> None:
    invalid = deepcopy(dataset)
    container = invalid["metadata"] if target == "metadata" else invalid["records"][0]
    container[field] = value
    with pytest.raises(ValidationFailure, match=message):
        validate_dataset_semantics(invalid)


def test_protocol_count_mismatch_is_rejected(dataset: dict) -> None:
    invalid = deepcopy(dataset)
    invalid["metadata"]["protocols_count"] = 2
    with pytest.raises(ValidationFailure, match="protocols_count"):
        validate_dataset_semantics(invalid)


def test_config_url_requires_redistribution_permission(dataset: dict) -> None:
    invalid = deepcopy(dataset)
    invalid["records"][0]["config_download_url"] = "https://example.invalid/profile.ovpn"
    invalid["records"][0]["redistribution_allowed"] = False
    with pytest.raises(ValidationFailure, match="redistribution_allowed=true"):
        validate_dataset_semantics(invalid)


def test_publication_requires_source_rights_decision(dataset: dict) -> None:
    invalid = deepcopy(dataset)
    invalid["records"][0].pop("source_license")
    invalid["records"][0].pop("redistribution_allowed")
    with pytest.raises(ValidationFailure, match="publication rights"):
        validate_dataset_semantics(invalid)


def test_wrong_wireguard_public_key_length_is_rejected() -> None:
    record = load_json("fixtures/wireguard.synthetic.json")
    record["server_public_key"] = "QUFBQQ=="
    with pytest.raises(ValidationFailure, match="32 bytes"):
        validate_wireguard_semantics(record)


def test_wireguard_forbidden_client_fields_are_rejected() -> None:
    record = load_json("fixtures/wireguard.synthetic.json")
    schema = load_json("schema/wireguard-metadata.schema.json")
    record["client_private_key"] = "synthetic-forbidden-value"
    assert any("additionalProperties" in item for item in schema_errors(record, schema))


def test_error_fixture_matches_openapi() -> None:
    contract = load_json("openapi/openapi.json")
    fixture = load_json("fixtures/error.synthetic.json")
    validate_schema(fixture, contract["components"]["schemas"]["Error"], "error")


def test_cli_help() -> None:
    result = subprocess.run(
        [sys.executable, str(ROOT / "tools/pvl_api.py"), "--help"],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert "PublicVPNList API v1" in result.stdout
