#!/usr/bin/env python3
"""Run all offline repository and optional snapshot checks."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit
from xml.etree import ElementTree

import yaml
from jsonschema import Draft202012Validator
from openapi_spec_validator import validate_url

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from publicvpnlist.exporter.policy import ExportSettings, SourceRegistry  # noqa: E402
from publicvpnlist.security import scan_repository  # noqa: E402
from publicvpnlist.validation import (  # noqa: E402
    ValidationFailure,
    ZipPolicy,
    load_json,
    validate_csv,
    validate_dataset_semantics,
    validate_manifest,
    validate_openvpn_zip,
    validate_schema,
    validate_wireguard_semantics,
)

REQUIRED_PATHS = {
    "/servers",
    "/servers/{public_id}",
    "/countries",
    "/protocols",
    "/stats",
    "/dataset",
    "/health",
}
MARKDOWN_LINK_RE = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
HTML_LINK_RE = re.compile(r"(?:href|src)=[\"']([^\"']+)[\"']", re.I)


def fail(message: str) -> None:
    raise ValidationFailure(message)


def validate_schemas() -> dict[str, dict]:
    schemas: dict[str, dict] = {}
    for path in sorted((ROOT / "schema").glob("*.schema.json")):
        schema = load_json(path)
        Draft202012Validator.check_schema(schema)
        schemas[path.name] = schema
    return schemas


def validate_exporter_configuration() -> None:
    SourceRegistry.from_path(ROOT / "config" / "dataset_sources.json")
    ExportSettings.from_path(ROOT / "config" / "exporter.json", ROOT)


def validate_openapi(schemas: dict[str, dict]) -> dict:
    path = ROOT / "openapi" / "openapi.json"
    docs_copy = ROOT / "docs" / "openapi.json"
    if path.read_bytes() != docs_copy.read_bytes():
        fail("generated docs/openapi.json copy is out of sync")
    contract = load_json(path)
    if contract.get("openapi") != "3.1.0":
        fail("OpenAPI version mismatch")
    if set(contract.get("paths", {})) != REQUIRED_PATHS:
        fail("OpenAPI endpoint set mismatch")
    server_ref = contract["components"]["schemas"]["Server"].get("$ref")
    if server_ref != "../schema/servers.schema.json#/$defs/OpenVpnServer":
        fail("OpenAPI Server must reference the canonical JSON Schema")
    canonical = schemas["servers.schema.json"]["$defs"]["OpenVpnServer"]
    projection = schemas["servers.schema.json"]["$defs"]["OpenVpnServerProjection"]
    if not canonical.get("required") or not canonical.get("properties"):
        fail("canonical Server model is incomplete")
    if set(projection.get("properties", {})) != set(canonical["properties"]):
        fail("fields projection is out of sync with canonical Server fields")
    projection_ref = contract["components"]["schemas"]["ServerListItem"].get("$ref")
    if projection_ref != ("../schema/servers.schema.json#/$defs/OpenVpnServerProjection"):
        fail("OpenAPI ServerListItem must reference the canonical projection")
    validate_url(path.as_uri())
    return contract


def validate_fixtures(
    schemas: dict[str, dict],
    contract: dict,
    policy: dict,
) -> None:
    dataset = load_json(ROOT / "fixtures" / "dataset.synthetic.json")
    validate_schema(dataset, schemas["servers.schema.json"], "synthetic dataset")
    validate_dataset_semantics(dataset)

    wireguard = load_json(ROOT / "fixtures" / "wireguard.synthetic.json")
    validate_schema(
        wireguard,
        schemas["wireguard-metadata.schema.json"],
        "synthetic WireGuard metadata",
    )
    validate_wireguard_semantics(wireguard)

    manifest = load_json(ROOT / "fixtures" / "manifest.synthetic.json")
    validate_schema(manifest, schemas["manifest.schema.json"], "synthetic manifest")
    validate_manifest(
        manifest,
        ROOT / "fixtures",
        set(policy["supported_snapshot_formats"]),
    )
    validate_csv(ROOT / "fixtures" / "servers.synthetic.csv", 1)
    xml_text = (ROOT / "fixtures" / "servers.synthetic.xml").read_text(encoding="utf-8")
    if "<!DOCTYPE" in xml_text.upper() or "<!ENTITY" in xml_text.upper():
        fail("synthetic XML: DTD and entities are forbidden")
    ElementTree.fromstring(xml_text)

    error = load_json(ROOT / "fixtures" / "error.synthetic.json")
    validate_schema(error, contract["components"]["schemas"]["Error"], "synthetic error")


def validate_collections(contract: dict) -> None:
    postman = load_json(
        ROOT / "collections" / "postman" / "PublicVPNList.postman_collection.json",
    )
    if postman.get("info", {}).get("schema") != (
        "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
    ):
        fail("Postman collection schema mismatch")
    raw_urls = {
        item.get("request", {}).get("url", {}).get("raw") for item in postman.get("item", [])
    }
    for endpoint in contract["paths"]:
        sample = endpoint.replace("/{public_id}", "/{{publicId}}")
        if not any(isinstance(url, str) and sample in url for url in raw_urls):
            fail(f"Postman collection misses {endpoint}")
    bruno_text = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted((ROOT / "collections" / "bruno" / "requests").glob("*.bru"))
    )
    for endpoint in contract["paths"]:
        sample = endpoint.replace("/{public_id}", "/{{public_id}}")
        if sample not in bruno_text:
            fail(f"Bruno collection misses {endpoint}")


def validate_yaml() -> None:
    for path in sorted(ROOT.rglob("*.yml")) + sorted(ROOT.rglob("*.yaml")):
        if ".git" in path.parts:
            continue
        with path.open(encoding="utf-8") as handle:
            list(yaml.safe_load_all(handle))


def validate_repository_formats() -> None:
    for path in sorted(ROOT.rglob("*.json")):
        if ".git" not in path.parts:
            json.loads(path.read_text(encoding="utf-8"))
    for path in sorted(ROOT.rglob("*.csv")):
        if ".git" not in path.parts:
            validate_csv(path)
    for path in sorted(ROOT.rglob("*.xml")):
        if ".git" in path.parts:
            continue
        text = path.read_text(encoding="utf-8")
        if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
            fail(f"{path.relative_to(ROOT)}: DTD and entities are forbidden")
        ElementTree.fromstring(text)
    for suffix in ("*.txt", "*.md"):
        for path in sorted(ROOT.rglob(suffix)):
            if ".git" not in path.parts:
                path.read_text(encoding="utf-8")


def validate_repository_archives(policy: dict) -> None:
    zip_policy = ZipPolicy(
        max_archive_bytes=policy["maximum_archive_bytes"],
        max_files=policy["maximum_archive_files"],
        max_expanded_bytes=policy["maximum_expanded_bytes"],
        max_ratio=policy["maximum_compression_ratio"],
        max_name_length=policy["maximum_archive_name_length"],
        allowed_extensions=tuple(policy["allowed_archive_extensions"]),
    )
    for path in sorted(ROOT.rglob("*.zip")):
        if ".git" in path.parts:
            continue
        validate_openvpn_zip(
            path,
            policy=zip_policy,
            allow_documentation_addresses="fixtures" in path.parts,
        )


def validate_markdown_links() -> None:
    failures: list[str] = []
    paths = sorted(ROOT.rglob("*.md")) + sorted(ROOT.rglob("*.html"))
    for path in paths:
        if ".git" in path.parts:
            continue
        text = path.read_text(encoding="utf-8")
        targets = MARKDOWN_LINK_RE.findall(text) + HTML_LINK_RE.findall(text)
        for raw_target in targets:
            target = raw_target.strip().split(maxsplit=1)[0].strip("<>")
            parsed = urlsplit(target)
            if parsed.scheme or target.startswith(("#", "mailto:")):
                continue
            relative = unquote(parsed.path)
            candidate = (path.parent / relative).resolve()
            try:
                candidate.relative_to(ROOT.resolve())
            except ValueError:
                failures.append(f"{path.relative_to(ROOT)}: link escapes repository")
                continue
            if not candidate.exists():
                failures.append(
                    f"{path.relative_to(ROOT)}: missing link target {relative}",
                )
    if failures:
        fail("Markdown link validation:\n" + "\n".join(failures))


def validate_repository_secrets() -> None:
    findings = scan_repository(
        ROOT,
        allowlist_path=ROOT / "secret-scan-allowlist.json",
    )
    if findings:
        rendered = "\n".join(
            f"{finding.path}:{finding.line}: {finding.rule}" for finding in findings
        )
        fail("possible secret or credential material:\n" + rendered)


def validate_optional_snapshot(
    schemas: dict[str, dict],
    policy: dict,
) -> int:
    latest = ROOT / "latest"
    if not latest.exists():
        return 0
    manifest = load_json(latest / "manifest.json")
    validate_schema(manifest, schemas["manifest.schema.json"], "latest manifest")
    supported_formats = set(policy["supported_snapshot_formats"])
    validate_manifest(
        manifest,
        latest,
        supported_formats,
    )
    format_paths = {item["format"]: latest / item["path"] for item in manifest["formats"]}
    canonical_format = policy["canonical_dataset_format"]
    if canonical_format not in format_paths:
        fail("snapshot is missing the configured canonical representation")
    if canonical_format != "json":
        fail("semantic parsing for the configured canonical format is not implemented")
    payload = load_json(format_paths[canonical_format])
    validate_schema(payload, schemas["servers.schema.json"], "latest dataset")
    validate_dataset_semantics(payload)
    if "csv" in format_paths:
        validate_csv(format_paths["csv"], len(payload["records"]))
    if "xml" in format_paths:
        xml_text = format_paths["xml"].read_text(encoding="utf-8")
        if "<!DOCTYPE" in xml_text.upper() or "<!ENTITY" in xml_text.upper():
            fail("snapshot XML: DTD and entities are forbidden")
        ElementTree.fromstring(xml_text)
    if "txt" in format_paths:
        format_paths["txt"].read_text(encoding="utf-8")

    previous = ROOT / ".previous-record-count"
    if previous.exists():
        old = int(previous.read_text(encoding="ascii").strip())
        current = len(payload["records"])
        if old >= 100 and current < int(old * 0.7):
            fail(f"record count dropped more than 30%: {old} -> {current}")
    return len(payload["records"])


def main() -> int:
    try:
        policy = load_json(ROOT / "validation-policy.json")
        schemas = validate_schemas()
        validate_exporter_configuration()
        contract = validate_openapi(schemas)
        validate_fixtures(schemas, contract, policy)
        validate_collections(contract)
        validate_yaml()
        validate_repository_formats()
        validate_repository_archives(policy)
        validate_markdown_links()
        validate_repository_secrets()
        count = validate_optional_snapshot(schemas, policy)
    except (ValidationFailure, KeyError, OSError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 1
    if count:
        print(f"validated repository and {count} snapshot records")
    else:
        print(
            "validated repository; only schemas and synthetic metadata fixtures are published",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
