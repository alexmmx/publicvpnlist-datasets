#!/usr/bin/env python3
import csv
import hashlib
import json
import re
import sys
import zipfile
from pathlib import Path
from xml.etree import ElementTree

import jsonschema

ROOT = Path(__file__).resolve().parents[1]
LATEST = ROOT / "latest"
ID_RE = re.compile(r"^pvl_[a-f0-9]{24}$")
SECRET_RE = re.compile(
    rb"(BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY|gh[pousr]_[A-Za-z0-9]{20,}|"
    rb"github_pat_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16})"
)


def fail(message: str) -> None:
    raise SystemExit(message)


server_schema = json.loads((ROOT / "schema" / "servers.schema.json").read_text(encoding="utf-8"))
manifest_schema = json.loads((ROOT / "schema" / "manifest.schema.json").read_text(encoding="utf-8"))
jsonschema.Draft202012Validator.check_schema(server_schema)
jsonschema.Draft202012Validator.check_schema(manifest_schema)

for path in ROOT.rglob("*"):
    if path.is_file() and path.stat().st_size <= 64 * 1024 * 1024:
        if SECRET_RE.search(path.read_bytes()):
            fail(f"possible secret: {path.relative_to(ROOT)}")

if not LATEST.exists():
    print("validated schemas and repository; endpoint dataset is not published")
    raise SystemExit(0)

payload = json.loads((LATEST / "servers.json").read_text(encoding="utf-8"))
manifest = json.loads((LATEST / "manifest.json").read_text(encoding="utf-8"))
jsonschema.validate(payload, server_schema)
jsonschema.validate(manifest, manifest_schema)
records = payload.get("records")
meta = payload.get("metadata")
if not isinstance(records, list) or not isinstance(meta, dict) or not records:
    fail("dataset shape or empty-dataset guard failed")
if meta.get("record_count") != len(records):
    fail("record_count mismatch")
if not re.fullmatch(r"\d{8}T\d{6}Z-[a-f0-9]{12}", str(meta.get("dataset_version", ""))):
    fail("dataset_version failed")
ids = [row.get("id") for row in records]
if any(not isinstance(value, str) or not ID_RE.fullmatch(value) for value in ids):
    fail("stable public ID failed")
if len(ids) != len(set(ids)):
    fail("duplicate public ID")
if any("server_id" in row or "legacy_id" in row for row in records):
    fail("internal ID leak")

with (LATEST / "servers.csv").open(newline="", encoding="utf-8") as handle:
    csv_rows = list(csv.reader(handle))
if len(csv_rows) != len(records) + 1:
    fail("CSV row count failed")
if any(value.startswith(("=", "+", "-", "@", "\t", "\r")) for row in csv_rows for value in row):
    fail("CSV formula injection guard failed")

ElementTree.parse(LATEST / "servers.xml")

checksums = {}
for line in (LATEST / "checksums.txt").read_text(encoding="utf-8").splitlines():
    digest, name = line.split("  ", 1)
    checksums[name] = digest
aliases = {
    "openvpn-latest.json": LATEST / "servers.json",
    "openvpn-latest.csv": LATEST / "servers.csv",
    "openvpn-latest.txt": LATEST / "servers.txt",
    "openvpn-latest.xml": LATEST / "servers.xml",
    "openvpn-top-100.zip": ROOT / "configs" / "top-100.zip",
}
for name, digest in checksums.items():
    path = aliases.get(name, LATEST / name)
    if not path.exists():
        fail(f"checksum target missing: {name}")
    if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
        fail(f"checksum mismatch: {name}")

zip_path = ROOT / "configs" / "top-100.zip"
if zip_path.exists():
    with zipfile.ZipFile(zip_path) as archive:
        if sum(info.file_size for info in archive.infolist()) > 100 * 1024 * 1024:
            fail("ZIP expanded-size limit failed")
        for info in archive.infolist():
            name = info.filename
            if name.startswith(("/", "\\")) or ".." in Path(name).parts:
                fail("ZIP path traversal failed")
            if (info.external_attr >> 16) & 0o170000 == 0o120000:
                fail("ZIP symlink failed")

previous = ROOT / ".previous-record-count"
if previous.exists():
    old = int(previous.read_text().strip())
    if old >= 100 and len(records) < int(old * 0.7):
        fail(f"record count dropped more than 30%: {old} -> {len(records)}")

print(f"validated {len(records)} records")
