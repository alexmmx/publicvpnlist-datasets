"""Schema, semantic, manifest, CSV and ZIP validation."""

from __future__ import annotations

import base64
import binascii
import csv
import hashlib
import ipaddress
import json
import re
import stat
import unicodedata
import zipfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

ID_RE = re.compile(r"^pvl_[a-f0-9]{24}$")
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
DATASET_VERSION_RE = re.compile(r"^\d{8}T\d{6}Z-[a-f0-9]{12}$")
ARCHIVE_EXTENSIONS = {".zip", ".7z", ".rar", ".tar", ".gz", ".bz2", ".xz"}
OPENVPN_HOOKS = {
    "client-connect",
    "client-disconnect",
    "down",
    "ipchange",
    "learn-address",
    "route-up",
    "script-security",
    "tls-verify",
    "up",
}
OPENVPN_LOCAL_PATH_DIRECTIVES = {"auth-user-pass", "ca", "cert", "key", "pkcs12"}


class ValidationFailure(ValueError):
    """A public-safe validation failure containing no record values."""


def load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValidationFailure(f"{path.name}: expected a JSON object")
    return payload


def schema_errors(instance: Any, schema: dict[str, Any]) -> list[str]:
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(instance), key=lambda item: list(item.path))
    return [
        f"{_json_path(error.absolute_path)}: {error.validator} validation failed"
        for error in errors
    ]


def validate_schema(instance: Any, schema: dict[str, Any], label: str) -> None:
    errors = schema_errors(instance, schema)
    if errors:
        raise ValidationFailure(f"{label}:\n" + "\n".join(errors))


def validate_dataset_semantics(payload: dict[str, Any]) -> None:
    metadata = payload.get("metadata")
    records = payload.get("records")
    if not isinstance(metadata, dict) or not isinstance(records, list):
        raise ValidationFailure("dataset: invalid envelope")

    failures: list[str] = []
    generated = _parse_time(metadata.get("generated_at"), "metadata.generated_at", failures)
    expires = _parse_time(metadata.get("expires_at"), "metadata.expires_at", failures)
    if generated and expires and generated >= expires:
        failures.append("metadata: generated_at must be earlier than expires_at")

    record_count = metadata.get("record_count")
    if record_count != len(records):
        failures.append("metadata.record_count: does not match records length")
    if metadata.get("fresh_count", 0) + metadata.get("stale_count", 0) != record_count:
        failures.append("metadata: fresh_count + stale_count must equal record_count")

    ids: list[str] = []
    countries: set[str] = set()
    protocols: set[str] = set()
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            failures.append(f"records[{index}]: expected object")
            continue
        public_id = record.get("id")
        if isinstance(public_id, str):
            ids.append(public_id)
        country = record.get("country_code")
        if isinstance(country, str):
            countries.add(country)
        protocol = record.get("protocol")
        if isinstance(protocol, str):
            protocols.add(protocol)

        first_seen = _parse_time(
            record.get("first_seen_at"),
            f"records[{index}].first_seen_at",
            failures,
            optional=True,
        )
        last_checked = _parse_time(
            record.get("last_checked_at"),
            f"records[{index}].last_checked_at",
            failures,
            optional=True,
        )
        last_success = _parse_time(
            record.get("last_success_at"),
            f"records[{index}].last_success_at",
            failures,
            optional=True,
        )
        if first_seen and last_checked and first_seen > last_checked:
            failures.append(f"records[{index}]: first_seen_at exceeds last_checked_at")
        if last_success and last_checked and last_success > last_checked:
            failures.append(f"records[{index}]: last_success_at exceeds last_checked_at")
        if last_checked and generated and last_checked > generated:
            failures.append(f"records[{index}]: last_checked_at exceeds generated_at")

        config_url = record.get("config_download_url")
        redistribution = record.get("redistribution_allowed")
        source_license = record.get("source_license")
        if not isinstance(source_license, str) or not source_license.strip():
            failures.append(
                f"records[{index}].source_license: publication rights must be recorded",
            )
        if not isinstance(redistribution, bool):
            failures.append(
                f"records[{index}].redistribution_allowed: explicit decision is required",
            )
        if config_url is not None and redistribution is not True:
            failures.append(
                f"records[{index}].config_download_url: requires redistribution_allowed=true",
            )
        checksum = record.get("config_sha256")
        if checksum is not None and (
            not isinstance(checksum, str) or not SHA256_RE.fullmatch(checksum)
        ):
            failures.append(f"records[{index}].config_sha256: invalid SHA-256")

    if len(ids) != len(set(ids)):
        failures.append("records.id: duplicate public identifier")
    if metadata.get("countries_count") != len(countries):
        failures.append("metadata.countries_count: does not match distinct countries")
    declared_protocols = metadata.get("protocols")
    if isinstance(declared_protocols, list) and set(declared_protocols) != protocols:
        failures.append("metadata.protocols: does not match distinct record protocols")
    if "protocols_count" in metadata and metadata["protocols_count"] != len(protocols):
        failures.append("metadata.protocols_count: does not match distinct protocols")

    if failures:
        raise ValidationFailure("dataset semantic validation:\n" + "\n".join(failures))


def validate_wireguard_semantics(record: dict[str, Any]) -> None:
    public_key = record.get("server_public_key")
    if not isinstance(public_key, str):
        raise ValidationFailure("server_public_key: missing")
    try:
        decoded = base64.b64decode(public_key, validate=True)
    except (binascii.Error, ValueError) as error:
        raise ValidationFailure("server_public_key: invalid base64") from error
    if len(decoded) != 32:
        raise ValidationFailure("server_public_key: decoded key must be 32 bytes")


def csv_cell_is_dangerous(value: str) -> bool:
    remaining = value
    while remaining:
        first = remaining[0]
        if first in {"\ufeff", "\u200b", "\u200c", "\u200d", "\u2060"}:
            remaining = remaining[1:]
            continue
        category = unicodedata.category(first)
        if first.isspace() or category in {"Cf", "Zl", "Zp", "Zs"}:
            if first in {"\t", "\r", "\n"}:
                return True
            remaining = remaining[1:]
            continue
        break
    return bool(remaining) and remaining[0] in {"=", "+", "-", "@"}


def validate_csv(path: Path, expected_records: int | None = None) -> None:
    with path.open(newline="", encoding="utf-8-sig") as handle:
        rows = list(csv.reader(handle))
    if not rows:
        raise ValidationFailure(f"{path.name}: CSV is empty")
    if expected_records is not None and len(rows) != expected_records + 1:
        raise ValidationFailure(f"{path.name}: CSV row count mismatch")
    for row_index, row in enumerate(rows):
        for column_index, value in enumerate(row):
            if csv_cell_is_dangerous(value):
                raise ValidationFailure(
                    f"{path.name}: unsafe CSV cell at row {row_index + 1}, "
                    f"column {column_index + 1}",
                )


def validate_manifest(
    manifest: dict[str, Any],
    base_dir: Path,
    supported_formats: set[str],
) -> None:
    formats = manifest.get("formats")
    if not isinstance(formats, list):
        raise ValidationFailure("manifest.formats: expected array")
    seen: set[str] = set()
    failures: list[str] = []
    for index, item in enumerate(formats):
        if not isinstance(item, dict):
            failures.append(f"manifest.formats[{index}]: expected object")
            continue
        format_name = item.get("format")
        if not isinstance(format_name, str) or format_name not in supported_formats:
            failures.append(f"manifest.formats[{index}].format: unsupported")
            continue
        if format_name in seen:
            failures.append(f"manifest.formats[{index}].format: duplicate")
        seen.add(format_name)
        relative = item.get("path")
        if not isinstance(relative, str):
            failures.append(f"manifest.formats[{index}].path: missing")
            continue
        path = _safe_child(base_dir, relative)
        if path is None or not path.is_file():
            failures.append(f"manifest.formats[{index}].path: missing or unsafe")
            continue
        if item.get("bytes") != path.stat().st_size:
            failures.append(f"manifest.formats[{index}].bytes: size mismatch")
        if item.get("sha256") != _sha256(path):
            failures.append(f"manifest.formats[{index}].sha256: checksum mismatch")
    if seen != supported_formats:
        failures.append("manifest.formats: does not contain the configured format set")
    if failures:
        raise ValidationFailure("manifest validation:\n" + "\n".join(failures))


@dataclass(frozen=True)
class ZipPolicy:
    max_archive_bytes: int = 10 * 1024 * 1024
    max_files: int = 1
    max_expanded_bytes: int = 2 * 1024 * 1024
    max_ratio: float = 100.0
    max_name_length: int = 180
    allowed_extensions: tuple[str, ...] = (".ovpn",)


DEFAULT_ZIP_POLICY = ZipPolicy()


def validate_openvpn_zip(
    path: Path,
    *,
    policy: ZipPolicy = DEFAULT_ZIP_POLICY,
    allow_documentation_addresses: bool = False,
) -> None:
    if path.stat().st_size > policy.max_archive_bytes:
        raise ValidationFailure(f"{path.name}: archive size limit exceeded")
    try:
        archive = zipfile.ZipFile(path)
    except zipfile.BadZipFile as error:
        raise ValidationFailure(f"{path.name}: invalid ZIP") from error
    with archive:
        infos = archive.infolist()
        failures: list[str] = []
        if not 1 <= len(infos) <= policy.max_files:
            failures.append("archive: invalid file count")
        expanded = sum(info.file_size for info in infos)
        if expanded > policy.max_expanded_bytes:
            failures.append("archive: expanded size limit exceeded")
        normalized_names: set[str] = set()
        for index, info in enumerate(infos):
            entry_failures: list[str] = []
            raw_name = info.filename
            normalized = unicodedata.normalize("NFKC", raw_name).replace("\\", "/")
            folded = normalized.casefold()
            if len(normalized) > policy.max_name_length:
                entry_failures.append(f"archive.entries[{index}].name: too long")
            if folded in normalized_names:
                entry_failures.append(f"archive.entries[{index}].name: duplicate")
            normalized_names.add(folded)
            pure = PurePosixPath(normalized)
            if (
                raw_name != normalized
                or normalized.startswith("/")
                or not pure.parts
                or ":" in pure.parts[0]
                or any(part in {"", ".", ".."} for part in pure.parts)
            ):
                entry_failures.append(f"archive.entries[{index}].name: unsafe path")
            if info.flag_bits & 0x1:
                entry_failures.append(f"archive.entries[{index}]: encrypted")
            mode = info.external_attr >> 16
            file_type = stat.S_IFMT(mode)
            if file_type not in {0, stat.S_IFREG} or stat.S_ISLNK(mode):
                entry_failures.append(f"archive.entries[{index}]: special file")
            suffix = PurePosixPath(normalized).suffix.casefold()
            if suffix not in policy.allowed_extensions:
                entry_failures.append(f"archive.entries[{index}]: extension is not allowed")
            if suffix in ARCHIVE_EXTENSIONS - set(policy.allowed_extensions):
                entry_failures.append(f"archive.entries[{index}]: nested archive")
            ratio = info.file_size / max(info.compress_size, 1)
            if ratio > policy.max_ratio:
                entry_failures.append(f"archive.entries[{index}]: compression ratio exceeded")
            failures.extend(entry_failures)
            if entry_failures:
                continue
            content = archive.read(info)
            _validate_openvpn_text(
                content,
                f"archive.entries[{index}]",
                failures,
                allow_documentation_addresses,
            )
        if failures:
            raise ValidationFailure("ZIP validation:\n" + "\n".join(failures))


def _validate_openvpn_text(
    content: bytes,
    label: str,
    failures: list[str],
    allow_documentation_addresses: bool,
) -> None:
    if b"\x00" in content:
        failures.append(f"{label}: binary content")
        return
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        failures.append(f"{label}: invalid UTF-8")
        return
    if len(content) > 512 * 1024:
        failures.append(f"{label}: profile size limit exceeded")
    for line_number, raw_line in enumerate(text.splitlines(), 1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith(("#", ";")):
            continue
        directive, _, argument = stripped.partition(" ")
        directive = directive.casefold()
        if directive in OPENVPN_HOOKS:
            failures.append(f"{label}.line[{line_number}]: executable hook")
        if directive in OPENVPN_LOCAL_PATH_DIRECTIVES and argument.strip() != "[inline]":
            failures.append(f"{label}.line[{line_number}]: local credential path")
        if directive == "auth-user-pass":
            failures.append(f"{label}.line[{line_number}]: credential directive")
        if directive in {"remote", "route"} and argument:
            candidate = argument.split()[0].strip("[]")
            try:
                address = ipaddress.ip_address(candidate)
            except ValueError:
                continue
            if not address.is_global and not (
                allow_documentation_addresses and _is_documentation_address(address)
            ):
                failures.append(f"{label}.line[{line_number}]: non-public address")
    lowered = text.casefold()
    if "<" + "key>" in lowered or "begin private key" in lowered:
        failures.append(f"{label}: embedded private key")
    if "<" + "cert>" in lowered:
        failures.append(f"{label}: embedded client certificate")
    if "privatekey" in lowered or "presharedkey" in lowered:
        failures.append(f"{label}: WireGuard credential")


def _is_documentation_address(address: ipaddress._BaseAddress) -> bool:
    networks = (
        ipaddress.ip_network("192.0.2.0/24"),
        ipaddress.ip_network("198.51.100.0/24"),
        ipaddress.ip_network("203.0.113.0/24"),
        ipaddress.ip_network("2001:db8::/32"),
    )
    return any(address in network for network in networks)


def _safe_child(base_dir: Path, relative: str) -> Path | None:
    if "\\" in relative:
        return None
    candidate = (base_dir / relative).resolve()
    try:
        candidate.relative_to(base_dir.resolve())
    except ValueError:
        return None
    return candidate


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _parse_time(
    value: Any,
    path: str,
    failures: list[str],
    *,
    optional: bool = False,
) -> datetime | None:
    if value is None and optional:
        return None
    if not isinstance(value, str):
        failures.append(f"{path}: expected date-time")
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        failures.append(f"{path}: invalid date-time")
        return None


def _json_path(parts: Any) -> str:
    path = "$"
    for part in parts:
        path += f"[{part}]" if isinstance(part, int) else f".{part}"
    return path
