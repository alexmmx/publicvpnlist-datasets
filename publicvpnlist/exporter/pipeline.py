"""Canonical internal-record to public-snapshot transformation."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import math
import re
import unicodedata
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from publicvpnlist.validation import (
    ValidationFailure,
    csv_cell_is_dangerous,
    validate_dataset_semantics,
    validate_schema,
)

from .policy import ExportSettings, SourceDecision, SourceRegistry

SCORE_NOTICE = "Technical quality score is not a privacy, identity or trust assessment."
CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
HOST_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
REJECTION_REASONS = {
    "source_not_approved",
    "license_missing",
    "metadata_export_not_allowed",
    "stale",
    "invalid_endpoint",
    "failed_check",
    "schema_error",
    "duplicate",
    "secret_detected",
}


@dataclass(frozen=True)
class PipelineResult:
    dataset: dict[str, Any]
    records_read: int
    records_accepted: int
    records_rejected: int
    duplicates_removed: int
    rejection_reasons: dict[str, int]


class RecordRejected(ValueError):
    def __init__(self, reason: str) -> None:
        if reason not in REJECTION_REASONS:
            reason = "schema_error"
        super().__init__(reason)
        self.reason = reason


class ExportPipeline:
    """Create one validated canonical record list for all output formats."""

    def __init__(
        self,
        *,
        registry: SourceRegistry,
        settings: ExportSettings,
        hmac_secret: bytes,
        server_schema: dict[str, Any],
        allow_documentation_addresses: bool = False,
    ) -> None:
        if len(hmac_secret) < 32:
            raise ValidationFailure("export: HMAC secret must contain at least 32 bytes")
        self.registry = registry
        self.settings = settings
        self._secret = hmac_secret
        self.server_schema = server_schema
        self.allow_documentation_addresses = allow_documentation_addresses

    def build(
        self,
        rows: Iterable[dict[str, Any]],
        *,
        generated_at: datetime,
    ) -> PipelineResult:
        generated_at = _utc(generated_at)
        raw_rows = list(rows)
        rejected: Counter[str] = Counter()
        candidates: list[dict[str, Any]] = []
        for raw in raw_rows:
            try:
                candidates.append(self._record(raw, generated_at))
            except RecordRejected as error:
                rejected[error.reason] += 1

        deduped: dict[str, dict[str, Any]] = {}
        for record in candidates:
            key = _endpoint_key(record)
            previous = deduped.get(key)
            if previous is None or _record_rank(record) > _record_rank(previous):
                if previous is not None:
                    rejected["duplicate"] += 1
                deduped[key] = record
            else:
                rejected["duplicate"] += 1

        records = sorted(
            deduped.values(),
            key=lambda record: (
                record["country_code"] or "",
                record["protocol"],
                record["transport"],
                record["hostname"] or record["ip"] or "",
                record["port"],
                record["id"],
            ),
        )
        generated_text = _format_time(generated_at)
        expires = generated_at + timedelta(seconds=self.settings.expires_after_seconds)
        next_update = generated_at + timedelta(
            seconds=self.settings.next_update_after_seconds,
        )
        countries = {record["country_code"] for record in records}
        protocols = sorted({record["protocol"] for record in records})
        sources = {record["source_name"] for record in records}
        timestamp_version = generated_at.strftime("%Y%m%dT%H%M%SZ")
        metadata: dict[str, Any] = {
            "dataset_version": "",
            "snapshot_id": "",
            "generated_at": generated_text,
            "expires_at": _format_time(expires),
            "next_update_at": _format_time(next_update),
            "record_count": len(records),
            "fresh_count": len(records),
            "stale_count": 0,
            "countries_count": len(countries),
            "protocols_count": len(protocols),
            "source_count": len(sources),
            "protocols": protocols,
            "schema_version": "1.0",
            "checksum_sha256": "",
            "source_url": "https://publicvpnlist.com/",
            "documentation_url": "https://publicvpnlist.com/api/",
            "license_url": "https://publicvpnlist.com/license/",
            "methodology_url": "https://publicvpnlist.com/methodology/",
            "score_notice": SCORE_NOTICE,
        }
        seed = _canonical_json({"metadata": metadata, "records": records})
        checksum = hashlib.sha256(seed).hexdigest()
        version = f"{timestamp_version}-{checksum[:12]}"
        metadata["checksum_sha256"] = checksum
        metadata["dataset_version"] = version
        metadata["snapshot_id"] = version
        dataset = {"metadata": metadata, "records": records}

        if records:
            validate_schema(dataset, self.server_schema, "generated dataset")
            validate_dataset_semantics(dataset)
        return PipelineResult(
            dataset=dataset,
            records_read=len(raw_rows),
            records_accepted=len(records),
            records_rejected=sum(rejected.values()),
            duplicates_removed=rejected["duplicate"],
            rejection_reasons=dict(sorted(rejected.items())),
        )

    def _record(
        self,
        raw: dict[str, Any],
        generated_at: datetime,
    ) -> dict[str, Any]:
        if not isinstance(raw, dict) or not _as_bool(raw.get("active")):
            raise RecordRejected("failed_check")
        source = self._source(raw.get("source"))
        protocol = _clean(raw.get("protocol") or "openvpn", 32).casefold()
        if protocol not in self.settings.allowed_protocols:
            raise RecordRejected("invalid_endpoint")
        transport = _normalize_transport(raw.get("transport") or raw.get("proto"))
        port = _integer(raw.get("port"))
        if transport not in {"tcp", "udp"} or port is None or not 1 <= port <= 65535:
            raise RecordRejected("invalid_endpoint")

        hostname = _normalize_hostname(
            raw.get("host") or raw.get("hostname"),
            allow_documentation=self.allow_documentation_addresses,
        )
        ip_value = _normalize_ip(
            raw.get("ip"),
            allow_documentation=self.allow_documentation_addresses,
        )
        if hostname is not None:
            try:
                host_ip = _normalize_ip(
                    hostname,
                    allow_documentation=self.allow_documentation_addresses,
                )
            except RecordRejected:
                host_ip = None
            if host_ip is not None:
                ip_value = ip_value or host_ip
                hostname = None
        if hostname is None and ip_value is None:
            raise RecordRejected("invalid_endpoint")

        checked_at = _parse_time(raw.get("checked_at") or raw.get("last_checked_at"))
        if checked_at is None or checked_at > generated_at:
            raise RecordRejected("failed_check")
        if (generated_at - checked_at).total_seconds() > self.settings.fresh_max_age_seconds:
            raise RecordRejected("stale")
        checker_status = _clean(raw.get("checker_status"), 80).casefold()
        if checker_status not in self.settings.accepted_checker_statuses:
            raise RecordRejected("failed_check")
        if (
            not _as_bool(raw.get("last_check_ok"))
            or _integer(raw.get("fail_streak"), 0) != 0
            or not _as_bool(raw.get("canonical_visible"))
            or not _as_bool(raw.get("canonical_downloadable"))
            or not _as_bool(raw.get("config_available"))
        ):
            raise RecordRejected("failed_check")
        if raw.get("clean") not in (None, "") and not _as_bool(raw.get("clean")):
            raise RecordRejected("failed_check")

        country_code = _clean(raw.get("country_code") or raw.get("cc"), 2).upper()
        if not re.fullmatch(r"[A-Z]{2}", country_code):
            raise RecordRejected("schema_error")
        country_name = _nullable_clean(raw.get("country_name") or raw.get("country"), 120)
        speed = _nullable_number(raw.get("speed_mbps"))
        latency = _nullable_number(raw.get("latency_ms"))
        if speed is None or latency is None or speed <= 0 or latency <= 0:
            raise RecordRejected("failed_check")

        endpoint = hostname or ip_value
        assert endpoint is not None
        public_id = self._public_id(protocol, transport, endpoint, port)
        first_seen = _optional_time(raw.get("first_seen_at"))
        last_success = _optional_time(raw.get("last_success_at")) or checked_at
        config_updated = _optional_time(raw.get("config_updated_at"))
        if first_seen is not None and first_seen > checked_at:
            raise RecordRejected("schema_error")
        if last_success > checked_at:
            raise RecordRejected("schema_error")
        if config_updated is not None and config_updated > generated_at:
            raise RecordRejected("schema_error")
        score = _integer(raw.get("technical_quality_score"), 0)
        score = max(0, min(100, score or 0))
        score_label = _nullable_clean(raw.get("score_label"), 40) or _score_label(score)
        record: dict[str, Any] = {
            "id": public_id,
            "country_code": country_code,
            "country_name": country_name,
            "city": _nullable_clean(raw.get("city"), 120),
            "hostname": hostname,
            "ip": ip_value,
            "protocol": protocol,
            "transport": transport,
            "port": port,
            "speed_mbps": speed,
            "latency_ms": latency,
            "jitter_ms": _nullable_number(raw.get("jitter_ms")),
            "packet_loss_percent": _bounded_number(
                raw.get("packet_loss_percent"),
                100,
            ),
            "upload_mbps": _nullable_number(raw.get("upload_mbps")),
            "uptime_percent_24h": _bounded_number(
                raw.get("uptime_percent_24h"),
                100,
            ),
            "uptime_percent_7d": _bounded_number(raw.get("uptime_percent_7d"), 100),
            "uptime_percent_30d": _bounded_number(
                raw.get("uptime_percent_30d"),
                100,
            ),
            "uptime_hours": _nullable_number(raw.get("uptime_hours")),
            "sessions": _non_negative_integer(raw.get("sessions")),
            "technical_quality_score": score,
            "score_label": score_label,
            "last_checked_at": _format_time(checked_at),
            "last_success_at": _format_time(last_success),
            "first_seen_at": _format_time(first_seen) if first_seen else None,
            "config_updated_at": _format_time(config_updated) if config_updated else None,
            "freshness_status": "fresh",
            "availability_status": "online_at_last_check",
            "source_name": source.source_name,
            "source_url": source.source_url,
            "source_license": source.source_license,
            "redistribution_allowed": source.redistribution_allowed,
            "server_page_url": f"https://publicvpnlist.com/api/v1/servers/{public_id}",
            "config_download_url": None,
            "risk_flags": sorted(
                {"privacy_not_assessed", "state_may_change", "third_party_server"},
            ),
            "config_sha256": None,
        }
        for value in record.values():
            if isinstance(value, str) and csv_cell_is_dangerous(value):
                raise RecordRejected("schema_error")
        try:
            record_schema = {
                "$schema": self.server_schema["$schema"],
                "$defs": self.server_schema["$defs"],
                "$ref": "#/$defs/OpenVpnServer",
            }
            validate_schema(record, record_schema, "record")
        except ValidationFailure as error:
            raise RecordRejected("schema_error") from error
        return record

    def _source(self, name: Any) -> SourceDecision:
        source = self.registry.resolve(name)
        if source is None or source.review_status != "approved":
            raise RecordRejected("source_not_approved")
        if not source.metadata_export_allowed:
            raise RecordRejected("metadata_export_not_allowed")
        if not source.source_name or not source.source_url or not source.source_license:
            raise RecordRejected("license_missing")
        return source

    def _public_id(
        self,
        protocol: str,
        transport: str,
        endpoint: str,
        port: int,
    ) -> str:
        message = f"{protocol}|{transport}|{endpoint}|{port}".encode()
        digest = hmac.new(self._secret, message, hashlib.sha256).hexdigest()
        return f"pvl_{digest[:24]}"


def _clean(value: Any, limit: int) -> str:
    if value is None:
        return ""
    text = unicodedata.normalize("NFC", str(value)).strip()
    text = CONTROL_RE.sub("", text)
    return text[:limit]


def _nullable_clean(value: Any, limit: int) -> str | None:
    cleaned = _clean(value, limit)
    return cleaned or None


def _normalize_hostname(value: Any, *, allow_documentation: bool) -> str | None:
    host = _clean(value, 253).casefold().rstrip(".")
    if not host:
        return None
    if re.fullmatch(r"[0-9.]+", host):
        return None
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return host
    if len(host) > 253 or "." not in host:
        return None
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    always_reserved = ("localhost", ".localhost", ".local", ".internal", ".home", ".lan")
    documentation = (".invalid", ".example", ".test")
    if ascii_host == "localhost" or ascii_host.endswith(always_reserved[1:]):
        return None
    if not allow_documentation and ascii_host.endswith(documentation):
        return None
    if all(HOST_LABEL_RE.fullmatch(label) for label in ascii_host.split(".")):
        return ascii_host
    return None


def _normalize_ip(value: Any, *, allow_documentation: bool) -> str | None:
    cleaned = _clean(value, 80).strip("[]")
    if not cleaned:
        return None
    if "%" in cleaned:
        raise RecordRejected("invalid_endpoint")
    try:
        address = ipaddress.ip_address(cleaned)
    except ValueError as error:
        raise RecordRejected("invalid_endpoint") from error
    if not address.is_global and not (allow_documentation and _documentation_address(address)):
        raise RecordRejected("invalid_endpoint")
    return address.compressed


def _documentation_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return any(
        address in network
        for network in (
            ipaddress.ip_network("192.0.2.0/24"),
            ipaddress.ip_network("198.51.100.0/24"),
            ipaddress.ip_network("203.0.113.0/24"),
            ipaddress.ip_network("2001:db8::/32"),
        )
    )


def _normalize_transport(value: Any) -> str:
    text = _clean(value, 16).casefold()
    if text.startswith("tcp"):
        return "tcp"
    return "udp" if text == "udp" else text


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().casefold() in {"1", "true", "yes", "y", "on"}


def _integer(value: Any, default: int | None = None) -> int | None:
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return default
    try:
        number = int(str(value))
    except (TypeError, ValueError):
        return default
    return number


def _non_negative_integer(value: Any) -> int | None:
    number = _integer(value)
    return number if number is not None and number >= 0 else None


def _nullable_number(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(number) or number < 0:
        return None
    return round(number, 3)


def _bounded_number(value: Any, maximum: float) -> float | None:
    number = _nullable_number(value)
    return number if number is not None and number <= maximum else None


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC).replace(microsecond=0)


def _optional_time(value: Any) -> datetime | None:
    return _parse_time(value)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).replace(microsecond=0)


def _format_time(value: datetime) -> str:
    return _utc(value).isoformat().replace("+00:00", "Z")


def _score_label(score: int) -> str:
    if score >= 80:
        return "Good"
    if score >= 50:
        return "Fair"
    return "Limited"


def _endpoint_key(record: dict[str, Any]) -> str:
    endpoint = record["hostname"] or record["ip"]
    return "|".join(
        (
            record["protocol"],
            record["transport"],
            endpoint,
            str(record["port"]),
        ),
    )


def _record_rank(record: dict[str, Any]) -> tuple[float, int, str]:
    checked = _parse_time(record["last_checked_at"])
    timestamp = checked.timestamp() if checked else 0.0
    completeness = sum(value is not None and value != "" for value in record.values())
    stable = hashlib.sha256(_canonical_json(record)).hexdigest()
    return timestamp, completeness, stable


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode()
