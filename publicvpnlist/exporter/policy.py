"""Deny-by-default source registry and exporter settings."""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from publicvpnlist.validation import ValidationFailure

REVIEW_STATUSES = {"approved", "pending", "rejected", "unknown"}
SOURCE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,63}$")
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
REQUIRED_SOURCE_FIELDS = {
    "source_id",
    "source_name",
    "source_url",
    "source_license",
    "license_url",
    "attribution",
    "redistribution_allowed",
    "metadata_export_allowed",
    "config_redistribution_allowed",
    "review_status",
    "reviewed_at",
    "reviewed_by",
    "evidence_url",
    "notes",
}


def _alias_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.casefold())


def _https_url(value: Any, *, optional: bool = False) -> bool:
    if value is None and optional:
        return True
    if not isinstance(value, str):
        return False
    parsed = urlsplit(value)
    host = parsed.hostname or ""
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    return (
        parsed.scheme == "https"
        and bool(parsed.netloc)
        and not parsed.username
        and not parsed.password
        and not parsed.query
        and host.casefold() != "localhost"
        and not host.casefold().endswith((".local", ".internal", ".home", ".lan"))
        and (address is None or address.is_global)
    )


@dataclass(frozen=True)
class SourceDecision:
    source_id: str
    source_name: str
    source_url: str
    source_license: str
    redistribution_allowed: bool
    metadata_export_allowed: bool
    review_status: str


class SourceRegistry:
    """Resolve internal source labels and make an explicit publication decision."""

    def __init__(self, payload: dict[str, Any]) -> None:
        if payload.get("schema_version") != "1.0":
            raise ValidationFailure("source registry: unsupported schema_version")
        sources = payload.get("sources")
        if not isinstance(sources, list):
            raise ValidationFailure("source registry: sources must be an array")
        self._aliases: dict[str, SourceDecision] = {}
        source_ids: set[str] = set()
        for index, item in enumerate(sources):
            if not isinstance(item, dict):
                raise ValidationFailure(f"source registry[{index}]: expected object")
            missing = REQUIRED_SOURCE_FIELDS - set(item)
            if missing:
                raise ValidationFailure(f"source registry[{index}]: required fields missing")
            source_id = item["source_id"]
            if not isinstance(source_id, str) or not SOURCE_ID_RE.fullmatch(source_id):
                raise ValidationFailure(f"source registry[{index}]: invalid source_id")
            if source_id in source_ids:
                raise ValidationFailure(f"source registry[{index}]: duplicate source_id")
            source_ids.add(source_id)
            status = item["review_status"]
            if status not in REVIEW_STATUSES:
                raise ValidationFailure(f"source registry[{index}]: invalid review_status")
            for boolean_field in (
                "redistribution_allowed",
                "metadata_export_allowed",
                "config_redistribution_allowed",
            ):
                if not isinstance(item[boolean_field], bool):
                    raise ValidationFailure(
                        f"source registry[{index}]: {boolean_field} must be boolean",
                    )
            if not _https_url(item["source_url"]):
                raise ValidationFailure(f"source registry[{index}]: invalid source_url")
            for text_field, maximum in (
                ("source_name", 160),
                ("source_license", 300),
                ("attribution", 500),
                ("notes", 1000),
            ):
                value = item[text_field]
                if not isinstance(value, str) or len(value) > maximum or CONTROL_RE.search(value):
                    raise ValidationFailure(
                        f"source registry[{index}]: invalid {text_field}",
                    )
            for optional_url in ("license_url", "evidence_url"):
                if not _https_url(item[optional_url], optional=True):
                    raise ValidationFailure(
                        f"source registry[{index}]: invalid {optional_url}",
                    )
            reviewed_at = item["reviewed_at"]
            if reviewed_at is not None and not _date_time(reviewed_at):
                raise ValidationFailure(
                    f"source registry[{index}]: invalid reviewed_at",
                )
            reviewed_by = item["reviewed_by"]
            if reviewed_by is not None and (
                not isinstance(reviewed_by, str)
                or not reviewed_by.strip()
                or len(reviewed_by) > 160
                or CONTROL_RE.search(reviewed_by)
            ):
                raise ValidationFailure(
                    f"source registry[{index}]: invalid reviewed_by",
                )
            if (
                status == "approved"
                and item["metadata_export_allowed"]
                and not str(item["source_name"]).strip()
            ):
                raise ValidationFailure(
                    f"source registry[{index}]: approved source_name is empty",
                )
            if (
                status == "approved"
                and item["metadata_export_allowed"]
                and (
                    not str(item["reviewed_at"] or "").strip()
                    or not str(item["reviewed_by"] or "").strip()
                    or not item["evidence_url"]
                )
            ):
                raise ValidationFailure(
                    f"source registry[{index}]: approved review evidence is incomplete",
                )
            decision = SourceDecision(
                source_id=source_id,
                source_name=str(item["source_name"]).strip(),
                source_url=str(item["source_url"]).strip(),
                source_license=str(item["source_license"]).strip(),
                redistribution_allowed=item["redistribution_allowed"],
                metadata_export_allowed=item["metadata_export_allowed"],
                review_status=status,
            )
            aliases = item.get("aliases", [])
            if not isinstance(aliases, list) or not aliases:
                raise ValidationFailure(f"source registry[{index}]: aliases must not be empty")
            for alias in [source_id, item["source_name"], *aliases]:
                key = _alias_key(str(alias))
                if not key:
                    raise ValidationFailure(f"source registry[{index}]: invalid alias")
                previous = self._aliases.get(key)
                if previous and previous.source_id != source_id:
                    raise ValidationFailure(f"source registry[{index}]: alias collision")
                self._aliases[key] = decision

    @classmethod
    def from_path(cls, path: Path) -> SourceRegistry:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise ValidationFailure("source registry: cannot load registry") from error
        if not isinstance(payload, dict):
            raise ValidationFailure("source registry: expected object")
        return cls(payload)

    def resolve(self, internal_name: Any) -> SourceDecision | None:
        if not isinstance(internal_name, str):
            return None
        return self._aliases.get(_alias_key(internal_name))


@dataclass(frozen=True)
class Guardrails:
    minimum_record_count: int
    minimum_countries_count: int
    maximum_drop_percent: float
    maximum_invalid_percent: float


@dataclass(frozen=True)
class ExportSettings:
    fresh_max_age_seconds: int
    expires_after_seconds: int
    next_update_after_seconds: int
    accepted_checker_statuses: frozenset[str]
    allowed_protocols: frozenset[str]
    supported_formats: tuple[str, ...]
    output_root: Path
    lock_timeout_seconds: int
    retention_versions: int
    guardrails: Guardrails

    @classmethod
    def from_path(cls, path: Path, repository_root: Path) -> ExportSettings:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise ValidationFailure("export settings: cannot load configuration") from error
        if payload.get("schema_version") != "1.0":
            raise ValidationFailure("export settings: unsupported schema_version")
        guardrails = payload.get("guardrails")
        if not isinstance(guardrails, dict):
            raise ValidationFailure("export settings: guardrails are missing")
        output_value = payload.get("output_root")
        if (
            not isinstance(output_value, str)
            or not output_value
            or ".." in Path(output_value).parts
        ):
            raise ValidationFailure("export settings: invalid output_root")
        output_root = Path(output_value)
        if not output_root.is_absolute():
            output_root = repository_root / output_root
        formats = tuple(payload.get("supported_formats", ()))
        if set(formats) != {"json", "csv", "txt", "xml"}:
            raise ValidationFailure("export settings: JSON/CSV/TXT/XML are required")
        return cls(
            fresh_max_age_seconds=_positive_int(payload, "fresh_max_age_seconds"),
            expires_after_seconds=_positive_int(payload, "expires_after_seconds"),
            next_update_after_seconds=_positive_int(payload, "next_update_after_seconds"),
            accepted_checker_statuses=frozenset(
                str(value).strip().casefold()
                for value in payload.get("accepted_checker_statuses", [])
                if str(value).strip()
            ),
            allowed_protocols=frozenset(
                str(value).strip().casefold()
                for value in payload.get("allowed_protocols", [])
                if str(value).strip()
            ),
            supported_formats=formats,
            output_root=output_root,
            lock_timeout_seconds=_positive_int(payload, "lock_timeout_seconds"),
            retention_versions=_positive_int(payload, "retention_versions"),
            guardrails=Guardrails(
                minimum_record_count=_non_negative_int(
                    guardrails,
                    "minimum_record_count",
                ),
                minimum_countries_count=_non_negative_int(
                    guardrails,
                    "minimum_countries_count",
                ),
                maximum_drop_percent=_percent(guardrails, "maximum_drop_percent"),
                maximum_invalid_percent=_percent(guardrails, "maximum_invalid_percent"),
            ),
        )


def _positive_int(payload: dict[str, Any], key: str) -> int:
    value = payload.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ValidationFailure(f"export settings: {key} must be a positive integer")
    return value


def _non_negative_int(payload: dict[str, Any], key: str) -> int:
    value = payload.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValidationFailure(f"export settings: {key} must be a non-negative integer")
    return value


def _percent(payload: dict[str, Any], key: str) -> float:
    value = payload.get(key)
    if not isinstance(value, int | float) or isinstance(value, bool):
        raise ValidationFailure(f"export settings: {key} must be numeric")
    if not 0 <= float(value) <= 100:
        raise ValidationFailure(f"export settings: {key} must be between 0 and 100")
    return float(value)


def _date_time(value: Any) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None
