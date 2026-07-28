"""Command-line entrypoint for local metadata export."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from publicvpnlist.validation import ValidationFailure, load_json

from .pipeline import ExportPipeline
from .policy import ExportSettings, SourceRegistry
from .publisher import SnapshotPublisher

ROOT = Path(__file__).resolve().parents[2]


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Build a rights-gated PublicVPNList metadata snapshot locally.",
    )
    mode = result.add_mutually_exclusive_group()
    mode.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate without switching the current snapshot (default).",
    )
    mode.add_argument(
        "--publish-local",
        action="store_true",
        help="Atomically activate the bundle only under the configured local output root.",
    )
    result.add_argument("--output-dir", type=Path)
    result.add_argument("--generated-at", help="UTC RFC 3339 time for deterministic tests.")
    result.add_argument("--limit", type=int)
    result.add_argument("--source")
    result.add_argument("--protocol")
    result.add_argument("--allow-partial", action="store_true")
    result.add_argument("--override-guardrails", action="store_true")
    result.add_argument("--validate-only", type=Path, metavar="BUNDLE_DIR")
    result.add_argument("--report", type=Path)
    configured_site_root = os.environ.get("PVL_SITE_ROOT")
    result.add_argument(
        "--site-root",
        type=Path,
        default=Path(configured_site_root) if configured_site_root else None,
    )
    result.add_argument(
        "--registry",
        type=Path,
        default=ROOT / "config" / "dataset_sources.json",
    )
    result.add_argument(
        "--settings",
        type=Path,
        default=ROOT / "config" / "exporter.json",
    )
    return result


def main(argv: list[str] | None = None) -> int:
    os.umask(0o077)
    args = parser().parse_args(argv)
    try:
        settings = ExportSettings.from_path(args.settings, ROOT)
        publisher = SnapshotPublisher(
            repository_root=ROOT,
            settings=settings,
            server_schema=load_json(ROOT / "schema" / "servers.schema.json"),
            manifest_schema=load_json(ROOT / "schema" / "manifest.schema.json"),
        )
        if args.validate_only is not None:
            publisher.validate_bundle(args.validate_only)
            print("validation result: passed")
            return 0
        partial = args.limit is not None or args.source is not None or args.protocol is not None
        if partial and args.publish_local and not args.allow_partial:
            raise ValidationFailure(
                "partial export: --allow-partial is required with --publish-local",
            )
        if args.override_guardrails and not args.publish_local:
            raise ValidationFailure(
                "guardrail override: only valid with --publish-local",
            )
        generated_at = _generated_at(args.generated_at)
        if args.publish_local and args.generated_at:
            drift = abs((datetime.now(UTC) - generated_at).total_seconds())
            if drift > 300:
                raise ValidationFailure(
                    "generated_at: local publication time must be within five minutes",
                )
        secret = os.environ.get("PVL_DATASET_HMAC_SECRET", "").encode()
        if not secret:
            raise ValidationFailure("export: PVL_DATASET_HMAC_SECRET is required")
        registry = SourceRegistry.from_path(args.registry)
        if args.site_root is None:
            raise ValidationFailure("Bitrix reader: --site-root or PVL_SITE_ROOT is required")
        rows = _read_bitrix(args, generated_at)
        pipeline = ExportPipeline(
            registry=registry,
            settings=settings,
            hmac_secret=secret,
            server_schema=publisher.server_schema,
        )
        print("export started", file=sys.stderr)
        result = pipeline.build(rows, generated_at=generated_at)
        output = _output_path(args.output_dir, settings.output_root)
        publication = publisher.run(
            result,
            output_root=output,
            dry_run=not args.publish_local,
            override_guardrails=args.override_guardrails,
        )
        _write_report(args.report, publication.report, output)
        print(f"records read: {result.records_read}", file=sys.stderr)
        print(f"records accepted: {result.records_accepted}", file=sys.stderr)
        print(f"records rejected: {result.records_rejected}", file=sys.stderr)
        print(f"duplicates removed: {result.duplicates_removed}", file=sys.stderr)
        print(f"validation result: {publication.report['validation_result']}", file=sys.stderr)
        print(f"output version: {publication.version}", file=sys.stderr)
        print(f"duration: {publication.report['duration_ms']} ms", file=sys.stderr)
        if publication.published:
            print(f"local snapshot activated: {publication.version}")
        else:
            print(json.dumps(publication.report, ensure_ascii=False, sort_keys=True))
        return 0
    except ValidationFailure as error:
        print(str(error), file=sys.stderr)
        return 1
    except (OSError, ValueError, subprocess.SubprocessError):
        print("export failed during a local read or filesystem operation", file=sys.stderr)
        return 1


def _generated_at(value: str | None) -> datetime:
    if value is None:
        return datetime.now(UTC).replace(microsecond=0)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValidationFailure("generated_at: invalid RFC 3339 value") from error
    if parsed.tzinfo is None:
        raise ValidationFailure("generated_at: timezone is required")
    return parsed.astimezone(UTC).replace(microsecond=0)


def _read_bitrix(args: argparse.Namespace, generated_at: datetime) -> list[dict[str, Any]]:
    command = [
        "php",
        str(ROOT / "exporter" / "bitrix_read.php"),
        f"--site-root={args.site_root}",
        f"--now={int(generated_at.timestamp())}",
    ]
    if args.limit is not None:
        if not 1 <= args.limit <= 100000:
            raise ValidationFailure("limit: must be between 1 and 100000")
        command.append(f"--limit={args.limit}")
    if args.source:
        command.append(f"--source={args.source}")
    if args.protocol:
        command.append(f"--protocol={args.protocol}")
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired as error:
        raise ValidationFailure("Bitrix reader timed out") from error
    if completed.returncode != 0:
        raise ValidationFailure(
            f"Bitrix reader failed with exit status {completed.returncode}",
        )
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise ValidationFailure("Bitrix reader returned invalid JSON") from error
    if not isinstance(payload, list) or not all(isinstance(row, dict) for row in payload):
        raise ValidationFailure("Bitrix reader returned an invalid record list")
    return payload


def _output_path(requested: Path | None, configured: Path) -> Path:
    if requested is None:
        return configured
    if requested.is_absolute():
        return requested
    return ROOT / requested


def _write_report(path: Path | None, report: dict[str, Any], output_root: Path) -> None:
    if path is None:
        return
    requested = path if path.is_absolute() else ROOT / path
    resolved_root = output_root.resolve(strict=False)
    resolved_path = requested.resolve(strict=False)
    try:
        resolved_path.relative_to(resolved_root)
    except ValueError as error:
        raise ValidationFailure("report path: outside configured output root") from error
    if requested.exists() and requested.is_symlink():
        raise ValidationFailure("report path: symlink rejected")
    requested.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{requested.name}.",
        dir=requested.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(report, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, requested)
    finally:
        if temporary.exists():
            temporary.unlink()
