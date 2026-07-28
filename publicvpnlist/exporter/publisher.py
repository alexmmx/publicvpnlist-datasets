"""Validated bundle creation and atomic local snapshot activation."""

from __future__ import annotations

import fcntl
import hashlib
import os
import re
import secrets
import time
from contextlib import AbstractContextManager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from publicvpnlist.security import scan_bytes
from publicvpnlist.validation import (
    ValidationFailure,
    load_json,
    validate_csv,
    validate_dataset_semantics,
    validate_manifest,
    validate_schema,
)

from .formats import (
    csv_bytes,
    json_bytes,
    parse_csv,
    parse_txt,
    parse_xml,
    txt_bytes,
    xml_bytes,
)
from .pipeline import SCORE_NOTICE, PipelineResult
from .policy import ExportSettings

VERSION_RE = re.compile(r"^\d{8}T\d{6}Z-[a-f0-9]{12}$")
CONTENT_TYPES = {
    "json": "application/json",
    "csv": "text/csv",
    "txt": "text/plain",
    "xml": "application/xml",
}
FORMAT_FILES = {
    "json": "servers.json",
    "csv": "servers.csv",
    "txt": "servers.txt",
    "xml": "servers.xml",
}
EXTRA_FILES = {"manifest.json", "SHA256SUMS", "export-report.json"}


@dataclass(frozen=True)
class PublicationResult:
    version: str
    bundle_path: Path | None
    published: bool
    guardrail_violations: tuple[str, ...]
    report: dict[str, Any]


class ExportLock(AbstractContextManager["ExportLock"]):
    """Advisory lock using flock; PID metadata is diagnostic only."""

    def __init__(self, root: Path, timeout_seconds: int) -> None:
        self.path = root / ".export.lock"
        self.timeout_seconds = timeout_seconds
        self.handle: Any = None

    def __enter__(self) -> ExportLock:
        flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(self.path, flags, 0o600)
        self.handle = os.fdopen(descriptor, "r+", encoding="ascii")
        deadline = time.monotonic() + self.timeout_seconds
        while True:
            try:
                fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError as error:
                if time.monotonic() >= deadline:
                    age = max(0, int(time.time() - self.path.stat().st_mtime))
                    self.handle.close()
                    self.handle = None
                    raise ValidationFailure(
                        f"export lock: active lock exceeded timeout (age {age}s)",
                    ) from error
                time.sleep(0.05)
        self.handle.seek(0)
        self.handle.truncate()
        self.handle.write(f"pid={os.getpid()}\nstarted={int(time.time())}\n")
        self.handle.flush()
        os.fsync(self.handle.fileno())
        return self

    def __exit__(self, *args: object) -> None:
        if self.handle is not None:
            fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
            self.handle.close()
            self.handle = None


class SnapshotPublisher:
    def __init__(
        self,
        *,
        repository_root: Path,
        settings: ExportSettings,
        server_schema: dict[str, Any],
        manifest_schema: dict[str, Any],
    ) -> None:
        self.repository_root = repository_root.resolve()
        self.settings = settings
        self.server_schema = server_schema
        self.manifest_schema = manifest_schema
        self.fields = tuple(server_schema["$defs"]["OpenVpnServer"]["properties"])

    def prepare_output_root(self, requested: Path | None = None) -> Path:
        configured = self.settings.output_root.absolute()
        target = (requested or configured).absolute()
        if ".." in target.parts:
            raise ValidationFailure("output path: traversal is forbidden")
        forbidden = {
            Path("/"),
            Path.home().absolute(),
            self.repository_root,
        }
        if target in forbidden:
            raise ValidationFailure("output path: unsafe root target")
        self._reject_symlink_components(target)
        configured_resolved = configured.resolve(strict=False)
        target_resolved = target.resolve(strict=False)
        try:
            target_resolved.relative_to(configured_resolved)
        except ValueError as error:
            raise ValidationFailure("output path: outside configured output root") from error
        target.mkdir(parents=True, exist_ok=True, mode=0o700)
        if target.is_symlink() or not target.is_dir():
            raise ValidationFailure("output path: symlink or non-directory target")
        os.chmod(target, 0o700)
        return target

    def build_bundle(
        self,
        directory: Path,
        result: PipelineResult,
        *,
        started_at: float,
        guardrail_violations: tuple[str, ...] = (),
        override_guardrails: bool = False,
    ) -> dict[str, Any]:
        directory.mkdir(mode=0o700)
        dataset = result.dataset
        records = dataset["records"]
        if not records:
            raise ValidationFailure("publication: empty dataset is forbidden")
        contents = {
            "json": json_bytes(dataset),
            "csv": csv_bytes(records, self.fields),
            "txt": txt_bytes(records, self.fields),
            "xml": xml_bytes(dataset, self.fields),
        }
        for format_name in self.settings.supported_formats:
            self._atomic_write(directory / FORMAT_FILES[format_name], contents[format_name])

        formats: list[dict[str, Any]] = []
        for format_name in self.settings.supported_formats:
            filename = FORMAT_FILES[format_name]
            path = directory / filename
            formats.append(
                {
                    "format": format_name,
                    "path": filename,
                    "filename": filename,
                    "content_type": CONTENT_TYPES[format_name],
                    "bytes": path.stat().st_size,
                    "size_bytes": path.stat().st_size,
                    "sha256": _sha256(path),
                    "record_count": len(records),
                },
            )
        metadata = dataset["metadata"]
        manifest = {
            "schema_version": metadata["schema_version"],
            "dataset_version": metadata["dataset_version"],
            "snapshot_id": metadata["snapshot_id"],
            "generated_at": metadata["generated_at"],
            "expires_at": metadata["expires_at"],
            "record_count": metadata["record_count"],
            "score_notice": SCORE_NOTICE,
            "formats": formats,
            "license_review": (
                "Every included source passed the approved metadata-export registry gate. "
                "No VPN profiles or client credentials are included."
            ),
        }
        self._atomic_write(directory / "manifest.json", json_bytes(manifest))
        report = {
            "schema_version": "1.0",
            "status": "validated",
            "output_version": metadata["dataset_version"],
            "records_read": result.records_read,
            "records_accepted": result.records_accepted,
            "records_rejected": result.records_rejected,
            "duplicates_removed": result.duplicates_removed,
            "rejection_reasons": result.rejection_reasons,
            "formats_generated": list(self.settings.supported_formats),
            "guardrail_violations": list(guardrail_violations),
            "guardrail_override": override_guardrails,
            "validation_result": "passed",
            "duration_ms": max(0, round((time.monotonic() - started_at) * 1000)),
        }
        self._atomic_write(directory / "export-report.json", json_bytes(report))
        checksum_names = [
            *(FORMAT_FILES[name] for name in self.settings.supported_formats),
            "manifest.json",
            "export-report.json",
        ]
        checksum_lines = [f"{_sha256(directory / name)}  {name}" for name in checksum_names]
        self._atomic_write(
            directory / "SHA256SUMS",
            ("\n".join(checksum_lines) + "\n").encode(),
        )
        self.validate_bundle(directory)
        return report

    def validate_bundle(self, directory: Path) -> dict[str, Any]:
        if directory.is_symlink() or not directory.is_dir():
            raise ValidationFailure("bundle: expected a real directory")
        expected = {
            *(FORMAT_FILES[name] for name in self.settings.supported_formats),
            *EXTRA_FILES,
        }
        actual = {path.name for path in directory.iterdir() if path.name != ".export.lock"}
        if actual != expected:
            raise ValidationFailure("bundle: missing or unexpected files")
        for path in directory.iterdir():
            if path.is_symlink() or not path.is_file():
                raise ValidationFailure("bundle: symlinks and special files are forbidden")
            findings = scan_bytes(path.read_bytes(), path.name)
            if findings:
                raise ValidationFailure(
                    f"bundle: secret scanner rejected {path.name}",
                )
        dataset = load_json(directory / FORMAT_FILES["json"])
        validate_schema(dataset, self.server_schema, "bundle dataset")
        validate_dataset_semantics(dataset)
        manifest = load_json(directory / "manifest.json")
        validate_schema(manifest, self.manifest_schema, "bundle manifest")
        validate_manifest(
            manifest,
            directory,
            set(self.settings.supported_formats),
        )
        records = dataset["records"]
        validate_csv(directory / FORMAT_FILES["csv"], len(records))
        parsed = {
            "csv": parse_csv(
                (directory / FORMAT_FILES["csv"]).read_bytes(),
                self.fields,
            ),
            "txt": parse_txt(
                (directory / FORMAT_FILES["txt"]).read_bytes(),
                self.fields,
            ),
            "xml": parse_xml(
                (directory / FORMAT_FILES["xml"]).read_bytes(),
                self.fields,
            ),
        }
        for format_name, parsed_records in parsed.items():
            if parsed_records != records:
                raise ValidationFailure(f"bundle: {format_name} round-trip mismatch")
        for item in manifest["formats"]:
            if (
                item["filename"] != item["path"]
                or item["size_bytes"] != item["bytes"]
                or item["record_count"] != len(records)
            ):
                raise ValidationFailure("bundle manifest: redundant fields mismatch")
        expected_checksums: dict[str, str] = {}
        for line in (directory / "SHA256SUMS").read_text(encoding="ascii").splitlines():
            digest, separator, filename = line.partition("  ")
            if not separator or filename in expected_checksums:
                raise ValidationFailure("bundle checksums: malformed or duplicate line")
            expected_checksums[filename] = digest
        checksum_files = expected - {"SHA256SUMS"}
        if set(expected_checksums) != checksum_files:
            raise ValidationFailure("bundle checksums: file set mismatch")
        for filename, digest in expected_checksums.items():
            if digest != _sha256(directory / filename):
                raise ValidationFailure("bundle checksums: digest mismatch")
        return dataset

    def guardrail_violations(
        self,
        result: PipelineResult,
        output_root: Path,
    ) -> tuple[str, ...]:
        records = result.dataset["records"]
        countries = {record["country_code"] for record in records}
        rules = self.settings.guardrails
        violations: list[str] = []
        if len(records) < rules.minimum_record_count:
            violations.append("minimum_record_count")
        if len(countries) < rules.minimum_countries_count:
            violations.append("minimum_countries_count")
        invalid_percent = (
            result.records_rejected / result.records_read * 100 if result.records_read else 100
        )
        if invalid_percent > rules.maximum_invalid_percent:
            violations.append("maximum_invalid_percent")
        previous_count = self._current_record_count(output_root)
        if previous_count and len(records) < previous_count:
            drop = (previous_count - len(records)) / previous_count * 100
            if drop > rules.maximum_drop_percent:
                violations.append("maximum_drop_percent")
        return tuple(violations)

    def run(
        self,
        result: PipelineResult,
        *,
        output_root: Path,
        dry_run: bool,
        override_guardrails: bool,
    ) -> PublicationResult:
        started_at = time.monotonic()
        root = self.prepare_output_root(output_root)
        with ExportLock(root, self.settings.lock_timeout_seconds):
            violations = self.guardrail_violations(result, root)
            if violations and not dry_run and not override_guardrails:
                raise ValidationFailure(
                    "guardrails: snapshot rejected (" + ", ".join(violations) + ")",
                )
            if not result.dataset["records"]:
                report = self._empty_report(result, violations, started_at)
                if dry_run:
                    return PublicationResult(
                        version=result.dataset["metadata"]["dataset_version"],
                        bundle_path=None,
                        published=False,
                        guardrail_violations=violations,
                        report=report,
                    )
                raise ValidationFailure("publication: empty dataset is forbidden")
            version = result.dataset["metadata"]["dataset_version"]
            if not VERSION_RE.fullmatch(version):
                raise ValidationFailure("publication: invalid version")
            staging = root / f".staging-{version}-{secrets.token_hex(6)}"
            self._assert_direct_child(staging, root)
            try:
                report = self.build_bundle(
                    staging,
                    result,
                    started_at=started_at,
                    guardrail_violations=violations,
                    override_guardrails=override_guardrails,
                )
                if dry_run:
                    return PublicationResult(
                        version=version,
                        bundle_path=None,
                        published=False,
                        guardrail_violations=violations,
                        report=report,
                    )
                versions = root / "versions"
                versions.mkdir(mode=0o700, exist_ok=True)
                if versions.is_symlink():
                    raise ValidationFailure("publication: versions path is a symlink")
                destination = versions / version
                if destination.exists() or destination.is_symlink():
                    raise ValidationFailure("publication: version already exists")
                os.replace(staging, destination)
                staging = destination
                self._activate(root, version)
                self._prune(root, version)
                return PublicationResult(
                    version=version,
                    bundle_path=destination,
                    published=True,
                    guardrail_violations=violations,
                    report=report,
                )
            finally:
                if staging.exists() and staging.name.startswith(".staging-"):
                    self._remove_tree(staging, root)

    def _activate(self, root: Path, version: str) -> None:
        current = root / "current"
        if current.exists() and not current.is_symlink():
            raise ValidationFailure("publication: current marker is not a symlink")
        temporary = root / f".current-{secrets.token_hex(6)}"
        os.symlink(f"versions/{version}", temporary)
        os.replace(temporary, current)

    def _prune(self, root: Path, current_version: str) -> None:
        versions_root = root / "versions"
        versions = sorted(
            (
                path
                for path in versions_root.iterdir()
                if path.is_dir() and not path.is_symlink() and VERSION_RE.fullmatch(path.name)
            ),
            key=lambda path: path.name,
            reverse=True,
        )
        keep_count = max(2, self.settings.retention_versions)
        keep = {path.name for path in versions[:keep_count]}
        keep.add(current_version)
        for path in versions:
            if path.name not in keep:
                self._remove_tree(path, versions_root)

    def _current_record_count(self, root: Path) -> int | None:
        current = root / "current"
        if not current.exists() and not current.is_symlink():
            return None
        if not current.is_symlink():
            raise ValidationFailure("guardrails: unexpected current marker")
        try:
            resolved = current.resolve(strict=True)
        except OSError as error:
            raise ValidationFailure("guardrails: broken current marker") from error
        versions_root = (root / "versions").resolve()
        try:
            resolved.relative_to(versions_root)
        except ValueError as error:
            raise ValidationFailure("guardrails: current marker escapes versions") from error
        dataset = self.validate_bundle(resolved)
        count = dataset.get("metadata", {}).get("record_count")
        return count if isinstance(count, int) and count >= 0 else None

    def _atomic_write(self, path: Path, content: bytes) -> None:
        if path.parent.is_symlink():
            raise ValidationFailure("atomic write: parent symlink rejected")
        temporary = path.parent / f".{path.name}.{secrets.token_hex(6)}.tmp"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(temporary, flags, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        finally:
            if temporary.exists():
                temporary.unlink()

    def _reject_symlink_components(self, target: Path) -> None:
        current = Path(target.anchor)
        for part in target.parts[1:]:
            current /= part
            if current.is_symlink():
                raise ValidationFailure("output path: symlink component rejected")

    def _assert_direct_child(self, path: Path, parent: Path) -> None:
        if path.parent != parent or path == parent or path.is_symlink():
            raise ValidationFailure("filesystem operation: unsafe path")

    def _remove_tree(self, path: Path, allowed_root: Path) -> None:
        allowed = allowed_root.resolve()
        candidate = path.absolute()
        try:
            candidate.relative_to(allowed)
        except ValueError as error:
            raise ValidationFailure("cleanup: path escapes allowed root") from error
        if candidate == allowed or candidate in {Path("/"), Path.home(), self.repository_root}:
            raise ValidationFailure("cleanup: unsafe target")
        if candidate.is_symlink():
            candidate.unlink()
            return
        if not candidate.exists():
            return
        for child in candidate.iterdir():
            if child.is_symlink() or child.is_file():
                child.unlink()
            elif child.is_dir():
                self._remove_tree(child, allowed)
            else:
                raise ValidationFailure("cleanup: special file rejected")
        candidate.rmdir()

    def _empty_report(
        self,
        result: PipelineResult,
        violations: tuple[str, ...],
        started_at: float,
    ) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "status": "dry-run-blocked",
            "output_version": result.dataset["metadata"]["dataset_version"],
            "records_read": result.records_read,
            "records_accepted": result.records_accepted,
            "records_rejected": result.records_rejected,
            "duplicates_removed": result.duplicates_removed,
            "rejection_reasons": result.rejection_reasons,
            "formats_generated": [],
            "guardrail_violations": list(violations),
            "guardrail_override": False,
            "validation_result": "not-run-empty-dataset",
            "duration_ms": max(0, round((time.monotonic() - started_at) * 1000)),
        }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
