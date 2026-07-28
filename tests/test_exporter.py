from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from publicvpnlist.exporter.pipeline import ExportPipeline
from publicvpnlist.exporter.policy import ExportSettings, Guardrails, SourceRegistry
from publicvpnlist.exporter.publisher import ExportLock, SnapshotPublisher
from publicvpnlist.validation import ValidationFailure

ROOT = Path(__file__).resolve().parents[1]
GENERATED_AT = datetime(2026, 7, 28, tzinfo=UTC)
TEST_SECRET = b"synthetic-exporter-secret-with-32-bytes-minimum"


@pytest.fixture()
def server_schema() -> dict:
    return json.loads((ROOT / "schema" / "servers.schema.json").read_text())


@pytest.fixture()
def manifest_schema() -> dict:
    return json.loads((ROOT / "schema" / "manifest.schema.json").read_text())


@pytest.fixture()
def registry() -> SourceRegistry:
    return SourceRegistry.from_path(
        ROOT / "tests" / "fixtures" / "dataset_sources.synthetic.json",
    )


@pytest.fixture()
def settings(tmp_path: Path) -> ExportSettings:
    configured = ExportSettings.from_path(ROOT / "config" / "exporter.json", ROOT)
    return replace(
        configured,
        output_root=tmp_path / "allowed-output",
        lock_timeout_seconds=1,
        guardrails=Guardrails(
            minimum_record_count=1,
            minimum_countries_count=1,
            maximum_drop_percent=30,
            maximum_invalid_percent=100,
        ),
    )


@pytest.fixture()
def pipeline(
    registry: SourceRegistry,
    settings: ExportSettings,
    server_schema: dict,
) -> ExportPipeline:
    return ExportPipeline(
        registry=registry,
        settings=settings,
        hmac_secret=TEST_SECRET,
        server_schema=server_schema,
        allow_documentation_addresses=True,
    )


@pytest.fixture()
def publisher(
    settings: ExportSettings,
    server_schema: dict,
    manifest_schema: dict,
) -> SnapshotPublisher:
    return SnapshotPublisher(
        repository_root=ROOT,
        settings=settings,
        server_schema=server_schema,
        manifest_schema=manifest_schema,
    )


def raw_record(**changes: object) -> dict:
    record = {
        "active": True,
        "host": "vpn.example.invalid",
        "ip": "192.0.2.10",
        "country_code": "us",
        "country_name": "Synthetic United States example",
        "speed_mbps": 100.5,
        "latency_ms": 25.25,
        "sessions": None,
        "uptime_hours": None,
        "clean": True,
        "port": 1194,
        "protocol": "openvpn",
        "transport": "udp",
        "source": "Synthetic Fixture",
        "checked_at": "2026-07-27T23:59:00Z",
        "first_seen_at": "2026-07-01T00:00:00Z",
        "last_success_at": "2026-07-27T23:59:00Z",
        "config_updated_at": None,
        "last_check_ok": True,
        "fail_streak": 0,
        "checker_status": "tunnel_ok",
        "config_available": True,
        "canonical_visible": True,
        "canonical_downloadable": True,
        "technical_quality_score": 80,
        "score_label": "Good",
    }
    record.update(changes)
    return record


def test_approved_source_exports_and_aliases_map_to_one_source(
    pipeline: ExportPipeline,
) -> None:
    result = pipeline.build(
        [raw_record(source="synthetic_fixture")],
        generated_at=GENERATED_AT,
    )
    assert result.records_accepted == 1
    assert result.dataset["records"][0]["source_name"] == "Synthetic fixture"
    assert result.dataset["metadata"]["source_count"] == 1


@pytest.mark.parametrize(
    "source",
    ["Unknown Source", "Synthetic Pending", "Synthetic Rejected"],
)
def test_unknown_pending_and_rejected_sources_are_blocked(
    pipeline: ExportPipeline,
    source: str,
) -> None:
    result = pipeline.build([raw_record(source=source)], generated_at=GENERATED_AT)
    assert result.records_accepted == 0
    assert result.rejection_reasons == {"source_not_approved": 1}


@pytest.mark.parametrize(
    ("source", "reason"),
    [
        ("Synthetic No License", "license_missing"),
        ("Synthetic Disabled", "metadata_export_not_allowed"),
    ],
)
def test_empty_license_and_disabled_metadata_export_are_blocked(
    pipeline: ExportPipeline,
    source: str,
    reason: str,
) -> None:
    result = pipeline.build([raw_record(source=source)], generated_at=GENERATED_AT)
    assert result.rejection_reasons == {reason: 1}


def test_public_id_is_stable_and_measurements_do_not_change_it(
    pipeline: ExportPipeline,
) -> None:
    first = pipeline.build([raw_record(speed_mbps=10)], generated_at=GENERATED_AT)
    second = pipeline.build([raw_record(speed_mbps=999)], generated_at=GENERATED_AT)
    assert first.dataset["records"][0]["id"] == second.dataset["records"][0]["id"]


def test_ipv4_ipv6_and_hostname_normalization(pipeline: ExportPipeline) -> None:
    ipv4 = pipeline.build(
        [raw_record(host="", ip="192.0.2.10")],
        generated_at=GENERATED_AT,
    ).dataset["records"][0]
    ipv6 = pipeline.build(
        [raw_record(host="", ip="2001:0db8:0:0:0:0:0:1")],
        generated_at=GENERATED_AT,
    ).dataset["records"][0]
    hostname = pipeline.build(
        [raw_record(host="VPN.Example.Invalid.", ip="")],
        generated_at=GENERATED_AT,
    ).dataset["records"][0]
    assert ipv4["ip"] == "192.0.2.10"
    assert ipv6["ip"] == "2001:db8::1"
    assert hostname["hostname"] == "vpn.example.invalid"


@pytest.mark.parametrize("port", [0, 65536, "bad"])
def test_invalid_port_is_rejected(pipeline: ExportPipeline, port: object) -> None:
    result = pipeline.build([raw_record(port=port)], generated_at=GENERATED_AT)
    assert result.rejection_reasons == {"invalid_endpoint": 1}


@pytest.mark.parametrize(
    ("host", "ip"),
    [
        ("999.1.1.1", ""),
        ("", "10.0.0.1"),
        ("", "127.0.0.1"),
    ],
)
def test_invalid_or_non_public_endpoint_is_rejected(
    pipeline: ExportPipeline,
    host: str,
    ip: str,
) -> None:
    result = pipeline.build([raw_record(host=host, ip=ip)], generated_at=GENERATED_AT)
    assert result.rejection_reasons == {"invalid_endpoint": 1}


def test_tcp_transport_is_normalized(pipeline: ExportPipeline) -> None:
    result = pipeline.build(
        [raw_record(transport="tcp-client")],
        generated_at=GENERATED_AT,
    )
    assert result.dataset["records"][0]["transport"] == "tcp"


def test_stale_and_failed_servers_are_rejected(pipeline: ExportPipeline) -> None:
    stale = pipeline.build(
        [raw_record(checked_at="2026-07-27T22:00:00Z")],
        generated_at=GENERATED_AT,
    )
    failed = pipeline.build(
        [raw_record(last_check_ok=False)],
        generated_at=GENERATED_AT,
    )
    unknown = pipeline.build(
        [raw_record(checker_status="unknown")],
        generated_at=GENERATED_AT,
    )
    assert stale.rejection_reasons == {"stale": 1}
    assert failed.rejection_reasons == {"failed_check": 1}
    assert unknown.rejection_reasons == {"failed_check": 1}


def test_duplicate_is_removed_deterministically(pipeline: ExportPipeline) -> None:
    older = raw_record(
        checked_at="2026-07-27T23:58:00Z",
        last_success_at="2026-07-27T23:58:00Z",
        speed_mbps=10,
    )
    newer = raw_record(checked_at="2026-07-27T23:59:00Z", speed_mbps=20)
    forward = pipeline.build([older, newer], generated_at=GENERATED_AT)
    reverse = pipeline.build([newer, older], generated_at=GENERATED_AT)
    assert forward.duplicates_removed == 1
    assert forward.dataset["records"] == reverse.dataset["records"]
    assert forward.dataset["records"][0]["speed_mbps"] == 20


def test_internal_fields_and_profile_content_never_reach_output(
    pipeline: ExportPipeline,
) -> None:
    raw = raw_record(
        bitrix_id=123,
        ovpn_path="/internal/path/profile.ovpn",
        ovpn_content="client\nremote 192.0.2.10 1194\n",
        checker_raw_result={"internal": True},
    )
    result = pipeline.build([raw], generated_at=GENERATED_AT)
    serialized = json.dumps(result.dataset, sort_keys=True)
    assert "bitrix_id" not in serialized
    assert "ovpn_path" not in serialized
    assert "ovpn_content" not in serialized
    assert "checker_raw_result" not in serialized
    assert "/internal/path" not in serialized


def test_csv_formula_injection_is_rejected(pipeline: ExportPipeline) -> None:
    result = pipeline.build(
        [raw_record(country_name="=CMD()")],
        generated_at=GENERATED_AT,
    )
    assert result.rejection_reasons == {"schema_error": 1}


def test_bundle_round_trips_manifest_sizes_and_checksums(
    pipeline: ExportPipeline,
    publisher: SnapshotPublisher,
    tmp_path: Path,
) -> None:
    result = pipeline.build([raw_record()], generated_at=GENERATED_AT)
    bundle = tmp_path / "bundle"
    publisher.build_bundle(bundle, result, started_at=0)
    dataset = publisher.validate_bundle(bundle)
    assert dataset == result.dataset
    manifest = json.loads((bundle / "manifest.json").read_text())
    for item in manifest["formats"]:
        path = bundle / item["filename"]
        assert item["record_count"] == 1
        assert item["size_bytes"] == path.stat().st_size
        assert item["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert dataset["metadata"]["record_count"] == 1
    assert dataset["metadata"]["countries_count"] == 1


@pytest.mark.parametrize(
    "parts",
    [
        ["-----BEGIN ", "PRIVATE KEY-----"],
        ["Private", "Key = synthetic"],
        ["Preshared", "Key = synthetic"],
        ["provisioning_", "token=synthetic"],
    ],
)
def test_bundle_secret_scan_detects_credentials(
    pipeline: ExportPipeline,
    publisher: SnapshotPublisher,
    tmp_path: Path,
    parts: list[str],
) -> None:
    result = pipeline.build([raw_record()], generated_at=GENERATED_AT)
    result.dataset["records"][0]["country_name"] = "".join(parts)
    with pytest.raises(ValidationFailure, match="secret scanner|dangerous cell"):
        publisher.build_bundle(tmp_path / "secret-bundle", result, started_at=0)


def test_parallel_export_lock_is_blocked(settings: ExportSettings, tmp_path: Path) -> None:
    root = tmp_path / "lock-root"
    root.mkdir()
    with (
        ExportLock(root, settings.lock_timeout_seconds),
        pytest.raises(ValidationFailure, match="active lock"),
        ExportLock(root, settings.lock_timeout_seconds),
    ):
        pass


def test_staging_failure_keeps_previous_current_snapshot(
    pipeline: ExportPipeline,
    publisher: SnapshotPublisher,
    settings: ExportSettings,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = publisher.prepare_output_root(settings.output_root)
    first = pipeline.build([raw_record()], generated_at=GENERATED_AT)
    published = publisher.run(
        first,
        output_root=root,
        dry_run=False,
        override_guardrails=False,
    )
    current_before = (root / "current").resolve()
    second = pipeline.build(
        [raw_record(speed_mbps=101)],
        generated_at=GENERATED_AT + timedelta(minutes=1),
    )

    def fail_bundle(*args: object, **kwargs: object) -> dict:
        raise ValidationFailure("synthetic staging failure")

    monkeypatch.setattr(publisher, "build_bundle", fail_bundle)
    with pytest.raises(ValidationFailure, match="synthetic staging failure"):
        publisher.run(
            second,
            output_root=root,
            dry_run=False,
            override_guardrails=False,
        )
    assert published.published
    assert (root / "current").resolve() == current_before


def test_record_drop_activates_guardrail(
    pipeline: ExportPipeline,
    publisher: SnapshotPublisher,
    settings: ExportSettings,
) -> None:
    root = publisher.prepare_output_root(settings.output_root)
    two = pipeline.build(
        [raw_record(), raw_record(host="", ip="198.51.100.20", port=443)],
        generated_at=GENERATED_AT,
    )
    publisher.run(two, output_root=root, dry_run=False, override_guardrails=False)
    one = pipeline.build(
        [raw_record(checked_at="2026-07-28T00:01:00Z")],
        generated_at=GENERATED_AT + timedelta(minutes=2),
    )
    with pytest.raises(ValidationFailure, match="maximum_drop_percent"):
        publisher.run(one, output_root=root, dry_run=False, override_guardrails=False)


def test_identical_input_creates_deterministic_snapshot_files(
    pipeline: ExportPipeline,
    publisher: SnapshotPublisher,
    tmp_path: Path,
) -> None:
    first = pipeline.build([raw_record()], generated_at=GENERATED_AT)
    second = pipeline.build([raw_record()], generated_at=GENERATED_AT)
    first_dir = tmp_path / "first"
    second_dir = tmp_path / "second"
    publisher.build_bundle(first_dir, first, started_at=0)
    publisher.build_bundle(second_dir, second, started_at=0)
    for name in ("servers.json", "servers.csv", "servers.txt", "servers.xml", "manifest.json"):
        assert (first_dir / name).read_bytes() == (second_dir / name).read_bytes()


def test_hmac_secret_is_not_exposed_in_errors(
    registry: SourceRegistry,
    settings: ExportSettings,
    server_schema: dict,
) -> None:
    secret = b"a-unique-synthetic-secret-of-at-least-32-bytes"
    pipeline = ExportPipeline(
        registry=registry,
        settings=settings,
        hmac_secret=secret,
        server_schema=server_schema,
        allow_documentation_addresses=True,
    )
    result = pipeline.build([raw_record(port=0)], generated_at=GENERATED_AT)
    assert secret.decode() not in json.dumps(result.rejection_reasons)


def test_output_path_traversal_and_symlink_are_blocked(
    publisher: SnapshotPublisher,
    settings: ExportSettings,
    tmp_path: Path,
) -> None:
    with pytest.raises(ValidationFailure, match="outside configured"):
        publisher.prepare_output_root(tmp_path / "outside")
    settings.output_root.mkdir()
    target = settings.output_root / "linked"
    target.symlink_to(tmp_path / "outside")
    with pytest.raises(ValidationFailure, match="symlink"):
        publisher.prepare_output_root(target)


def test_empty_dataset_never_publishes(
    pipeline: ExportPipeline,
    publisher: SnapshotPublisher,
    settings: ExportSettings,
) -> None:
    empty = pipeline.build(
        [raw_record(source="Unknown Source")],
        generated_at=GENERATED_AT,
    )
    dry = publisher.run(
        empty,
        output_root=settings.output_root,
        dry_run=True,
        override_guardrails=False,
    )
    assert not dry.published
    assert "minimum_record_count" in dry.guardrail_violations
    with pytest.raises(ValidationFailure):
        publisher.run(
            empty,
            output_root=settings.output_root,
            dry_run=False,
            override_guardrails=True,
        )


def test_hmac_secret_is_required(
    registry: SourceRegistry,
    settings: ExportSettings,
    server_schema: dict,
) -> None:
    with pytest.raises(ValidationFailure, match="at least 32 bytes"):
        ExportPipeline(
            registry=registry,
            settings=settings,
            hmac_secret=b"",
            server_schema=server_schema,
        )


def test_production_registry_has_no_approved_real_source() -> None:
    payload = json.loads((ROOT / "config" / "dataset_sources.json").read_text())
    assert not [
        source
        for source in payload["sources"]
        if source["review_status"] == "approved" and source["metadata_export_allowed"] is True
    ]
