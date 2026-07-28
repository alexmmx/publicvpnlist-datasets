from __future__ import annotations

import hashlib
import json
import struct
import warnings
import zipfile
from pathlib import Path

import pytest

from publicvpnlist.security import line_fingerprint, scan_bytes, scan_repository
from publicvpnlist.validation import (
    ValidationFailure,
    ZipPolicy,
    csv_cell_is_dangerous,
    validate_manifest,
    validate_openvpn_zip,
)


@pytest.mark.parametrize(
    "value",
    [
        "=CMD()",
        " =CMD()",
        "\u00a0=CMD()",
        "\u2009=CMD()",
        "\u200b=CMD()",
        "\ufeff=CMD()",
        "\t=CMD()",
        "\r=CMD()",
        "\n=CMD()",
        "+SUM(1,1)",
        "@IMPORTXML(...)",
    ],
)
def test_csv_formula_injection_bypasses_are_rejected(value: str) -> None:
    assert csv_cell_is_dangerous(value)


def test_plain_csv_values_are_allowed() -> None:
    assert not csv_cell_is_dangerous("Synthetic server")
    assert not csv_cell_is_dangerous("192.0.2.10")


def _write_zip(path: Path, entries: list[tuple[str, bytes]]) -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, content in entries:
                archive.writestr(name, content)


def _safe_profile() -> bytes:
    return b"client\nproto udp\nremote 192.0.2.20 1194\n"


def test_zip_slip_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "slip.zip"
    _write_zip(path, [("../profile.ovpn", _safe_profile())])
    with pytest.raises(ValidationFailure, match="unsafe path"):
        validate_openvpn_zip(path, allow_documentation_addresses=True)


def test_zip_compression_bomb_ratio_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "ratio.zip"
    _write_zip(path, [("profile.ovpn", b"A" * 500_000)])
    with pytest.raises(ValidationFailure, match="compression ratio"):
        validate_openvpn_zip(
            path,
            policy=ZipPolicy(max_expanded_bytes=1_000_000),
            allow_documentation_addresses=True,
        )


def test_encrypted_zip_flag_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "encrypted.zip"
    _write_zip(path, [("profile.ovpn", _safe_profile())])
    data = bytearray(path.read_bytes())
    local = data.find(b"PK\x03\x04")
    central = data.find(b"PK\x01\x02")
    local_flags = struct.unpack_from("<H", data, local + 6)[0] | 1
    central_flags = struct.unpack_from("<H", data, central + 8)[0] | 1
    struct.pack_into("<H", data, local + 6, local_flags)
    struct.pack_into("<H", data, central + 8, central_flags)
    path.write_bytes(data)
    with pytest.raises(ValidationFailure, match="encrypted"):
        validate_openvpn_zip(path, allow_documentation_addresses=True)


def test_duplicate_zip_names_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "duplicate.zip"
    _write_zip(
        path,
        [
            ("Profile.ovpn", _safe_profile()),
            ("profile.ovpn", _safe_profile()),
        ],
    )
    with pytest.raises(ValidationFailure, match="duplicate"):
        validate_openvpn_zip(
            path,
            policy=ZipPolicy(max_files=2),
            allow_documentation_addresses=True,
        )


def test_openvpn_private_key_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "key.zip"
    dangerous = _safe_profile() + b"<" + b"key>\nnot-a-real-key\n</" + b"key>\n"
    _write_zip(path, [("profile.ovpn", dangerous)])
    with pytest.raises(ValidationFailure, match="private key"):
        validate_openvpn_zip(path, allow_documentation_addresses=True)


@pytest.mark.parametrize(
    ("parts", "rule"),
    [
        (["Private", "Key = synthetic"], "wireguard_private_key"),
        (["Preshared", "Key = synthetic"], "wireguard_preshared_key"),
        (["provisioning_", "token=synthetic"], "provisioning_token"),
        (["-----BEGIN ", "PRIVATE KEY-----"], "private_key_pem"),
    ],
)
def test_secret_scanner_rejects_credentials(parts: list[str], rule: str) -> None:
    findings = scan_bytes("".join(parts).encode())
    assert any(finding.rule == rule for finding in findings)


def test_secret_scanner_rejects_profile_qr_manifest_reference() -> None:
    reference = b'{"path":"wireguard-profile-' + b'qr.png"}'
    findings = scan_bytes(reference, "manifest.json")
    assert any(finding.rule == "sensitive_artifact_reference" for finding in findings)


def test_secret_allowlist_is_exact_line_fingerprint(tmp_path: Path) -> None:
    reviewed = "".join(["Private", "Key = documentation-placeholder"])
    (tmp_path / "guide.txt").write_text(reviewed + "\n", encoding="utf-8")
    allowlist = tmp_path / "allowlist.json"
    allowlist.write_text(
        json.dumps({"line_sha256": {"guide.txt": [line_fingerprint(reviewed)]}}),
        encoding="utf-8",
    )
    assert scan_repository(tmp_path, allowlist_path=allowlist) == []
    (tmp_path / "guide.txt").write_text(reviewed + "-changed\n", encoding="utf-8")
    assert scan_repository(tmp_path, allowlist_path=allowlist)


def test_manifest_checksum_and_size(tmp_path: Path) -> None:
    target = tmp_path / "servers.json"
    target.write_text('{"synthetic":true}\n', encoding="utf-8")
    manifest = {
        "formats": [
            {
                "format": "json",
                "path": "servers.json",
                "bytes": target.stat().st_size,
                "sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
            }
        ]
    }
    validate_manifest(manifest, tmp_path, {"json"})
    manifest["formats"][0]["sha256"] = "0" * 64
    with pytest.raises(ValidationFailure, match="checksum mismatch"):
        validate_manifest(manifest, tmp_path, {"json"})


def test_manifest_duplicate_format_is_rejected(tmp_path: Path) -> None:
    target = tmp_path / "servers.json"
    target.write_text("{}\n", encoding="utf-8")
    item = {
        "format": "json",
        "path": "servers.json",
        "bytes": target.stat().st_size,
        "sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
    }
    with pytest.raises(ValidationFailure, match="duplicate"):
        validate_manifest({"formats": [item, dict(item)]}, tmp_path, {"json"})


def test_checked_in_synthetic_manifest_is_consistent() -> None:
    root = Path(__file__).resolve().parents[1]
    manifest = json.loads(
        (root / "fixtures" / "manifest.synthetic.json").read_text(encoding="utf-8"),
    )
    validate_manifest(manifest, root / "fixtures", {"json", "csv", "txt", "xml"})
