"""Repository secret scanning with precise, reviewable line allowlisting."""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
import zipfile
from dataclasses import dataclass
from pathlib import Path

TEXT_EXTENSIONS = {
    ".bru",
    ".conf",
    ".csv",
    ".html",
    ".json",
    ".md",
    ".mjs",
    ".ovpn",
    ".php",
    ".py",
    ".sh",
    ".svg",
    ".toml",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}
IMAGE_EXTENSIONS = {".gif", ".jpeg", ".jpg", ".png", ".webp"}
SECRET_PATTERNS = {
    "private_key_pem": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", re.I),
    "openvpn_inline_key": re.compile(r"<\s*key\s*>", re.I),
    "openvpn_inline_cert": re.compile(r"<\s*cert\s*>", re.I),
    "wireguard_private_key": re.compile(r"\bPrivateKey\s*=", re.I),
    "wireguard_preshared_key": re.compile(r"\bPresharedKey\s*=", re.I),
    "openvpn_auth": re.compile(r"^\s*auth-user-pass(?:\s|$)", re.I),
    "client_secret": re.compile(r"\bclient[_-]?secret\s*[:=]", re.I),
    "access_token": re.compile(r"\baccess[_-]?token\s*[:=]", re.I),
    "password": re.compile(r"\b(?:password|passwd)\s*[:=]", re.I),
    "provisioning_token": re.compile(r"\bprovisioning[_-]?token\s*[:=]", re.I),
}
SENSITIVE_IMAGE_NAME = re.compile(
    r"(?:wireguard|vpn|profile|config|qr).*(?:key|secret|token|credential)|"
    r"(?:key|secret|token|credential).*(?:wireguard|vpn|profile|config|qr)",
    re.I,
)
SENSITIVE_ARTIFACT_REFERENCE = re.compile(
    r"(?:wireguard|vpn|profile|config)[^\s\"']{0,80}"
    r"(?:qr|key|secret|token)[^\s\"']*\.(?:gif|jpe?g|png|svg|webp)|"
    r"(?:qr|key|secret|token)[^\s\"']{0,80}"
    r"(?:wireguard|vpn|profile|config)[^\s\"']*\.(?:gif|jpe?g|png|svg|webp)",
    re.I,
)


@dataclass(frozen=True)
class SecretFinding:
    path: str
    line: int
    rule: str


def scan_repository(
    root: Path,
    *,
    allowlist_path: Path | None = None,
) -> list[SecretFinding]:
    allowlist = _load_allowlist(allowlist_path)
    findings: list[SecretFinding] = []
    for path in sorted(root.rglob("*")):
        if any(part in {".git", ".venv", "__pycache__", ".pytest_cache"} for part in path.parts):
            continue
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        suffix = path.suffix.casefold()
        if suffix == ".zip":
            findings.extend(_scan_zip(path, relative, allowlist))
        elif suffix in TEXT_EXTENSIONS:
            findings.extend(_scan_text(path.read_bytes(), relative, allowlist))
        elif suffix in IMAGE_EXTENSIONS and SENSITIVE_IMAGE_NAME.search(
            unicodedata.normalize("NFKC", path.name),
        ):
            findings.append(SecretFinding(relative, 0, "sensitive_image_name"))
    return findings


def scan_bytes(
    content: bytes,
    path: str = "artifact.txt",
) -> list[SecretFinding]:
    return _scan_text(content, path, {})


def line_fingerprint(line: str) -> str:
    return hashlib.sha256(line.rstrip("\r\n").encode("utf-8")).hexdigest()


def _scan_text(
    content: bytes,
    path: str,
    allowlist: dict[str, set[str]],
) -> list[SecretFinding]:
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError:
        return []
    findings: list[SecretFinding] = []
    permitted = allowlist.get(path, set())
    for line_number, line in enumerate(text.splitlines(), 1):
        fingerprint = line_fingerprint(line)
        if SENSITIVE_ARTIFACT_REFERENCE.search(line) and fingerprint not in permitted:
            findings.append(SecretFinding(path, line_number, "sensitive_artifact_reference"))
        for rule, pattern in SECRET_PATTERNS.items():
            if pattern.search(line) and fingerprint not in permitted:
                findings.append(SecretFinding(path, line_number, rule))
    return findings


def _scan_zip(
    path: Path,
    relative: str,
    allowlist: dict[str, set[str]],
) -> list[SecretFinding]:
    findings: list[SecretFinding] = []
    try:
        archive = zipfile.ZipFile(path)
    except zipfile.BadZipFile:
        return [SecretFinding(relative, 0, "invalid_zip")]
    with archive:
        for info in archive.infolist():
            nested_path = f"{relative}!/{info.filename}"
            if SENSITIVE_IMAGE_NAME.search(unicodedata.normalize("NFKC", info.filename)):
                findings.append(SecretFinding(nested_path, 0, "sensitive_image_name"))
            if info.file_size <= 2 * 1024 * 1024:
                findings.extend(_scan_text(archive.read(info), nested_path, allowlist))
    return findings


def _load_allowlist(path: Path | None) -> dict[str, set[str]]:
    if path is None or not path.exists():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    entries = payload.get("line_sha256", {})
    if not isinstance(entries, dict):
        raise ValueError("invalid secret scan allowlist")
    return {
        str(name): {str(fingerprint) for fingerprint in fingerprints}
        for name, fingerprints in entries.items()
        if isinstance(fingerprints, list)
    }
