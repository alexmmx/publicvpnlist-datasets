"""Typed API models checked against the canonical JSON Schema in tests."""

from __future__ import annotations

from typing import TypedDict


class ServerOptionalFields(TypedDict, total=False):
    jitter_ms: float | None
    packet_loss_percent: float | None
    upload_mbps: float | None
    uptime_percent_24h: float | None
    uptime_percent_30d: float | None
    last_success_at: str | None
    source_license: str | None
    redistribution_allowed: bool


class Server(ServerOptionalFields):
    id: str
    country_code: str | None
    country_name: str | None
    city: str | None
    hostname: str | None
    ip: str | None
    protocol: str
    transport: str
    port: int
    speed_mbps: float | None
    latency_ms: float | None
    uptime_percent_7d: float | None
    uptime_hours: float | None
    sessions: int | None
    technical_quality_score: int
    score_label: str
    last_checked_at: str | None
    first_seen_at: str | None
    config_updated_at: str | None
    freshness_status: str
    availability_status: str
    source_name: str
    source_url: str
    server_page_url: str
    config_download_url: str | None
    risk_flags: list[str]
    config_sha256: str | None


class ResponseMeta(TypedDict, total=False):
    schema_version: str
    dataset_version: str
    snapshot_id: str
    generated_at: str
    expires_at: str
    total: int
    page: int
    per_page: int
    pages: int


class ResponseLinks(TypedDict, total=False):
    self: str
    next: str | None
    prev: str | None
    documentation: str


class ServerListResponse(TypedDict):
    data: list[Server]
    meta: ResponseMeta
    links: ResponseLinks


class ServerResponse(TypedDict):
    data: Server
    meta: ResponseMeta
    links: ResponseLinks
