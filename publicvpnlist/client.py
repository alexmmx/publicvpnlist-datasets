"""A small, typed and bounded PublicVPNList API client."""

from __future__ import annotations

import json
import time
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from typing import Any, Protocol, cast
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, build_opener

from .models import Server, ServerListResponse, ServerResponse

DEFAULT_BASE_URL = "https://publicvpnlist.com/api/v1"
DEFAULT_MAX_RESPONSE_BYTES = 4 * 1024 * 1024
RETRYABLE_STATUS = frozenset({429, 502, 503, 504})


class ClientError(RuntimeError):
    """Base class for safe client failures."""


class TransportError(ClientError):
    """The request could not be completed."""


class ContentTypeError(ClientError):
    """The server returned an unsupported media type."""


class ResponseTooLargeError(ClientError):
    """The response exceeded the configured byte limit."""


class ApiError(ClientError):
    """A non-successful HTTP response."""

    def __init__(
        self,
        status: int,
        code: str = "http_error",
        message: str = "The API request failed",
        request_id: str | None = None,
    ) -> None:
        super().__init__(f"HTTP {status}: {code}: {message}")
        self.status = status
        self.code = code
        self.request_id = request_id


class NotModified(ClientError):
    """A conditional request returned HTTP 304."""


@dataclass(frozen=True)
class TransportResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes


class Transport(Protocol):
    def request(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        timeout: float,
        max_bytes: int,
    ) -> TransportResponse:
        """Return a bounded response without logging its body."""


class UrllibTransport:
    """Default standard-library transport."""

    def __init__(self) -> None:
        self._opener = build_opener()

    def request(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        timeout: float,
        max_bytes: int,
    ) -> TransportResponse:
        request = Request(url, method=method, headers=dict(headers))
        try:
            with self._opener.open(request, timeout=timeout) as response:
                body = response.read(max_bytes + 1)
                if len(body) > max_bytes:
                    raise ResponseTooLargeError(
                        f"response exceeds {max_bytes} bytes",
                    )
                return TransportResponse(
                    status=response.status,
                    headers=dict(response.headers.items()),
                    body=body,
                )
        except HTTPError as error:
            body = error.read(max_bytes + 1)
            if len(body) > max_bytes:
                body = b""
            return TransportResponse(
                status=error.code,
                headers=dict(error.headers.items()),
                body=body,
            )
        except (TimeoutError, URLError) as error:
            raise TransportError("request transport failed") from error


class SessionTransport:
    """Adapter for a requests-compatible user-supplied session."""

    def __init__(self, session: Any) -> None:
        self._session = session

    def request(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        timeout: float,
        max_bytes: int,
    ) -> TransportResponse:
        try:
            response = self._session.request(
                method,
                url,
                headers=dict(headers),
                timeout=timeout,
                stream=True,
            )
            chunks: list[bytes] = []
            size = 0
            for chunk in response.iter_content(chunk_size=64 * 1024):
                size += len(chunk)
                if size > max_bytes:
                    raise ResponseTooLargeError(
                        f"response exceeds {max_bytes} bytes",
                    )
                chunks.append(chunk)
            return TransportResponse(
                status=int(response.status_code),
                headers=dict(response.headers),
                body=b"".join(chunks),
            )
        except ResponseTooLargeError:
            raise
        except Exception as error:
            raise TransportError("request transport failed") from error
        finally:
            if "response" in locals():
                response.close()


class PublicVPNListClient:
    """Client with bounded retries, response size and request time."""

    def __init__(
        self,
        *,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = 15.0,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        max_retries: int = 2,
        transport: Transport | None = None,
        session: Any | None = None,
        user_agent: str = "publicvpnlist-python/1.0",
        sleeper: Any = time.sleep,
    ) -> None:
        if timeout <= 0 or max_response_bytes < 1 or not 0 <= max_retries <= 5:
            raise ValueError("invalid client limits")
        if transport is not None and session is not None:
            raise ValueError("pass either transport or session, not both")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.max_response_bytes = max_response_bytes
        self.max_retries = max_retries
        self.transport = transport or (
            SessionTransport(session) if session is not None else UrllibTransport()
        )
        self.user_agent = user_agent
        self._sleep = sleeper

    def get(
        self,
        path: str,
        *,
        params: Mapping[str, str | int | float] | None = None,
        etag: str | None = None,
    ) -> dict[str, Any]:
        if not path.startswith("/") or path.startswith("//"):
            raise ValueError("path must be an API-relative absolute path")
        query = urlencode(params or {})
        url = f"{self.base_url}{path}" + (f"?{query}" if query else "")
        headers = {
            "Accept": "application/json",
            "User-Agent": self.user_agent,
        }
        if etag:
            headers["If-None-Match"] = etag

        for attempt in range(self.max_retries + 1):
            response = self.transport.request(
                "GET",
                url,
                headers,
                self.timeout,
                self.max_response_bytes,
            )
            if response.status in RETRYABLE_STATUS and attempt < self.max_retries:
                retry_after = _retry_after(response.headers)
                self._sleep(min(retry_after or 2**attempt, 5.0))
                continue
            return self._decode(response)
        raise AssertionError("bounded retry loop exhausted unexpectedly")

    def list_servers(
        self,
        **params: str | int | float,
    ) -> ServerListResponse:
        return cast(ServerListResponse, self.get("/servers", params=params))

    def get_server(self, public_id: str) -> ServerResponse:
        if not public_id.startswith("pvl_"):
            raise ValueError("invalid public server identifier")
        return cast(ServerResponse, self.get(f"/servers/{public_id}"))

    def iter_servers(
        self,
        **params: str | int | float,
    ) -> Iterator[Server]:
        next_path = "/servers"
        next_params: Mapping[str, str | int | float] | None = params
        while next_path:
            payload = self.get(next_path, params=next_params)
            data = payload.get("data")
            if not isinstance(data, list):
                raise ClientError("invalid list response")
            yield from cast(list[Server], data)
            next_url = payload.get("links", {}).get("next")
            if not next_url:
                break
            if not isinstance(next_url, str) or not next_url.startswith(self.base_url):
                raise ClientError("pagination link is outside the configured API")
            next_path = next_url[len(self.base_url) :]
            next_params = None

    def _decode(self, response: TransportResponse) -> dict[str, Any]:
        if response.status == 304:
            raise NotModified("cached representation is current")
        content_type = _header(response.headers, "content-type").split(";", 1)[0].lower()
        if content_type != "application/json":
            raise ContentTypeError("expected application/json")
        try:
            payload = json.loads(response.body)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ClientError("invalid JSON response") from error
        if not isinstance(payload, dict):
            raise ClientError("expected a JSON object")
        if not 200 <= response.status < 300:
            error_data = payload.get("error", {})
            if not isinstance(error_data, dict):
                error_data = {}
            raise ApiError(
                response.status,
                str(error_data.get("code", "http_error")),
                str(error_data.get("message", "The API request failed")),
                (
                    str(error_data["request_id"])
                    if error_data.get("request_id") is not None
                    else None
                ),
            )
        return payload


def _header(headers: Mapping[str, str], name: str) -> str:
    for key, value in headers.items():
        if key.lower() == name:
            return value
    return ""


def _retry_after(headers: Mapping[str, str]) -> float | None:
    value = _header(headers, "retry-after")
    try:
        parsed = float(value)
    except ValueError:
        return None
    return max(0.0, parsed)
