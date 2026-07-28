from __future__ import annotations

import json
from collections.abc import Mapping

import pytest

from publicvpnlist.client import (
    ApiError,
    ContentTypeError,
    NotModified,
    PublicVPNListClient,
    ResponseTooLargeError,
    TransportResponse,
)


class FakeTransport:
    def __init__(self, responses: list[TransportResponse]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, str, Mapping[str, str], float, int]] = []

    def request(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        timeout: float,
        max_bytes: int,
    ) -> TransportResponse:
        self.calls.append((method, url, headers, timeout, max_bytes))
        return self.responses.pop(0)


def response(status: int, payload: dict, **headers: str) -> TransportResponse:
    return TransportResponse(
        status=status,
        headers={"Content-Type": "application/json", **headers},
        body=json.dumps(payload).encode(),
    )


def test_client_handles_safe_api_error_without_leaking_body() -> None:
    transport = FakeTransport(
        [
            response(
                404,
                {
                    "error": {
                        "code": "not_found",
                        "message": "Server was not found",
                        "request_id": "synthetic-request",
                    }
                },
            )
        ],
    )
    client = PublicVPNListClient(transport=transport, max_retries=0)
    with pytest.raises(ApiError) as captured:
        client.get_server("pvl_000000000000000000000001")
    assert captured.value.code == "not_found"
    assert captured.value.request_id == "synthetic-request"


def test_client_retries_only_bounded_temporary_errors() -> None:
    transport = FakeTransport(
        [
            response(503, {"error": {}}, **{"Retry-After": "0"}),
            response(200, {"data": [], "meta": {}, "links": {}}),
        ],
    )
    sleeps: list[float] = []
    client = PublicVPNListClient(
        transport=transport,
        max_retries=1,
        sleeper=sleeps.append,
    )
    assert client.list_servers()["data"] == []
    assert len(transport.calls) == 2
    assert sleeps == [1]


def test_client_does_not_retry_validation_errors() -> None:
    transport = FakeTransport([response(400, {"error": {}})])
    client = PublicVPNListClient(transport=transport, max_retries=2)
    with pytest.raises(ApiError):
        client.list_servers()
    assert len(transport.calls) == 1


def test_client_rejects_wrong_content_type() -> None:
    transport = FakeTransport(
        [
            TransportResponse(
                status=200,
                headers={"Content-Type": "text/html"},
                body=b"<html></html>",
            )
        ],
    )
    client = PublicVPNListClient(transport=transport)
    with pytest.raises(ContentTypeError):
        client.list_servers()


def test_client_handles_not_modified_without_json_body() -> None:
    transport = FakeTransport(
        [TransportResponse(status=304, headers={}, body=b"")],
    )
    client = PublicVPNListClient(transport=transport)
    with pytest.raises(NotModified):
        client.get("/stats", etag='"synthetic"')


def test_client_propagates_response_size_limit() -> None:
    class LargeTransport(FakeTransport):
        def request(
            self,
            method: str,
            url: str,
            headers: Mapping[str, str],
            timeout: float,
            max_bytes: int,
        ) -> TransportResponse:
            raise ResponseTooLargeError(f"response exceeds {max_bytes} bytes")

    client = PublicVPNListClient(transport=LargeTransport([]), max_response_bytes=64)
    with pytest.raises(ResponseTooLargeError):
        client.list_servers()


def test_client_pagination_stays_on_configured_api() -> None:
    transport = FakeTransport(
        [
            response(
                200,
                {
                    "data": [{"id": "pvl_000000000000000000000001"}],
                    "meta": {},
                    "links": {
                        "next": "https://publicvpnlist.com/api/v1/servers?page=2",
                    },
                },
            ),
            response(
                200,
                {
                    "data": [{"id": "pvl_000000000000000000000002"}],
                    "meta": {},
                    "links": {"next": None},
                },
            ),
        ],
    )
    client = PublicVPNListClient(transport=transport)
    assert [item["id"] for item in client.iter_servers(per_page=1)] == [
        "pvl_000000000000000000000001",
        "pvl_000000000000000000000002",
    ]


def test_client_accepts_requests_compatible_session() -> None:
    class SessionResponse:
        status_code = 200
        headers = {"Content-Type": "application/json"}

        def iter_content(self, chunk_size: int) -> list[bytes]:
            assert chunk_size > 0
            return [b'{"data":[],"meta":{},"links":{}}']

        def close(self) -> None:
            return None

    class Session:
        def request(self, *_args: object, **kwargs: object) -> SessionResponse:
            assert kwargs["stream"] is True
            assert kwargs["timeout"] == 3
            return SessionResponse()

    client = PublicVPNListClient(session=Session(), timeout=3)
    assert client.list_servers()["data"] == []
