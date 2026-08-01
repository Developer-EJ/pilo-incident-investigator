import json
import traceback
from datetime import UTC, datetime

import pytest

from pilo_incident_investigator.integrations.github import (
    GitHubClient,
    HttpResponse,
    IntegrationError,
)


class RecordingTransport:
    def __init__(self, response: HttpResponse) -> None:
        self.response = response
        self.calls: list[tuple[str, str, dict[str, str], bytes | None, float]] = []

    def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes | None,
        timeout_seconds: float,
    ) -> HttpResponse:
        self.calls.append((method, url, headers, body, timeout_seconds))
        return self.response


def response_body() -> bytes:
    return json.dumps(
        [
            {
                "id": 102,
                "environment": "dev",
                "sha": "bbbbbbbb",
                "created_at": "2026-08-01T00:30:00Z",
            },
            {
                "id": 101,
                "environment": "dev",
                "ref": "aaaaaaaa",
                "created_at": "2026-07-31T23:30:00Z",
            },
            {
                "id": 100,
                "environment": "prod",
                "sha": "cccccccc",
                "created_at": "2026-08-01T00:45:00Z",
            },
        ]
    ).encode()


def test_recent_deployments_are_bounded_filtered_and_normalized() -> None:
    transport = RecordingTransport(HttpResponse(status=200, body=response_body()))
    client = GitHubClient("synthetic-token", transport=transport)

    deployments = client.recent_deployments(
        "synthetic-org/pilo-dev-service-01",
        since=datetime(2026, 8, 1, tzinfo=UTC),
    )

    assert [(item.deployment_id, item.environment, item.revision) for item in deployments] == [
        ("102", "dev", "bbbbbbbb")
    ]
    method, url, headers, body, timeout = transport.calls[0]
    assert method == "GET"
    assert url.endswith(
        "/repos/synthetic-org/pilo-dev-service-01/deployments?environment=dev&per_page=10"
    )
    assert headers["Authorization"] == "Bearer synthetic-token"
    assert body is None
    assert timeout == 5.0


def test_client_repr_never_contains_token() -> None:
    client = GitHubClient(
        "synthetic-token", transport=RecordingTransport(HttpResponse(status=200, body=b"[]"))
    )

    assert repr(client) == "GitHubClient(redacted=True)"
    assert "synthetic-token" not in repr(client)


@pytest.mark.parametrize("repository", ["not-a-pair", "owner/repo/extra", "owner/../repo"])
def test_invalid_repository_is_rejected_before_http(repository: str) -> None:
    transport = RecordingTransport(HttpResponse(status=200, body=b"[]"))
    client = GitHubClient("synthetic-token", transport=transport)

    with pytest.raises(ValueError, match="repository"):
        client.recent_deployments(repository, since=datetime(2026, 8, 1, tzinfo=UTC))

    assert transport.calls == []


def test_naive_since_is_rejected_before_http() -> None:
    transport = RecordingTransport(HttpResponse(status=200, body=b"[]"))
    client = GitHubClient("synthetic-token", transport=transport)

    with pytest.raises(ValueError, match="timezone-aware"):
        client.recent_deployments("synthetic-org/pilo-dev-service-01", since=datetime(2026, 8, 1))

    assert transport.calls == []


@pytest.mark.parametrize(
    "response",
    [
        HttpResponse(status=500, body=b"SENSITIVE-RESPONSE-MARKER"),
        HttpResponse(status=200, body=b"SENSITIVE-RESPONSE-MARKER"),
    ],
)
def test_http_and_decode_errors_do_not_expose_response(response: HttpResponse) -> None:
    client = GitHubClient("synthetic-token", transport=RecordingTransport(response))

    with pytest.raises(IntegrationError) as captured:
        client.recent_deployments(
            "synthetic-org/pilo-dev-service-01", since=datetime(2026, 8, 1, tzinfo=UTC)
        )

    rendered = "".join(traceback.format_exception(captured.value))
    assert "SENSITIVE-RESPONSE-MARKER" not in rendered
    assert "synthetic-token" not in rendered


def test_transport_error_does_not_expose_remote_message() -> None:
    sensitive_marker = "SENSITIVE-TRANSPORT-MARKER"

    class FailingTransport(RecordingTransport):
        def request(
            self,
            method: str,
            url: str,
            headers: dict[str, str],
            body: bytes | None,
            timeout_seconds: float,
        ) -> HttpResponse:
            raise OSError(sensitive_marker)

    client = GitHubClient(
        "synthetic-token", transport=FailingTransport(HttpResponse(status=200, body=b"[]"))
    )

    with pytest.raises(IntegrationError) as captured:
        client.recent_deployments(
            "synthetic-org/pilo-dev-service-01", since=datetime(2026, 8, 1, tzinfo=UTC)
        )

    assert sensitive_marker not in "".join(traceback.format_exception(captured.value))
