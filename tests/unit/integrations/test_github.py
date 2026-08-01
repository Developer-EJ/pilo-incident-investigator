import json
import traceback
from datetime import UTC, datetime
from urllib.parse import parse_qs, urlparse

import pytest

from pilo_incident_investigator.integrations.github import (
    ChangedFile,
    GitHubClient,
    HttpResponse,
    IntegrationError,
)

INCIDENT_ID = "inc-0123456789abcdefabcd"


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


class SequencedTransport(RecordingTransport):
    def __init__(self, responses: list[HttpResponse]) -> None:
        super().__init__(responses[0])
        self.responses = responses

    def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes | None,
        timeout_seconds: float,
    ) -> HttpResponse:
        self.calls.append((method, url, headers, body, timeout_seconds))
        return self.responses[len(self.calls) - 1]


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


def test_changed_files_use_one_bounded_request_and_exclude_file_contents() -> None:
    body = json.dumps(
        {
            "files": [
                {"filename": "src/service.py", "status": "modified", "patch": "secret patch"},
                {"filename": "README.md", "status": "added", "contents_url": "private URL"},
            ]
        }
    ).encode()
    transport = RecordingTransport(HttpResponse(status=200, body=body))
    client = GitHubClient("synthetic-token", transport=transport)

    files = client.changed_files("synthetic-org/pilo-dev-service-01", limit=2)

    assert files == (
        ChangedFile(path="src/service.py", status="modified"),
        ChangedFile(path="README.md", status="added"),
    )
    assert transport.calls == [
        (
            "GET",
            "https://api.github.com/repos/synthetic-org/pilo-dev-service-01/commits/HEAD?per_page=2",
            {
                "Accept": "application/vnd.github+json",
                "Authorization": "Bearer synthetic-token",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            None,
            5.0,
        )
    ]


def test_client_repr_never_contains_token() -> None:
    client = GitHubClient(
        "synthetic-token", transport=RecordingTransport(HttpResponse(status=200, body=b"[]"))
    )

    assert repr(client) == "GitHubClient(redacted=True)"
    assert "synthetic-token" not in repr(client)


@pytest.mark.parametrize(
    "repository",
    [
        "not-a-pair",
        "owner/repo/extra",
        "owner/..",
        "../repo",
        "owner/.",
        "./repo",
        f"{'o' * 101}/repo",
        f"owner/{'r' * 101}",
    ],
)
def test_invalid_repository_is_rejected_before_http(repository: str) -> None:
    transport = RecordingTransport(HttpResponse(status=200, body=b"[]"))
    client = GitHubClient("synthetic-token", transport=transport)

    with pytest.raises(ValueError, match="repository"):
        client.recent_deployments(repository, since=datetime(2026, 8, 1, tzinfo=UTC))

    assert transport.calls == []


def test_non_github_api_origin_is_rejected_before_http() -> None:
    transport = RecordingTransport(HttpResponse(status=200, body=b"[]"))

    with pytest.raises(ValueError, match="GitHub API origin"):
        GitHubClient(
            "synthetic-token",
            transport=transport,
            api_base="http://attacker.invalid",
        )

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


def test_find_issue_searches_open_and_closed_and_verifies_exact_marker_line() -> None:
    open_response = HttpResponse(
        status=200,
        body=json.dumps(
            {
                "total_count": 1,
                "incomplete_results": False,
                "items": [
                    {
                        "body": f"prefix <!-- incident-id:{INCIDENT_ID} --> suffix",
                        "html_url": "https://github.com/synthetic-org/incidents/issues/3",
                    }
                ],
            }
        ).encode(),
    )
    closed_response = HttpResponse(
        status=200,
        body=json.dumps(
            {
                "total_count": 1,
                "incomplete_results": False,
                "items": [
                    {
                        "body": f"<!-- incident-id:{INCIDENT_ID} -->\n## Incident Brief",
                        "html_url": "https://github.com/synthetic-org/incidents/issues/4",
                    }
                ],
            }
        ).encode(),
    )
    transport = SequencedTransport([open_response, closed_response])
    client = GitHubClient("synthetic-token", transport=transport)

    issue_url = client.find_issue_by_incident_id("synthetic-org/incidents", INCIDENT_ID)

    assert issue_url == "https://github.com/synthetic-org/incidents/issues/4"
    assert len(transport.calls) == 2
    states = []
    for method, url, _, body, timeout in transport.calls:
        assert method == "GET"
        assert urlparse(url).path == "/search/issues"
        query = parse_qs(urlparse(url).query)
        assert query["per_page"] == ["100"]
        assert "repo:synthetic-org/incidents" in query["q"][0]
        assert "is:issue" in query["q"][0]
        assert f'"incident-id:{INCIDENT_ID}" in:body' in query["q"][0]
        states.append("open" if "state:open" in query["q"][0] else "closed")
        assert body is None
        assert timeout == 5.0
    assert states == ["open", "closed"]


def test_find_issue_returns_none_when_search_only_has_loose_substring() -> None:
    response = HttpResponse(
        status=200,
        body=json.dumps(
            {
                "total_count": 1,
                "incomplete_results": False,
                "items": [
                    {
                        "body": f"prefix <!-- incident-id:{INCIDENT_ID} --> suffix",
                        "html_url": "https://github.com/synthetic-org/incidents/issues/3",
                    }
                ],
            }
        ).encode(),
    )
    client = GitHubClient("synthetic-token", transport=SequencedTransport([response, response]))

    assert client.find_issue_by_incident_id("synthetic-org/incidents", INCIDENT_ID) is None


def test_create_incident_issue_prefixes_exact_marker_and_returns_validated_url() -> None:
    response = HttpResponse(
        status=201,
        body=json.dumps(
            {
                "number": 7,
                "html_url": "https://github.com/synthetic-org/incidents/issues/7",
            }
        ).encode(),
    )
    transport = RecordingTransport(response)
    client = GitHubClient("synthetic-token", transport=transport)

    issue_url = client.create_incident_issue(
        "synthetic-org/incidents", INCIDENT_ID, "## Incident Brief\n\nSafe."
    )

    assert issue_url == "https://github.com/synthetic-org/incidents/issues/7"
    method, url, headers, body, timeout = transport.calls[0]
    assert method == "POST"
    assert url == "https://api.github.com/repos/synthetic-org/incidents/issues"
    assert headers["Authorization"] == "Bearer synthetic-token"
    assert json.loads(body or b"") == {
        "title": f"Incident {INCIDENT_ID}",
        "body": f"<!-- incident-id:{INCIDENT_ID} -->\n## Incident Brief\n\nSafe.",
    }
    assert timeout == 5.0


@pytest.mark.parametrize(
    "incident_id",
    ["", "inc-123", "../escape", "inc/123", "inc-123\n-->", "inc-0123456789ABCDEFABCD"],
)
def test_incident_issue_methods_reject_unsafe_incident_id_before_http(
    incident_id: str,
) -> None:
    transport = RecordingTransport(HttpResponse(status=200, body=b"{}"))
    client = GitHubClient("synthetic-token", transport=transport)

    with pytest.raises(ValueError, match="incident ID"):
        client.find_issue_by_incident_id("synthetic-org/incidents", incident_id)
    with pytest.raises(ValueError, match="incident ID"):
        client.create_incident_issue("synthetic-org/incidents", incident_id, "safe")

    assert transport.calls == []


@pytest.mark.parametrize(
    "response",
    [
        HttpResponse(
            status=200,
            body=json.dumps(
                {"total_count": 101, "incomplete_results": False, "items": []}
            ).encode(),
        ),
        HttpResponse(
            status=200,
            body=json.dumps(
                {
                    "total_count": 2,
                    "incomplete_results": False,
                    "items": [
                        {
                            "body": "unrelated",
                            "html_url": "https://github.com/synthetic-org/incidents/issues/1",
                        }
                    ],
                }
            ).encode(),
        ),
    ],
)
def test_issue_search_never_concludes_absence_from_truncated_results(
    response: HttpResponse,
) -> None:
    client = GitHubClient("synthetic-token", transport=RecordingTransport(response))

    with pytest.raises(IntegrationError, match="invalid"):
        client.find_issue_by_incident_id("synthetic-org/incidents", INCIDENT_ID)


@pytest.mark.parametrize(
    "response",
    [
        HttpResponse(status=500, body=b"SENSITIVE-RESPONSE-MARKER"),
        HttpResponse(status=200, body=b"not-json"),
        HttpResponse(status=200, body=b"x" * 1_000_001),
        HttpResponse(
            status=200,
            body=json.dumps(
                {
                    "total_count": 1,
                    "incomplete_results": False,
                    "items": [
                        {
                            "body": f"<!-- incident-id:{INCIDENT_ID} -->",
                            "html_url": "https://attacker.invalid/leak",
                        }
                    ],
                }
            ).encode(),
        ),
    ],
)
def test_issue_search_response_errors_are_sanitized(response: HttpResponse) -> None:
    client = GitHubClient("synthetic-token", transport=RecordingTransport(response))

    with pytest.raises(IntegrationError) as captured:
        client.find_issue_by_incident_id("synthetic-org/incidents", INCIDENT_ID)

    rendered = "".join(traceback.format_exception(captured.value))
    assert "SENSITIVE-RESPONSE-MARKER" not in rendered
    assert "synthetic-token" not in rendered
    assert "attacker.invalid" not in rendered


def test_issue_creation_rejects_oversized_body_before_http() -> None:
    transport = RecordingTransport(HttpResponse(status=201, body=b"{}"))
    client = GitHubClient("synthetic-token", transport=transport)

    with pytest.raises(ValueError, match="Issue Markdown"):
        client.create_incident_issue("synthetic-org/incidents", INCIDENT_ID, "x" * 65_001)

    assert transport.calls == []


def test_issue_creation_rejects_credential_shaped_markdown_before_http() -> None:
    marker = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"
    transport = RecordingTransport(HttpResponse(status=201, body=b"{}"))
    client = GitHubClient("synthetic-token", transport=transport)

    with pytest.raises(ValueError) as captured:
        client.create_incident_issue(
            "synthetic-org/incidents", INCIDENT_ID, f"unsafe credential {marker}"
        )

    assert transport.calls == []
    assert marker not in "".join(traceback.format_exception(captured.value))


@pytest.mark.parametrize(
    "issue_markdown",
    [
        f"<!-- incident-id:{INCIDENT_ID} -->\ncurrent marker",
        "<!-- incident-id:inc-11111111111111111111 -->\nfuture search confusion",
        "<!--  INCIDENT-ID : inc-22222222222222222222  -->\nmarker-like",
        "<!-- incident-id:attacker -->\nnoncanonical marker",
        "<!-- incident-id -->\nmarker without value",
        "<!--  InCiDeNt - Id : attacker  -->\nnormalized marker",
    ],
)
def test_issue_creation_rejects_supplied_incident_markers_before_http(
    issue_markdown: str,
) -> None:
    transport = RecordingTransport(
        HttpResponse(
            status=201,
            body=json.dumps(
                {"html_url": "https://github.com/synthetic-org/incidents/issues/9"}
            ).encode(),
        )
    )
    client = GitHubClient("synthetic-token", transport=transport)

    with pytest.raises(ValueError) as captured:
        client.create_incident_issue("synthetic-org/incidents", INCIDENT_ID, issue_markdown)

    assert transport.calls == []
    assert "incident-id" not in "".join(traceback.format_exception(captured.value)).casefold()
