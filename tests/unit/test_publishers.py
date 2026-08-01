from __future__ import annotations

import traceback
from dataclasses import dataclass
from typing import Any

import pytest

from pilo_incident_investigator.integrations.github import IntegrationError
from pilo_incident_investigator.publishers import (
    MAX_BUNDLE_BYTES,
    MAX_ISSUE_MARKDOWN_CHARS,
    MAX_SLACK_SUMMARY_CHARS,
    BundleStoreFailed,
    PublicationPayload,
    Publisher,
    SlackWebhookClient,
)


class RecordingS3:
    def __init__(self, calls: list[str], *, failure: Exception | None = None) -> None:
        self.calls = calls
        self.failure = failure
        self.requests: list[dict[str, Any]] = []

    def put_object(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append("s3")
        self.requests.append(kwargs)
        if self.failure is not None:
            raise self.failure
        return {}


class RecordingGitHub:
    def __init__(
        self,
        calls: list[str],
        *,
        existing_url: str | None = None,
        search_failure: Exception | None = None,
        create_failure: Exception | None = None,
    ) -> None:
        self.calls = calls
        self.issue_url = existing_url
        self.search_failure = search_failure
        self.create_failure = create_failure
        self.created: list[tuple[str, str, str]] = []

    def find_issue_by_incident_id(self, repository: str, incident_id: str) -> str | None:
        self.calls.append("github")
        if self.search_failure is not None:
            raise self.search_failure
        return self.issue_url

    def create_incident_issue(self, repository: str, incident_id: str, issue_markdown: str) -> str:
        self.calls.append("github-create")
        if self.create_failure is not None:
            raise self.create_failure
        self.created.append((repository, incident_id, issue_markdown))
        self.issue_url = "https://github.com/synthetic-org/incidents/issues/7"
        return self.issue_url


class RecordingSlack:
    def __init__(self, calls: list[str], *, failure: Exception | None = None) -> None:
        self.calls = calls
        self.failure = failure
        self.messages: list[str] = []

    def send_text(self, text: str) -> None:
        self.calls.append("slack")
        self.messages.append(text)
        if self.failure is not None:
            raise self.failure


class RecordingState:
    def __init__(
        self,
        *,
        fail_at: str | None = None,
        failure: Exception | None = None,
        result: bool = True,
    ) -> None:
        self.fail_at = fail_at
        self.failure = failure or RuntimeError("SENSITIVE-STATE-ERROR")
        self.result = result
        self.calls: list[tuple[str, str]] = []

    def _mark(self, name: str, event_id: str) -> bool:
        self.calls.append((name, event_id))
        if self.fail_at == name:
            raise self.failure
        return self.result

    def mark_bundle_stored(self, event_id: str) -> bool:
        return self._mark("bundle", event_id)

    def mark_issue_published(self, event_id: str) -> bool:
        return self._mark("issue", event_id)

    def mark_slack_attempted(self, event_id: str) -> bool:
        return self._mark("slack", event_id)


def payload(**overrides: object) -> PublicationPayload:
    values: dict[str, object] = {
        "event_id": "evt-123",
        "incident_id": "inc-123",
        "bundle_bytes": b'{"incident_id":"inc-123"}',
        "issue_markdown": "## Incident Brief\n\nSafe summary.",
        "slack_summary": "API alarms require investigation",
    }
    values.update(overrides)
    return PublicationPayload(**values)  # type: ignore[arg-type]


def publisher(
    calls: list[str],
    *,
    s3: RecordingS3 | None = None,
    github: RecordingGitHub | None = None,
    slack: RecordingSlack | None = None,
    state: RecordingState | None = None,
) -> tuple[Publisher, RecordingS3, RecordingGitHub, RecordingSlack, RecordingState]:
    actual_s3 = s3 or RecordingS3(calls)
    actual_github = github or RecordingGitHub(calls)
    actual_slack = slack or RecordingSlack(calls)
    actual_state = state or RecordingState()
    return (
        Publisher(
            bundle_bucket="synthetic-private-bucket",
            github_repository="synthetic-org/incidents",
            s3=actual_s3,
            github=actual_github,
            slack=actual_slack,
            state=actual_state,
        ),
        actual_s3,
        actual_github,
        actual_slack,
        actual_state,
    )


def test_publish_order_and_exact_s3_arguments() -> None:
    calls: list[str] = []
    subject, s3, github, slack, state = publisher(calls)

    result = subject.publish(payload())

    assert calls == ["s3", "github", "github-create", "slack"]
    assert s3.requests == [
        {
            "Bucket": "synthetic-private-bucket",
            "Key": "incidents/inc-123/bundle.json",
            "Body": b'{"incident_id":"inc-123"}',
            "ContentType": "application/json",
            "ServerSideEncryption": "AES256",
        }
    ]
    assert github.created == [
        ("synthetic-org/incidents", "inc-123", "## Incident Brief\n\nSafe summary.")
    ]
    assert slack.messages == [
        "inc-123 — API alarms require investigation — "
        "https://github.com/synthetic-org/incidents/issues/7"
    ]
    assert state.calls == [
        ("bundle", "evt-123"),
        ("issue", "evt-123"),
        ("slack", "evt-123"),
    ]
    assert result.bundle_uri == "s3://synthetic-private-bucket/incidents/inc-123/bundle.json"
    assert result.issue_url == "https://github.com/synthetic-org/incidents/issues/7"
    assert result.slack_status == "sent"


def test_s3_failure_is_sanitized_and_blocks_every_later_step() -> None:
    calls: list[str] = []
    marker = "SENSITIVE-S3-ERROR"
    subject, _, _, _, state = publisher(calls, s3=RecordingS3(calls, failure=RuntimeError(marker)))

    with pytest.raises(BundleStoreFailed) as captured:
        subject.publish(payload())

    assert calls == ["s3"]
    assert state.calls == []
    assert marker not in "".join(traceback.format_exception(captured.value))
    assert captured.value.__cause__ is None


def test_bundle_checkpoint_failure_is_not_hidden_and_blocks_github_and_slack() -> None:
    calls: list[str] = []
    state = RecordingState(fail_at="bundle")
    subject, _, _, _, _ = publisher(calls, state=state)

    with pytest.raises(RuntimeError, match="SENSITIVE-STATE-ERROR"):
        subject.publish(payload())

    assert calls == ["s3"]
    assert state.calls == [("bundle", "evt-123")]


def test_existing_issue_is_reused_without_creating_another() -> None:
    calls: list[str] = []
    url = "https://github.com/synthetic-org/incidents/issues/4"
    github = RecordingGitHub(calls, existing_url=url)
    subject, _, _, slack, state = publisher(calls, github=github)

    result = subject.publish(payload())

    assert calls == ["s3", "github", "slack"]
    assert github.created == []
    assert result.issue_url == url
    assert slack.messages == [f"inc-123 — API alarms require investigation — {url}"]
    assert state.calls[1] == ("issue", "evt-123")


def test_issue_checkpoint_integration_error_is_not_mistaken_for_github_failure() -> None:
    calls: list[str] = []
    state_error = IntegrationError("state persistence failed")
    subject, _, _, slack, state = publisher(
        calls,
        state=RecordingState(fail_at="issue", failure=state_error),
    )

    with pytest.raises(IntegrationError, match="state persistence failed"):
        subject.publish(payload())

    assert calls == ["s3", "github", "github-create"]
    assert slack.messages == []
    assert state.calls == [("bundle", "evt-123"), ("issue", "evt-123")]


@pytest.mark.parametrize("failure_stage", ["search", "create"])
def test_github_failure_sends_only_fixed_degraded_message(failure_stage: str) -> None:
    calls: list[str] = []
    marker = "SENSITIVE-GITHUB-ERROR"
    github = RecordingGitHub(
        calls,
        search_failure=IntegrationError(marker) if failure_stage == "search" else None,
        create_failure=IntegrationError(marker) if failure_stage == "create" else None,
    )
    subject, _, _, slack, state = publisher(calls, github=github)

    result = subject.publish(
        payload(
            bundle_bytes=b"SENSITIVE-BUNDLE-DATA",
            issue_markdown="SENSITIVE-ISSUE-BODY",
            slack_summary="SENSITIVE-SUMMARY-MUST-NOT-BE-DEGRADED",
        )
    )

    assert result.issue_url is None
    assert result.slack_status == "sent"
    assert slack.messages == ["inc-123 — degraded: issue publication failed"]
    rendered = repr(result) + repr(slack.messages) + repr(state.calls)
    assert "SENSITIVE" not in rendered
    assert ("issue", "evt-123") not in state.calls
    assert state.calls[-1] == ("slack", "evt-123")


def test_degraded_slack_failure_is_recorded_without_raising() -> None:
    calls: list[str] = []
    subject, _, _, slack, state = publisher(
        calls,
        github=RecordingGitHub(calls, search_failure=IntegrationError("private")),
        slack=RecordingSlack(calls, failure=IntegrationError("private")),
    )

    result = subject.publish(payload())

    assert result.issue_url is None
    assert result.slack_status == "failed"
    assert slack.messages == ["inc-123 — degraded: issue publication failed"]
    assert state.calls[-1] == ("slack", "evt-123")


def test_normal_slack_failure_is_recorded_without_raising() -> None:
    calls: list[str] = []
    subject, _, _, _, state = publisher(
        calls, slack=RecordingSlack(calls, failure=IntegrationError("private"))
    )

    result = subject.publish(payload())

    assert result.issue_url == "https://github.com/synthetic-org/incidents/issues/7"
    assert result.slack_status == "failed"
    assert state.calls[-1] == ("slack", "evt-123")


def test_retry_reuses_issue_but_may_send_duplicate_slack_with_incident_id() -> None:
    calls: list[str] = []
    subject, s3, github, slack, state = publisher(calls)

    first = subject.publish(payload())
    second = subject.publish(payload())

    assert first == second
    assert len(s3.requests) == 2
    assert len(github.created) == 1
    assert len(slack.messages) == 2
    assert all("inc-123" in message for message in slack.messages)
    assert state.calls.count(("slack", "evt-123")) == 2


def test_already_advanced_checkpoints_do_not_block_idempotent_retry() -> None:
    calls: list[str] = []
    state = RecordingState(result=False)
    subject, _, github, slack, _ = publisher(
        calls,
        github=RecordingGitHub(
            calls,
            existing_url="https://github.com/synthetic-org/incidents/issues/4",
        ),
        state=state,
    )

    result = subject.publish(payload())

    assert result.issue_url == "https://github.com/synthetic-org/incidents/issues/4"
    assert github.created == []
    assert slack.messages == [
        "inc-123 — API alarms require investigation — "
        "https://github.com/synthetic-org/incidents/issues/4"
    ]
    assert state.calls == [
        ("bundle", "evt-123"),
        ("issue", "evt-123"),
        ("slack", "evt-123"),
    ]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("event_id", ""),
        ("incident_id", "../escape"),
        ("incident_id", "inc-123\n--> injected"),
        ("incident_id", "inc/123"),
        ("bundle_bytes", b""),
        ("bundle_bytes", b"x" * (MAX_BUNDLE_BYTES + 1)),
        ("issue_markdown", ""),
        ("issue_markdown", "x" * (MAX_ISSUE_MARKDOWN_CHARS + 1)),
        ("slack_summary", ""),
        ("slack_summary", "x" * (MAX_SLACK_SUMMARY_CHARS + 1)),
    ],
    ids=[
        "empty-event-id",
        "path-traversal-incident-id",
        "marker-injection-incident-id",
        "slash-incident-id",
        "empty-bundle",
        "oversized-bundle",
        "empty-issue",
        "oversized-issue",
        "empty-summary",
        "oversized-summary",
    ],
)
def test_invalid_payload_is_rejected_before_external_calls(field: str, value: object) -> None:
    calls: list[str] = []
    subject, _, _, _, _ = publisher(calls)

    with pytest.raises(ValueError):
        subject.publish(payload(**{field: value}))

    assert calls == []


def test_publication_payload_repr_hides_publishable_content() -> None:
    publication = payload(
        bundle_bytes=b"SENSITIVE-BUNDLE",
        issue_markdown="SENSITIVE-ISSUE",
        slack_summary="SENSITIVE-SUMMARY",
    )

    rendered = repr(publication)

    assert rendered == "PublicationPayload(redacted=True)"
    assert "SENSITIVE" not in rendered


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("slack_summary", "authorization: bearer fake-sensitive-credential"),
        ("issue_markdown", "webhook=https://hooks.slack.com/services/T/B/private"),
    ],
)
def test_publishable_text_with_credential_shape_is_rejected_before_calls(
    field: str, value: str
) -> None:
    calls: list[str] = []
    subject, _, _, _, _ = publisher(calls)

    with pytest.raises(ValueError, match="publishable text"):
        subject.publish(payload(**{field: value}))

    assert calls == []


@dataclass
class WebResponse:
    status: int
    body: bytes


class WebTransport:
    def __init__(self, response: WebResponse, *, failure: Exception | None = None) -> None:
        self.response = response
        self.failure = failure
        self.calls: list[tuple[str, str, dict[str, str], bytes | None, float]] = []

    def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes | None,
        timeout_seconds: float,
    ) -> WebResponse:
        self.calls.append((method, url, headers, body, timeout_seconds))
        if self.failure is not None:
            raise self.failure
        return self.response


def test_slack_webhook_sends_bounded_json_and_has_safe_repr() -> None:
    webhook = "https://hooks.slack.com/services/T000/B000/SAFEEXAMPLE"
    transport = WebTransport(WebResponse(status=200, body=b"ok"))
    client = SlackWebhookClient(webhook, transport=transport)

    client.send_text("inc-123 — bounded summary")

    method, url, headers, body, timeout = transport.calls[0]
    assert method == "POST"
    assert url == webhook
    assert headers == {"Content-Type": "application/json; charset=utf-8"}
    assert body == b'{"text":"inc-123 \\u2014 bounded summary"}'
    assert timeout == 5.0
    assert repr(client) == "SlackWebhookClient(redacted=True)"
    assert webhook not in repr(client)


@pytest.mark.parametrize(
    "webhook",
    [
        "http://hooks.slack.com/services/T/B/X",
        "https://attacker.invalid/services/T/B/X",
        "https://hooks.slack.com/other/T/B/X",
        "https://hooks.slack.com/services/T/B",
        "https://hooks.slack.com/services/T/B/X?token=secret",
    ],
)
def test_invalid_slack_webhook_is_rejected(webhook: str) -> None:
    transport = WebTransport(WebResponse(status=200, body=b"ok"))

    with pytest.raises(ValueError, match="Slack webhook"):
        SlackWebhookClient(webhook, transport=transport)

    assert transport.calls == []


@pytest.mark.parametrize(
    "response",
    [
        WebResponse(status=500, body=b"SENSITIVE-RESPONSE"),
        WebResponse(status=200, body=b"not-ok"),
        WebResponse(status=200, body=b"x" * 1025),
    ],
)
def test_slack_response_failures_are_sanitized(response: WebResponse) -> None:
    marker = "https://hooks.slack.com/services/T000/B000/PRIVATE"
    client = SlackWebhookClient(marker, transport=WebTransport(response))

    with pytest.raises(IntegrationError) as captured:
        client.send_text("inc-123 — safe")

    rendered = "".join(traceback.format_exception(captured.value))
    assert "SENSITIVE-RESPONSE" not in rendered
    assert marker not in rendered


def test_slack_transport_failure_is_sanitized() -> None:
    secret = "SENSITIVE-TRANSPORT"
    client = SlackWebhookClient(
        "https://hooks.slack.com/services/T000/B000/PRIVATE",
        transport=WebTransport(WebResponse(status=200, body=b"ok"), failure=OSError(secret)),
    )

    with pytest.raises(IntegrationError) as captured:
        client.send_text("inc-123 — safe")

    assert secret not in "".join(traceback.format_exception(captured.value))
