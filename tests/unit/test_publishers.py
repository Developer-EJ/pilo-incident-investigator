from __future__ import annotations

import json
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
    PublisherStateFailed,
    SlackWebhookClient,
)

INCIDENT_ID = "inc-0123456789abcdefabcd"
BUNDLE_BYTES = b'{"incident_id":"inc-0123456789abcdefabcd"}'


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
        self.calls: list[tuple[str, ...]] = []

    def _mark(self, name: str, event_id: str, *details: str) -> bool:
        self.calls.append((name, event_id, *details))
        if self.fail_at == name:
            raise self.failure
        return self.result

    def mark_bundle_stored(self, event_id: str) -> bool:
        return self._mark("bundle", event_id)

    def mark_issue_published(self, event_id: str) -> bool:
        return self._mark("issue", event_id)

    def mark_slack_attempted(self, event_id: str, status: str) -> bool:
        return self._mark("slack", event_id, status)


def payload(**overrides: object) -> PublicationPayload:
    values: dict[str, object] = {
        "event_id": "evt-123",
        "incident_id": INCIDENT_ID,
        "bundle_bytes": BUNDLE_BYTES,
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
            "Key": f"incidents/{INCIDENT_ID}/bundle.json",
            "Body": BUNDLE_BYTES,
            "ContentType": "application/json",
            "ServerSideEncryption": "AES256",
        }
    ]
    assert github.created == [
        ("synthetic-org/incidents", INCIDENT_ID, "## Incident Brief\n\nSafe summary.")
    ]
    assert slack.messages == [
        f"{INCIDENT_ID} — API alarms require investigation — "
        "https://github.com/synthetic-org/incidents/issues/7"
    ]
    assert state.calls == [
        ("bundle", "evt-123"),
        ("issue", "evt-123"),
        ("slack", "evt-123", "sent"),
    ]
    assert result.bundle_uri == (
        f"s3://synthetic-private-bucket/incidents/{INCIDENT_ID}/bundle.json"
    )
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
    assert slack.messages == [f"{INCIDENT_ID} — API alarms require investigation — {url}"]
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
            bundle_bytes=b'{"detail":"SENSITIVE-BUNDLE-DATA"}',
            issue_markdown="SENSITIVE-ISSUE-BODY",
            slack_summary="SENSITIVE-SUMMARY-MUST-NOT-BE-DEGRADED",
        )
    )

    assert result.issue_url is None
    assert result.slack_status == "sent"
    assert slack.messages == [f"{INCIDENT_ID} — degraded: issue publication failed"]
    rendered = repr(result) + repr(slack.messages) + repr(state.calls)
    assert "SENSITIVE" not in rendered
    assert ("issue", "evt-123") not in state.calls
    assert state.calls[-1] == ("slack", "evt-123", "sent")


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
    assert slack.messages == [f"{INCIDENT_ID} — degraded: issue publication failed"]
    assert state.calls[-1] == ("slack", "evt-123", "failed")


def test_normal_slack_failure_is_recorded_without_raising() -> None:
    calls: list[str] = []
    subject, _, _, _, state = publisher(
        calls, slack=RecordingSlack(calls, failure=IntegrationError("private"))
    )

    result = subject.publish(payload())

    assert result.issue_url == "https://github.com/synthetic-org/incidents/issues/7"
    assert result.slack_status == "failed"
    assert state.calls[-1] == ("slack", "evt-123", "failed")


def test_retry_reuses_issue_but_may_send_duplicate_slack_with_incident_id() -> None:
    calls: list[str] = []
    subject, s3, github, slack, state = publisher(calls)

    first = subject.publish(payload())
    second = subject.publish(payload())

    assert first == second
    assert len(s3.requests) == 2
    assert len(github.created) == 1
    assert len(slack.messages) == 2
    assert all(INCIDENT_ID in message for message in slack.messages)
    assert state.calls.count(("slack", "evt-123", "sent")) == 2


def test_unclaimed_publisher_state_blocks_publication_after_s3() -> None:
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

    with pytest.raises(PublisherStateFailed, match="not claimed"):
        subject.publish(payload())

    assert calls == ["s3"]
    assert github.created == []
    assert slack.messages == []
    assert state.calls == [("bundle", "evt-123")]


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


@pytest.mark.parametrize(
    ("field", "unsafe_id"),
    [
        ("incident_id", "inc-123"),
        ("incident_id", "inc-0123456789ABCDEFABCD"),
        ("event_id", "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"),
    ],
)
def test_noncanonical_or_credential_shaped_ids_are_rejected_without_side_effects(
    field: str, unsafe_id: str
) -> None:
    calls: list[str] = []
    state = RecordingState()
    publisher(calls, state=state)

    with pytest.raises(ValueError) as captured:
        payload(**{field: unsafe_id})

    rendered = "".join(traceback.format_exception(captured.value))
    assert calls == []
    assert state.calls == []
    assert unsafe_id not in rendered


@pytest.mark.parametrize("repository", ["../repo", "owner/..", "owner/.", "./repo"])
def test_publisher_rejects_repository_dot_segments_before_s3(repository: str) -> None:
    calls: list[str] = []

    with pytest.raises(ValueError, match="repository"):
        Publisher(
            bundle_bucket="synthetic-private-bucket",
            github_repository=repository,
            s3=RecordingS3(calls),
            github=RecordingGitHub(calls),
            slack=RecordingSlack(calls),
            state=RecordingState(),
        )

    assert calls == []


def test_credential_shaped_bundle_bytes_are_rejected_before_every_sink() -> None:
    calls: list[str] = []
    state = RecordingState()
    subject, _, _, _, _ = publisher(calls, state=state)
    marker = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"

    with pytest.raises(ValueError) as captured:
        subject.publish(payload(bundle_bytes=f'{{"token":"{marker}"}}'.encode()))

    assert calls == []
    assert state.calls == []
    assert marker not in "".join(traceback.format_exception(captured.value))


@pytest.mark.parametrize(
    "bundle_bytes",
    [
        b'{"token":"synthetic-opaque-value"}',
        b'{"nested":{"password":"synthetic-opaque-value"}}',
        b'{"items":[{"clientSecret":["synthetic-opaque-value"]}]}',
        b'{"awsSecretAccessKey":{"part":"synthetic-opaque-value"}}',
    ],
)
def test_semantically_sensitive_bundle_values_are_rejected_before_s3(
    bundle_bytes: bytes,
) -> None:
    calls: list[str] = []
    state = RecordingState()
    publisher(calls, state=state)

    with pytest.raises(ValueError) as captured:
        payload(bundle_bytes=bundle_bytes)

    assert calls == []
    assert state.calls == []
    assert "synthetic-opaque-value" not in "".join(traceback.format_exception(captured.value))


def test_redacted_bundle_sentinel_and_rotation_metadata_remain_publishable() -> None:
    safe_bundle = json.dumps(
        {
            "last_rotated_at": "2026-01-01T00:00:00Z",
            "next_rotation_at": None,
            "password": "[REDACTED:SENSITIVE_FIELD]",
            "rotation_enabled": True,
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()

    publication = payload(bundle_bytes=safe_bundle)

    assert publication.bundle_bytes == safe_bundle


@pytest.mark.parametrize(
    "bundle_bytes",
    [
        b'{"token":123456789}',
        b'{"password":true}',
        b'{"password":null}',
        b'{"clientSecret":[{"part":7}]}',
        b'{"clientSecret":[]}',
        b'{"clientSecret":{}}',
    ],
)
def test_sensitive_non_string_or_empty_values_fail_before_every_sink(
    bundle_bytes: bytes,
) -> None:
    calls: list[str] = []
    state = RecordingState()
    publisher(calls, state=state)

    with pytest.raises(ValueError) as captured:
        payload(bundle_bytes=bundle_bytes)

    assert calls == []
    assert state.calls == []
    rendered = "".join(traceback.format_exception(captured.value))
    assert "123456789" not in rendered
    assert "clientSecret" not in rendered


def test_sensitive_container_with_approved_sentinels_remains_publishable() -> None:
    safe_bundle = (
        b'{"clientSecret":["[REDACTED:SENSITIVE_FIELD]",{"nested":"[REDACTED:SENSITIVE_FIELD]"}]}'
    )

    publication = payload(bundle_bytes=safe_bundle)

    assert publication.bundle_bytes == safe_bundle


@pytest.mark.parametrize(
    "bundle_bytes",
    [
        b'{"value":NaN}',
        b'{"value":Infinity}',
        b'{"value":-Infinity}',
        b'{"value":1e400}',
    ],
)
def test_nonfinite_json_numbers_are_rejected_before_every_sink(bundle_bytes: bytes) -> None:
    calls: list[str] = []
    state = RecordingState()
    publisher(calls, state=state)

    with pytest.raises(ValueError, match="canonical"):
        payload(bundle_bytes=bundle_bytes)

    assert calls == []
    assert state.calls == []


@pytest.mark.parametrize(
    "issue_markdown",
    [
        f"<!-- incident-id:{INCIDENT_ID} -->\nInjected current marker",
        "<!-- incident-id:inc-11111111111111111111 -->\nInjected other marker",
        "<!--  INCIDENT-ID : inc-22222222222222222222  -->\nMarker-like",
    ],
)
def test_issue_markdown_rejects_hidden_incident_marker_before_every_sink(
    issue_markdown: str,
) -> None:
    calls: list[str] = []
    state = RecordingState()
    publisher(calls, state=state)

    with pytest.raises(ValueError) as captured:
        payload(issue_markdown=issue_markdown)

    assert calls == []
    assert state.calls == []
    assert "incident-id" not in "".join(traceback.format_exception(captured.value)).casefold()


def test_publication_payload_repr_hides_publishable_content() -> None:
    publication = payload(
        bundle_bytes=b'{"detail":"PRIVATE-BUNDLE"}',
        issue_markdown="PRIVATE-ISSUE",
        slack_summary="PRIVATE-SUMMARY",
    )

    rendered = repr(publication)

    assert rendered == "PublicationPayload(redacted=True)"
    assert "PRIVATE" not in rendered


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

    with pytest.raises(ValueError, match="credential shape"):
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
    assert body == '{"text":"inc-123 — bounded summary"}'.encode()
    assert timeout == 5.0
    assert repr(client) == "SlackWebhookClient(redacted=True)"
    assert webhook not in repr(client)


def test_slack_webhook_accepts_bounded_korean_summary_without_ascii_expansion() -> None:
    transport = WebTransport(WebResponse(status=200, body=b"ok"))
    client = SlackWebhookClient(
        "https://hooks.slack.com/services/T000/B000/SAFEEXAMPLE",
        transport=transport,
    )
    text = "가" * MAX_SLACK_SUMMARY_CHARS

    client.send_text(text)

    body = transport.calls[0][3]
    assert body is not None
    assert json.loads(body) == {"text": text}
    assert len(body) <= 3_000


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


def test_slack_adapter_rejects_credential_shaped_text_before_http() -> None:
    marker = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"
    transport = WebTransport(WebResponse(status=200, body=b"ok"))
    client = SlackWebhookClient(
        "https://hooks.slack.com/services/T000/B000/PRIVATE",
        transport=transport,
    )

    with pytest.raises(ValueError) as captured:
        client.send_text(f"{INCIDENT_ID} — {marker}")

    assert transport.calls == []
    assert marker not in "".join(traceback.format_exception(captured.value))
