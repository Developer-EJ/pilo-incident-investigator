"""Ordered, bounded publication of already-redacted incident records."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.request import Request, urlopen

from pilo_incident_investigator.integrations.github import (
    IntegrationError,
    validate_incident_id,
    validate_repository,
)
from pilo_incident_investigator.redaction import Redactor, is_safe_structural_id

MAX_BUNDLE_BYTES = 1_000_000
MAX_ISSUE_MARKDOWN_CHARS = 65_000
MAX_SLACK_SUMMARY_CHARS = 500
MAX_SLACK_MESSAGE_BYTES = 3_000
MAX_SLACK_RESPONSE_BYTES = 1_024
SLACK_TIMEOUT_SECONDS = 5.0

_IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_BUCKET_PATTERN = re.compile(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]")
_SLACK_WEBHOOK_PATTERN = re.compile(
    r"https://hooks\.slack\.com/services/[A-Za-z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9]+"
)


class BundleStoreFailed(RuntimeError):
    """Sanitized failure to durably store the canonical Incident Bundle."""


class PublisherStateFailed(RuntimeError):
    """Sanitized failure to durably record a publisher outcome."""


@dataclass(frozen=True, slots=True, repr=False)
class PublicationPayload:
    event_id: str
    incident_id: str
    bundle_bytes: bytes
    issue_markdown: str
    slack_summary: str

    def __post_init__(self) -> None:
        _validate_publication(self)

    def __repr__(self) -> str:
        return "PublicationPayload(redacted=True)"


@dataclass(frozen=True, slots=True)
class PublishResult:
    bundle_uri: str
    issue_url: str | None
    slack_status: str


class S3Client(Protocol):
    def put_object(self, **kwargs: Any) -> dict[str, Any]: ...


class GitHubIssueClient(Protocol):
    def find_issue_by_incident_id(self, repository: str, incident_id: str) -> str | None: ...

    def create_incident_issue(
        self, repository: str, incident_id: str, issue_markdown: str
    ) -> str: ...


class SlackClient(Protocol):
    def send_text(self, text: str) -> None: ...


class PublisherState(Protocol):
    def mark_bundle_stored(self, event_id: str) -> bool: ...

    def mark_issue_published(self, event_id: str) -> bool: ...

    def mark_slack_attempted(self, event_id: str, status: str) -> bool: ...


class HttpResponseLike(Protocol):
    status: int
    body: bytes


class SlackHttpTransport(Protocol):
    def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes | None,
        timeout_seconds: float,
    ) -> HttpResponseLike: ...


@dataclass(frozen=True, slots=True)
class _SlackHttpResponse:
    status: int
    body: bytes


class _UrlLibSlackTransport:
    def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes | None,
        timeout_seconds: float,
    ) -> _SlackHttpResponse:
        request = Request(url=url, data=body, headers=headers, method=method)
        with urlopen(request, timeout=timeout_seconds) as response:  # noqa: S310
            return _SlackHttpResponse(
                status=response.status,
                body=response.read(MAX_SLACK_RESPONSE_BYTES + 1),
            )


class SlackWebhookClient:
    """Bounded Slack Incoming Webhook adapter with credential-safe failures."""

    __slots__ = ("_transport", "_webhook_url")

    def __init__(self, webhook_url: str, *, transport: SlackHttpTransport | None = None) -> None:
        if _SLACK_WEBHOOK_PATTERN.fullmatch(webhook_url) is None:
            raise ValueError("Slack webhook must use the official HTTPS services endpoint")
        self._webhook_url = webhook_url
        self._transport = transport or _UrlLibSlackTransport()

    def send_text(self, text: str) -> None:
        if not isinstance(text, str) or not text:
            raise ValueError("Slack text must be a non-empty string")
        _require_safe_text(text)
        body = json.dumps({"text": text}, ensure_ascii=False, separators=(",", ":")).encode()
        if len(body) > MAX_SLACK_MESSAGE_BYTES:
            raise ValueError("Slack message exceeds the bounded payload size")
        try:
            response = self._transport.request(
                "POST",
                self._webhook_url,
                {"Content-Type": "application/json; charset=utf-8"},
                body,
                SLACK_TIMEOUT_SECONDS,
            )
        except (OSError, TimeoutError):
            raise IntegrationError("Slack request failed") from None
        if (
            response.status != 200
            or len(response.body) > MAX_SLACK_RESPONSE_BYTES
            or response.body != b"ok"
        ):
            raise IntegrationError("Slack request failed")

    def __repr__(self) -> str:
        return "SlackWebhookClient(redacted=True)"


class Publisher:
    """Publish one Incident Bundle, Issue, and Slack handoff in safe order."""

    def __init__(
        self,
        *,
        bundle_bucket: str,
        github_repository: str,
        s3: S3Client,
        github: GitHubIssueClient,
        slack: SlackClient,
        state: PublisherState,
    ) -> None:
        if _BUCKET_PATTERN.fullmatch(bundle_bucket) is None:
            raise ValueError("bundle bucket must be a valid bucket name")
        validate_repository(github_repository)
        self._bundle_bucket = bundle_bucket
        self._github_repository = github_repository
        self._s3 = s3
        self._github = github
        self._slack = slack
        self._state = state

    def publish(self, publication: PublicationPayload) -> PublishResult:
        _validate_publication(publication)
        key = f"incidents/{publication.incident_id}/bundle.json"
        bundle_uri = f"s3://{self._bundle_bucket}/{key}"

        try:
            self._s3.put_object(
                Bucket=self._bundle_bucket,
                Key=key,
                Body=publication.bundle_bytes,
                ContentType="application/json",
                ServerSideEncryption="AES256",
            )
        except Exception:
            raise BundleStoreFailed("Incident Bundle storage failed") from None

        # Independent outcome writes return True on retries even when the
        # compatibility checkpoint rank is already ahead; False is unclaimed.
        if not self._state.mark_bundle_stored(publication.event_id):
            raise PublisherStateFailed("publisher state was not claimed")

        issue_url: str | None
        try:
            issue_url = self._github.find_issue_by_incident_id(
                self._github_repository, publication.incident_id
            )
            if issue_url is None:
                issue_url = self._github.create_incident_issue(
                    self._github_repository,
                    publication.incident_id,
                    publication.issue_markdown,
                )
        except IntegrationError:
            issue_url = None
        else:
            if not self._state.mark_issue_published(publication.event_id):
                raise PublisherStateFailed("publisher state was not claimed")

        if issue_url is None:
            slack_text = f"{publication.incident_id} — degraded: issue publication failed"
        else:
            slack_text = f"{publication.incident_id} — {publication.slack_summary} — {issue_url}"

        try:
            self._slack.send_text(slack_text)
        except IntegrationError:
            slack_status = "failed"
        else:
            slack_status = "sent"
        if not self._state.mark_slack_attempted(publication.event_id, slack_status):
            raise PublisherStateFailed("publisher state was not claimed")

        return PublishResult(
            bundle_uri=bundle_uri,
            issue_url=issue_url,
            slack_status=slack_status,
        )


def _validate_publication(publication: PublicationPayload) -> None:
    if not isinstance(publication, PublicationPayload):
        raise TypeError("publication must be a PublicationPayload")
    if _IDENTIFIER_PATTERN.fullmatch(publication.event_id) is None or not is_safe_structural_id(
        publication.event_id
    ):
        raise ValueError("event ID is invalid")
    validate_incident_id(publication.incident_id)
    if not isinstance(publication.bundle_bytes, bytes) or not (
        1 <= len(publication.bundle_bytes) <= MAX_BUNDLE_BYTES
    ):
        raise ValueError("Bundle bytes must be non-empty and bounded")
    _validate_canonical_bundle_bytes(publication.bundle_bytes)
    if not isinstance(publication.issue_markdown, str) or not (
        1 <= len(publication.issue_markdown) <= MAX_ISSUE_MARKDOWN_CHARS
    ):
        raise ValueError("Issue Markdown must be non-empty and bounded")
    if not isinstance(publication.slack_summary, str) or not (
        1 <= len(publication.slack_summary) <= MAX_SLACK_SUMMARY_CHARS
    ):
        raise ValueError("Slack summary must be non-empty and bounded")
    redactor = Redactor()
    for value in (publication.issue_markdown, publication.slack_summary):
        _require_safe_text(value, redactor=redactor)


def _validate_canonical_bundle_bytes(bundle_bytes: bytes) -> None:
    try:
        text = bundle_bytes.decode("utf-8")
        parsed = json.loads(text)
        if not isinstance(parsed, dict):
            raise TypeError
        canonical = json.dumps(
            parsed,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (UnicodeError, ValueError, TypeError):
        raise ValueError("Bundle bytes must be canonical UTF-8 JSON") from None
    if canonical != bundle_bytes:
        raise ValueError("Bundle bytes must be canonical UTF-8 JSON")
    _require_safe_text(text)


def _require_safe_text(value: str, *, redactor: Redactor | None = None) -> None:
    actual_redactor = redactor or Redactor()
    redacted, report = actual_redactor.redact_text(value)
    if report.replacements or redacted != value:
        raise ValueError("publishable text contains a credential shape")
