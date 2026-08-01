"""Bounded GitHub REST reads with credential-safe failures."""

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol
from urllib.parse import urlencode
from urllib.request import Request, urlopen

MAX_DEPLOYMENTS = 10
MAX_CHANGED_FILES = 100
MAX_RESPONSE_BYTES = 1_000_000
REQUEST_TIMEOUT_SECONDS = 5.0
GITHUB_API_BASE = "https://api.github.com"
_REPOSITORY_PATTERN = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")


class IntegrationError(RuntimeError):
    """Sanitized external integration failure."""


@dataclass(frozen=True, slots=True)
class HttpResponse:
    status: int
    body: bytes


@dataclass(frozen=True, slots=True)
class Deployment:
    deployment_id: str
    environment: str
    revision: str
    created_at: datetime


@dataclass(frozen=True, slots=True)
class ChangedFile:
    path: str
    status: str


class HttpTransport(Protocol):
    def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes | None,
        timeout_seconds: float,
    ) -> HttpResponse: ...


class _UrlLibTransport:
    def request(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes | None,
        timeout_seconds: float,
    ) -> HttpResponse:
        request = Request(url=url, data=body, headers=headers, method=method)
        with urlopen(request, timeout=timeout_seconds) as response:  # noqa: S310
            return HttpResponse(
                status=response.status,
                body=response.read(MAX_RESPONSE_BYTES + 1),
            )


class GitHubClient:
    __slots__ = ("_token", "_transport", "_api_base")

    def __init__(
        self,
        token: str,
        *,
        transport: HttpTransport | None = None,
        api_base: str = GITHUB_API_BASE,
    ) -> None:
        if not token:
            raise ValueError("GitHub token must be non-empty")
        if api_base.rstrip("/") != GITHUB_API_BASE:
            raise ValueError("GitHub API origin must be the official HTTPS endpoint")
        self._token = token
        self._transport = transport or _UrlLibTransport()
        self._api_base = GITHUB_API_BASE

    def recent_deployments(self, repository: str, since: datetime) -> tuple[Deployment, ...]:
        _require_repository(repository)
        if since.tzinfo is None or since.utcoffset() is None:
            raise ValueError("since must be timezone-aware")
        query = urlencode({"environment": "dev", "per_page": MAX_DEPLOYMENTS})
        url = f"{self._api_base}/repos/{repository}/deployments?{query}"
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self._token}",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        try:
            response = self._transport.request("GET", url, headers, None, REQUEST_TIMEOUT_SECONDS)
        except (OSError, TimeoutError):
            raise IntegrationError("GitHub request failed") from None
        if response.status != 200 or len(response.body) > MAX_RESPONSE_BYTES:
            raise IntegrationError("GitHub request failed")

        try:
            raw = json.loads(response.body)
            if not isinstance(raw, list):
                raise TypeError
            deployments = tuple(_parse_deployment(item) for item in raw)
        except (UnicodeError, ValueError, TypeError, KeyError):
            raise IntegrationError("GitHub response was invalid") from None

        threshold = since.astimezone(UTC)
        matching = (
            item
            for item in deployments
            if item.environment == "dev" and item.created_at.astimezone(UTC) >= threshold
        )
        return tuple(
            sorted(matching, key=lambda item: item.created_at, reverse=True)[:MAX_DEPLOYMENTS]
        )

    def changed_files(self, repository: str, limit: int) -> tuple[ChangedFile, ...]:
        _require_repository(repository)
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= MAX_CHANGED_FILES
        ):
            raise ValueError("changed file limit must be between 1 and 100")
        query = urlencode({"per_page": limit})
        url = f"{self._api_base}/repos/{repository}/commits/HEAD?{query}"
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self._token}",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        try:
            response = self._transport.request("GET", url, headers, None, REQUEST_TIMEOUT_SECONDS)
        except (OSError, TimeoutError):
            raise IntegrationError("GitHub request failed") from None
        if response.status != 200 or len(response.body) > MAX_RESPONSE_BYTES:
            raise IntegrationError("GitHub request failed")
        try:
            raw = json.loads(response.body)
            if not isinstance(raw, dict) or not isinstance(raw.get("files"), list):
                raise TypeError
            files = tuple(_parse_changed_file(item) for item in raw["files"])
        except (UnicodeError, ValueError, TypeError, KeyError):
            raise IntegrationError("GitHub response was invalid") from None
        return files[:limit]

    def __repr__(self) -> str:
        return "GitHubClient(redacted=True)"


def _parse_deployment(raw: object) -> Deployment:
    if not isinstance(raw, dict):
        raise TypeError
    deployment_id = raw["id"]
    environment = raw["environment"]
    revision = raw.get("sha", raw.get("ref"))
    created_at = raw["created_at"]
    if isinstance(deployment_id, bool) or not isinstance(deployment_id, int | str):
        raise TypeError
    if not isinstance(environment, str) or not isinstance(revision, str):
        raise TypeError
    if not isinstance(created_at, str):
        raise TypeError
    parsed_time = datetime.fromisoformat(created_at.replace("Z", "+00:00"))
    if parsed_time.tzinfo is None or parsed_time.utcoffset() is None:
        raise ValueError
    return Deployment(
        deployment_id=str(deployment_id),
        environment=environment,
        revision=revision,
        created_at=parsed_time,
    )


def _parse_changed_file(raw: object) -> ChangedFile:
    if not isinstance(raw, dict):
        raise TypeError
    path = raw.get("filename")
    status = raw.get("status")
    if not isinstance(path, str) or not path or not isinstance(status, str) or not status:
        raise TypeError
    return ChangedFile(path=path, status=status)


def _require_repository(repository: str) -> None:
    segments = repository.split("/")
    if _REPOSITORY_PATTERN.fullmatch(repository) is None or any(
        segment in {".", ".."} for segment in segments
    ):
        raise ValueError("repository must be an owner/name pair")
