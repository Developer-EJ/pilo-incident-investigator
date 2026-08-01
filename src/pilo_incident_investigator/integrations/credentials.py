"""Isolated loading for the two service-owned SSM SecureString values."""

from typing import Any, Protocol

from botocore.exceptions import BotoCoreError, ClientError


class CredentialError(RuntimeError):
    """Raised without carrying credential values or remote error messages."""


class SsmClient(Protocol):
    def get_parameter(self, **kwargs: Any) -> dict[str, Any]: ...


class SsmCredentialProvider:
    __slots__ = ("_client", "_github_name", "_slack_name", "_cache")

    def __init__(self, client: SsmClient, github_name: str, slack_name: str) -> None:
        if not github_name.strip() or not slack_name.strip():
            raise ValueError("SSM parameter names must be non-empty")
        if github_name == slack_name:
            raise ValueError("SSM parameter names must be distinct")
        self._client = client
        self._github_name = github_name
        self._slack_name = slack_name
        self._cache: dict[str, str] = {}

    def github_token(self) -> str:
        return self._load(self._github_name)

    def slack_webhook_url(self) -> str:
        return self._load(self._slack_name)

    def _load(self, name: str) -> str:
        if name in self._cache:
            return self._cache[name]
        try:
            response = self._client.get_parameter(Name=name, WithDecryption=True)
            value = response["Parameter"]["Value"]
        except (BotoCoreError, ClientError, KeyError, TypeError):
            raise CredentialError("credential unavailable") from None
        if not isinstance(value, str) or not value:
            raise CredentialError("credential unavailable")
        self._cache[name] = value
        return value

    def __repr__(self) -> str:
        return "SsmCredentialProvider(redacted=True)"
