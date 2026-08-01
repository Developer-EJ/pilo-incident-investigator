import traceback
from typing import Any

from botocore.exceptions import ClientError

from pilo_incident_investigator.integrations.credentials import (
    CredentialError,
    SsmCredentialProvider,
)


class FakeSsmClient:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.values = {
            "/pilo-incident-investigator/dev/github-token": "synthetic-github-token",
            "/pilo-incident-investigator/dev/slack-webhook-url": "synthetic-slack-webhook",
        }

    def get_parameter(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(kwargs)
        return {"Parameter": {"Value": self.values[kwargs["Name"]]}}


def provider(client: FakeSsmClient) -> SsmCredentialProvider:
    return SsmCredentialProvider(
        client,
        "/pilo-incident-investigator/dev/github-token",
        "/pilo-incident-investigator/dev/slack-webhook-url",
    )


def test_credentials_are_loaded_with_decryption_and_cached_separately() -> None:
    client = FakeSsmClient()
    credentials = provider(client)

    assert credentials.github_token() == "synthetic-github-token"
    assert credentials.github_token() == "synthetic-github-token"
    assert credentials.slack_webhook_url() == "synthetic-slack-webhook"
    assert client.calls == [
        {
            "Name": "/pilo-incident-investigator/dev/github-token",
            "WithDecryption": True,
        },
        {
            "Name": "/pilo-incident-investigator/dev/slack-webhook-url",
            "WithDecryption": True,
        },
    ]


def test_credential_provider_repr_never_contains_values() -> None:
    client = FakeSsmClient()
    credentials = provider(client)
    credentials.github_token()
    credentials.slack_webhook_url()

    rendered = repr(credentials)
    assert rendered == "SsmCredentialProvider(redacted=True)"
    assert "synthetic-github-token" not in rendered
    assert "synthetic-slack-webhook" not in rendered


def test_ssm_error_traceback_does_not_expose_remote_message() -> None:
    sensitive_marker = "SENSITIVE-SSM-MARKER"

    class FailingSsmClient(FakeSsmClient):
        def get_parameter(self, **kwargs: Any) -> dict[str, Any]:
            raise ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": sensitive_marker}},
                "GetParameter",
            )

    credentials = provider(FailingSsmClient())

    try:
        credentials.github_token()
    except CredentialError as error:
        rendered = "".join(traceback.format_exception(error))
        assert sensitive_marker not in rendered
        assert "credential unavailable" in rendered
    else:
        raise AssertionError("CredentialError must be raised")


def test_parameter_names_must_be_non_empty_and_distinct() -> None:
    client = FakeSsmClient()

    for github_name, slack_name in (("", "/slack"), ("/same", "/same")):
        try:
            SsmCredentialProvider(client, github_name, slack_name)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid parameter names must be rejected")
