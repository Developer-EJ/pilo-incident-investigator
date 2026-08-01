from copy import deepcopy
from datetime import UTC, datetime

import pytest

from pilo_incident_investigator.domain import (
    AlarmEvent,
    CollectorFailure,
    Evidence,
    IncidentBundle,
    Investigation,
    Snapshot,
    SupportedStatement,
    ToolRequest,
    ToolResult,
)
from pilo_incident_investigator.redaction import Redactor, UnsafeBundleError

NOW = datetime(2026, 8, 1, tzinfo=UTC)


def _bundle_with_secrets() -> IncidentBundle:
    snapshot_evidence = Evidence(
        evidence_id="E-SNAPSHOT",
        source="logs token=source-value",
        observed_at=NOW,
        summary="Slack xoxb-1234567890-secret",
        data={"nested": ["password=hunter2", 7, True, None]},
    )
    tool_evidence = Evidence(
        evidence_id="E-TOOL",
        source="rds.events",
        observed_at=NOW,
        summary="authorization Bearer abc.def.ghi",
        data={"url": "https://example.invalid/path?api_key=query-secret"},
    )
    request = ToolRequest(
        tool="service_log_search",
        resource_key="ghp_abcdefghijklmnopqrstuvwxyz123456",
        parameters={"filter": "secret=parameter-value"},
        reason="Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
    )
    result = ToolResult(
        request=request,
        evidence=(tool_evidence,),
        failure=CollectorFailure(
            collector="tool token=collector-value",
            code="AKIAABCDEFGHIJKLMNOP",
            detail="https://hooks.slack.com/services/T000/B000/WEBHOOK",
        ),
    )
    return IncidentBundle(
        incident_id="inc-safe",
        alarm=AlarmEvent(
            event_id="evt token=event-value",
            alarm_arn="arn token=alarm-value",
            alarm_name="alarm passwd=name-value",
            state_timestamp=NOW,
            detail={"authorization": "Bearer alarm-secret", "count": 2},
        ),
        snapshot=Snapshot(
            incident_id="inc-safe",
            evidence=(snapshot_evidence,),
            failures=(CollectorFailure("collector", "token=code-value", "secret=detail-value"),),
        ),
        investigation=Investigation(
            facts=(SupportedStatement("fact xoxp-1234-secret", ("E-SNAPSHOT",)),),
            directions=(SupportedStatement("direction token=value", ("E-TOOL",)),),
            missing=("missing ghp_abcdefghijklmnopqrstuvwxyz123456",),
            classification="runtime password=classification-value",
            tool_calls=(result,),
            classification_evidence_ids=("E-SNAPSHOT",),
        ),
        created_at=NOW,
        metadata={"token": "opaque-metadata-value", "mode": "hybrid_agent"},
    )


def _safe_bundle() -> IncidentBundle:
    evidence = Evidence("E-001", "ecs", NOW, "running=0", {"running": 0})
    return IncidentBundle(
        incident_id="inc-safe",
        alarm=AlarmEvent("evt-safe", "synthetic", "alarm", NOW, {"state": "ALARM"}),
        snapshot=Snapshot("inc-safe", (evidence,), ()),
        investigation=Investigation(
            facts=(SupportedStatement("running count observed", ("E-001",)),),
            directions=(),
            missing=(),
            classification="unclassified",
            tool_calls=(),
        ),
        created_at=NOW,
        metadata={},
    )


@pytest.mark.parametrize(
    ("secret", "category"),
    [
        ("xoxb-1234567890-secret", "SLACK_TOKEN"),
        ("xapp-1-A1234567890-opaque", "SLACK_TOKEN"),
        ("ghp_abcdefghijklmnopqrstuvwxyz123456", "GITHUB_TOKEN"),
        ("github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz", "GITHUB_TOKEN"),
        ("password=hunter2", "CREDENTIAL_ASSIGNMENT"),
        ("AKIAABCDEFGHIJKLMNOP", "AWS_ACCESS_KEY"),
        ("ASIAABCDEFGHIJKLMNOP", "AWS_ACCESS_KEY"),
        ("Authorization: Bearer abc.def.ghi", "AUTHORIZATION"),
        ("Bearer standalone-token", "AUTHORIZATION"),
        ("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==", "AUTHORIZATION"),
        ("https://hooks.slack.com/services/T000/B000/WEBHOOK", "WEBHOOK_URL"),
        ("https://example.invalid/path?access_token=query-secret", "QUERY_CREDENTIAL"),
        ("https://example.invalid/path?clientSecret=query-secret", "QUERY_CREDENTIAL"),
        ("https://example.invalid/path?passwd=query-secret", "QUERY_CREDENTIAL"),
        (
            "https://example.invalid/path?awsSecretAccessKey=query-secret",
            "QUERY_CREDENTIAL",
        ),
        ('password="hunter two"', "CREDENTIAL_ASSIGNMENT"),
    ],
)
def test_redact_text_removes_each_credential_shape(secret: str, category: str) -> None:
    redacted, report = Redactor().redact_text(f"request failed: {secret}")

    assert secret not in redacted
    assert report.replacements == 1
    assert report.categories == ((category, 1),)
    assert secret not in repr(report)


def test_redact_bundle_recurses_without_mutating_or_changing_evidence_ids() -> None:
    bundle = _bundle_with_secrets()
    original = deepcopy(bundle)

    redacted, report = Redactor().redact_bundle(bundle)
    redacted_again, second_report = Redactor().redact_bundle(redacted)

    assert bundle == original
    assert redacted == redacted_again
    assert second_report.replacements == 0
    assert report.replacements > 10
    assert redacted.snapshot.evidence[0].evidence_id == "E-SNAPSHOT"
    assert redacted.investigation.facts[0].evidence_ids == ("E-SNAPSHOT",)
    assert redacted.investigation.classification_evidence_ids == ("E-SNAPSHOT",)
    assert redacted.incident_id == "inc-safe"
    assert redacted.snapshot.evidence[0].data["nested"][1:] == [7, True, None]  # type: ignore[index]
    serialized = repr(redacted)
    for secret in (
        "hunter2",
        "alarm-secret",
        "query-secret",
        "opaque-metadata-value",
        "QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
    ):
        assert secret not in serialized


def test_query_token_is_counted_once_and_remains_idempotent() -> None:
    value = "https://example.invalid/path?token=query-secret"

    redacted, report = Redactor().redact_text(value)
    redacted_again, second_report = Redactor().redact_text(redacted)

    assert report.replacements == 1
    assert redacted_again == redacted
    assert second_report.replacements == 0


@pytest.mark.parametrize(
    ("value", "category"),
    [
        ("xapp-1-A1234567890-opaque", "SLACK_TOKEN"),
        ("https://example.invalid/?passwd=opaque-value", "QUERY_CREDENTIAL"),
        (
            "https://example.invalid/?awsSecretAccessKey=opaque-value",
            "QUERY_CREDENTIAL",
        ),
        (
            "https://example.invalid/?aws_secret_access_key=opaque-value",
            "QUERY_CREDENTIAL",
        ),
    ],
)
def test_additional_credential_shapes_are_counted_once_and_idempotent(
    value: str, category: str
) -> None:
    redacted, report = Redactor().redact_text(value)
    redacted_again, second_report = Redactor().redact_text(redacted)

    assert report.categories == ((category, 1),)
    assert redacted_again == redacted
    assert second_report.replacements == 0


@pytest.mark.parametrize(
    "key",
    [
        "client_secret",
        "clientSecret",
        "access_token",
        "aws_secret_access_key",
        "x-api-key",
        "api-key",
        "api_key",
        "refresh_token",
        "id_token",
        "auth_token",
        "authorization",
        "webhook_url",
        "private_key",
        "credential",
        "credentials",
        "password",
        "passwd",
        "secret",
        "token",
    ],
)
def test_sensitive_key_normalization_redacts_opaque_values(key: str) -> None:
    bundle = _safe_bundle()
    bundle.metadata[key] = "opaque value with spaces"

    redacted, report = Redactor().redact_bundle(bundle)

    assert redacted.metadata[key] == "[REDACTED:SENSITIVE_FIELD]"
    assert report.categories == (("SENSITIVE_FIELD", 1),)


def test_sensitive_container_redacts_each_string_leaf_and_preserves_shape() -> None:
    bundle = _safe_bundle()
    bundle.metadata["clientSecret"] = {
        "first": "opaque-one",
        "nested": ["opaque-two", 3, False, None, {"last": "[REDACTED:SENSITIVE_FIELD]"}],
    }

    redacted, report = Redactor().redact_bundle(bundle)
    redacted_again, second_report = Redactor().redact_bundle(redacted)

    assert redacted.metadata["clientSecret"] == {
        "first": "[REDACTED:SENSITIVE_FIELD]",
        "nested": [
            "[REDACTED:SENSITIVE_FIELD]",
            3,
            False,
            None,
            {"last": "[REDACTED:SENSITIVE_FIELD]"},
        ],
    }
    assert report.categories == (("SENSITIVE_FIELD", 2),)
    assert redacted_again == redacted
    assert second_report.replacements == 0


@pytest.mark.parametrize(
    "key",
    ["github_token", "dbPassword", "service-secret", "SecretString", "apiKeyValue"],
)
def test_sensitive_key_tokenization_redacts_prefixed_and_suffixed_names(key: str) -> None:
    bundle = _safe_bundle()
    bundle.metadata[key] = "opaque-value"

    redacted, report = Redactor().redact_bundle(bundle)

    assert redacted.metadata[key] == "[REDACTED:SENSITIVE_FIELD]"
    assert report.categories == (("SENSITIVE_FIELD", 1),)


@pytest.mark.parametrize(
    "key",
    ["monkey", "secretary", "api_version", "private_subnet", "refresh_interval"],
)
def test_key_tokenization_does_not_redact_normal_context(key: str) -> None:
    bundle = _safe_bundle()
    bundle.metadata[key] = "ordinary-value"

    redacted, report = Redactor().redact_bundle(bundle)

    assert redacted.metadata[key] == "ordinary-value"
    assert report.replacements == 0


def test_contextual_credential_assignment_redacts_quoted_value() -> None:
    value = 'dbPassword="hunter two words"'

    redacted, report = Redactor().redact_text(value)

    assert "hunter" not in redacted
    assert report.categories == (("CREDENTIAL_ASSIGNMENT", 1),)


@pytest.mark.parametrize(
    "value",
    [r'password="hunter\"tail"', r"secret='hunter\'tail'"],
)
def test_escaped_quoted_assignment_removes_the_entire_value(value: str) -> None:
    redacted, report = Redactor().redact_text(value)
    redacted_again, second_report = Redactor().redact_text(redacted)

    assert redacted == f"{value.split('=', 1)[0]}=[REDACTED:CREDENTIAL]"
    assert report.categories == (("CREDENTIAL_ASSIGNMENT", 1),)
    assert redacted_again == redacted
    assert second_report.replacements == 0


@pytest.mark.parametrize(
    "text",
    [
        "basic snapshot status",
        "Basic investigation workflow",
        "bearer task count",
        "bearer snapshot status",
        "bearer investigation workflow",
        "Bearer abcdefghijklm",
    ],
)
def test_authorization_scheme_words_in_normal_text_are_not_redacted(text: str) -> None:
    redacted, report = Redactor().redact_text(text)

    assert redacted == text
    assert report.replacements == 0


@pytest.mark.parametrize(
    "text",
    [
        "Bearer abc.def.ghi",
        "Bearer eyJhbGciOiJIUzI1NiJ9.payload.signature",
        "Bearer abcdefghijklmnopqrstuvwxyz",
        "Bearer abcdefghijklmn",
        "Bearer abcdefghijklmno",
        "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
        "Basic dXNlcjpwYXNz",
    ],
)
def test_standalone_credential_shaped_authorization_is_redacted(text: str) -> None:
    redacted, report = Redactor().redact_text(text)

    assert text not in redacted
    assert report.categories == (("AUTHORIZATION", 1),)


@pytest.mark.parametrize(
    "text",
    [
        "Bearer abcdefghijklmnopqrstuvwxyz",
        "Bearer abc.def.ghi",
        "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
        "Basic dXNlcjpwYXNz",
    ],
)
def test_standalone_authorization_redaction_is_idempotent_and_counted_once(text: str) -> None:
    redacted, report = Redactor().redact_text(text)
    redacted_again, second_report = Redactor().redact_text(redacted)

    assert report.categories == (("AUTHORIZATION", 1),)
    assert redacted_again == redacted
    assert second_report.replacements == 0


@pytest.mark.parametrize("text", ["Basic dXNlcg==", "Basic not-valid-base64!"])
def test_basic_without_decoded_userinfo_is_not_redacted(text: str) -> None:
    redacted, report = Redactor().redact_text(text)

    assert redacted == text
    assert report.replacements == 0


@pytest.mark.parametrize(
    "key",
    [
        "dbPassword",
        "service-secret",
        "github_token",
        "SecretString",
        "apiKeyValue",
        "awsSecretAccessKey",
    ],
)
def test_query_uses_sensitive_key_tokenization(key: str) -> None:
    value = f"https://example.invalid/path?{key}=opaque-value"

    redacted, report = Redactor().redact_text(value)
    redacted_again, second_report = Redactor().redact_text(redacted)

    assert redacted == f"https://example.invalid/path?{key}=[REDACTED:QUERY_CREDENTIAL]"
    assert report.categories == (("QUERY_CREDENTIAL", 1),)
    assert redacted_again == redacted
    assert second_report.replacements == 0


@pytest.mark.parametrize(
    "key",
    ["status", "api_version", "private_subnet", "refresh_interval", "secretary"],
)
def test_query_leaves_normal_key_context_unchanged(key: str) -> None:
    value = f"https://example.invalid/path?{key}=ordinary-value"

    redacted, report = Redactor().redact_text(value)

    assert redacted == value
    assert report.replacements == 0


def test_redact_bundle_fails_closed_without_echoing_invalid_value() -> None:
    bundle = _bundle_with_secrets()
    bundle.metadata["invalid"] = object()  # type: ignore[assignment]

    with pytest.raises(UnsafeBundleError) as caught:
        Redactor().redact_bundle(bundle)

    assert "object" not in str(caught.value)
    assert "opaque-metadata-value" not in repr(caught.value)
