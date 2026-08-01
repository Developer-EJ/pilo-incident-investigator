from copy import deepcopy
from datetime import UTC, datetime

import pytest

from pilo_incident_investigator.domain import (
    AlarmEvent,
    CollectorFailure,
    Evidence,
    IncidentBundle,
    Investigation,
    JsonValue,
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
        "nested": ["opaque-two", {"last": "[REDACTED:SENSITIVE_FIELD]"}],
    }

    redacted, report = Redactor().redact_bundle(bundle)
    redacted_again, second_report = Redactor().redact_bundle(redacted)

    assert redacted.metadata["clientSecret"] == {
        "first": "[REDACTED:SENSITIVE_FIELD]",
        "nested": [
            "[REDACTED:SENSITIVE_FIELD]",
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
    ("value", "key"),
    [
        ('password="hunter\nsecond tail"', "password"),
        ("secret='hunter\nsecond tail'", "secret"),
        ('password="hunter\\\nsecond tail"', "password"),
        ("secret='hunter\\\nsecond tail'", "secret"),
    ],
)
def test_closed_multiline_quoted_assignment_is_fully_redacted(value: str, key: str) -> None:
    redacted, report = Redactor().redact_text(value)
    redacted_again, second_report = Redactor().redact_text(redacted)

    assert redacted == f"{key}=[REDACTED:CREDENTIAL]"
    assert "hunter" not in redacted
    assert "tail" not in redacted
    assert report.categories == (("CREDENTIAL_ASSIGNMENT", 1),)
    assert redacted_again == redacted
    assert second_report.replacements == 0


@pytest.mark.parametrize(
    ("value", "key"),
    [
        ('password="hunter\nsecond tail', "password"),
        ("secret='hunter\nsecond tail", "secret"),
        ('password="hunter\\\nsecond tail', "password"),
        ("secret='hunter\\\nsecond tail", "secret"),
        ('password="hunter\nsecond tail\\', "password"),
        ("secret='hunter\nsecond tail\\", "secret"),
    ],
)
def test_unclosed_multiline_quoted_assignment_redacts_through_end(value: str, key: str) -> None:
    redacted, report = Redactor().redact_text(value)
    redacted_again, second_report = Redactor().redact_text(redacted)

    assert redacted == f"{key}=[REDACTED:CREDENTIAL]"
    assert "hunter" not in redacted
    assert "tail" not in redacted
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


@pytest.mark.parametrize(
    "value",
    [
        {"token": "synthetic-opaque-value"},
        {"nested": {"password": "synthetic-opaque-value"}},
        {"items": [{"clientSecret": ["synthetic-opaque-value"]}]},
        {"awsSecretAccessKey": {"part": "synthetic-opaque-value"}},
    ],
)
def test_redact_json_uses_sensitive_key_context_for_opaque_values(value: object) -> None:
    redacted, report = Redactor().redact_json(value)  # type: ignore[arg-type]

    assert redacted != value
    assert report.replacements > 0
    assert "synthetic-opaque-value" not in repr(redacted)


def test_redact_json_preserves_redacted_sentinels_and_rotation_metadata() -> None:
    value: JsonValue = {
        "password": "[REDACTED:SENSITIVE_FIELD]",
        "rotation_enabled": True,
        "last_rotated_at": "2026-01-01T00:00:00Z",
        "next_rotation_at": None,
    }

    redacted, report = Redactor().redact_json(value)

    assert redacted == value
    assert report.replacements == 0


@pytest.mark.parametrize(
    "value",
    [
        {"token": 123456789},
        {"password": True},
        {"password": None},
        {"clientSecret": [{"part": 7}]},
        {"clientSecret": []},
        {"clientSecret": {}},
    ],
)
def test_redact_json_fails_closed_for_non_string_or_empty_sensitive_values(
    value: JsonValue,
) -> None:
    with pytest.raises(UnsafeBundleError) as captured:
        Redactor().redact_json(value)

    rendered = repr(captured.value)
    assert "123456789" not in rendered
    assert "clientSecret" not in rendered


def test_redact_json_accepts_only_approved_sentinels_in_sensitive_containers() -> None:
    value: JsonValue = {
        "clientSecret": [
            "[REDACTED:SENSITIVE_FIELD]",
            {"nested": "[REDACTED:SENSITIVE_FIELD]"},
        ]
    }

    redacted, report = Redactor().redact_json(value)

    assert redacted == value
    assert report.replacements == 0


def test_redact_json_preserves_non_sensitive_primitives_and_empty_containers() -> None:
    value: JsonValue = {
        "count": 3,
        "enabled": True,
        "ratio": 1.25,
        "missing": None,
        "items": [],
        "details": {},
    }

    redacted, report = Redactor().redact_json(value)

    assert redacted == value
    assert report.replacements == 0
    assert isinstance(redacted, dict)
    assert type(redacted["count"]) is int
    assert type(redacted["enabled"]) is bool
    assert type(redacted["ratio"]) is float


def test_redact_json_preserves_secret_rotation_metadata_primitives() -> None:
    value: JsonValue = {
        "rotation_enabled": True,
        "rotation_interval_days": 30,
        "rotation_progress": 0.5,
        "last_rotated_at": "2026-01-01T00:00:00Z",
        "next_rotation_at": None,
    }

    redacted, report = Redactor().redact_json(value)

    assert redacted == value
    assert report.replacements == 0


@pytest.mark.parametrize(
    "message",
    [
        '{"password":"opaque-secret"}',
        r"{\"password\":\"opaque-secret\"}",
    ],
)
def test_redact_json_detects_embedded_json_credentials_in_log_strings(message: str) -> None:
    value: JsonValue = {"message": message}

    redacted, report = Redactor().redact_json(value)

    assert redacted != value
    assert report.replacements > 0
    assert "opaque-secret" not in repr(redacted)


def test_redact_json_preserves_safe_structured_log_strings() -> None:
    value: JsonValue = {
        "message": '{"status":"healthy","rotation_enabled":true}',
    }

    redacted, report = Redactor().redact_json(value)

    assert redacted == value
    assert report.replacements == 0


@pytest.mark.parametrize("wrapper", ["secrets", "tokens", "passwords", "clientSecrets"])
def test_plural_sensitive_wrappers_create_sensitive_context(wrapper: str) -> None:
    value: JsonValue = {wrapper: {"database": "opaque-secret"}}

    redacted, report = Redactor().redact_json(value)

    assert redacted != value
    assert report.replacements == 1
    assert "opaque-secret" not in repr(redacted)


@pytest.mark.parametrize(
    "sentinel",
    ["[REDACTED:UNAPPROVED]", "[REDACTED:FAKE]"],
)
def test_unapproved_redaction_sentinel_is_not_idempotently_trusted(sentinel: str) -> None:
    value: JsonValue = {"clientSecret": {"nested": sentinel}}

    redacted, report = Redactor().redact_json(value)

    assert redacted == {"clientSecret": {"nested": "[REDACTED:SENSITIVE_FIELD]"}}
    assert report.replacements == 1


@pytest.mark.parametrize(
    "message",
    [
        '{"password":123456}',
        '{"password":true}',
        '{"password":null}',
        '{"password":{"part":7}}',
        '{"password":["opaque-secret",7]}',
        r'{"password":123456}',
        '{"outer":"{\\"password\\":123456}"}',
    ],
)
def test_embedded_json_non_string_sensitive_values_fail_closed(message: str) -> None:
    value: JsonValue = {"message": message}

    with pytest.raises(UnsafeBundleError) as captured:
        Redactor().redact_json(value)

    assert "123456" not in repr(captured.value)
    assert "opaque-secret" not in repr(captured.value)


def test_embedded_json_spaced_sensitive_key_is_redacted() -> None:
    value: JsonValue = {"message": '{"client secret":"opaque-secret"}'}

    redacted, report = Redactor().redact_json(value)

    assert redacted != value
    assert report.replacements == 1
    assert "opaque-secret" not in repr(redacted)


def test_non_json_prose_with_braced_example_is_not_parsed_or_redacted() -> None:
    value: JsonValue = {"message": 'prefix {"password":123456} suffix'}

    redacted, report = Redactor().redact_json(value)

    assert redacted == value
    assert report.replacements == 0


@pytest.mark.parametrize("wrapper", ["secret_rotation_metadata", "secrets_rotation_metadata"])
def test_secret_rotation_metadata_wrapper_is_narrowly_safe(wrapper: str) -> None:
    value: JsonValue = {
        wrapper: {
            "last_rotated_at": "2026-01-01T00:00:00Z",
            "rotation_enabled": True,
        }
    }

    redacted, report = Redactor().redact_json(value)

    assert redacted == value
    assert report.replacements == 0


def test_secret_rotation_metadata_wrapper_does_not_exempt_nested_credentials() -> None:
    value: JsonValue = {
        "secret_rotation_metadata": {"password": "opaque-secret"},
    }

    redacted, report = Redactor().redact_json(value)

    assert redacted != value
    assert report.replacements == 1
    assert "opaque-secret" not in repr(redacted)
