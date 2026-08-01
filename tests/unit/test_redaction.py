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


@pytest.mark.parametrize(
    ("secret", "category"),
    [
        ("xoxb-1234567890-secret", "SLACK_TOKEN"),
        ("ghp_abcdefghijklmnopqrstuvwxyz123456", "GITHUB_TOKEN"),
        ("github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz", "GITHUB_TOKEN"),
        ("password=hunter2", "CREDENTIAL_ASSIGNMENT"),
        ("AKIAABCDEFGHIJKLMNOP", "AWS_ACCESS_KEY"),
        ("Authorization: Bearer abc.def.ghi", "AUTHORIZATION"),
        ("https://hooks.slack.com/services/T000/B000/WEBHOOK", "WEBHOOK_URL"),
        ("https://example.invalid/path?access_token=query-secret", "QUERY_CREDENTIAL"),
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


def test_redact_bundle_fails_closed_without_echoing_invalid_value() -> None:
    bundle = _bundle_with_secrets()
    bundle.metadata["invalid"] = object()  # type: ignore[assignment]

    with pytest.raises(UnsafeBundleError) as caught:
        Redactor().redact_bundle(bundle)

    assert "object" not in str(caught.value)
    assert "opaque-metadata-value" not in repr(caught.value)
