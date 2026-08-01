import json
from datetime import datetime, timedelta, timezone

import pytest

from pilo_incident_investigator.bundle import canonical_bundle_json
from pilo_incident_investigator.domain import (
    AlarmEvent,
    Evidence,
    IncidentBundle,
    Investigation,
    Snapshot,
    SupportedStatement,
)
from pilo_incident_investigator.redaction import UnsafeBundleError

KST = timezone(timedelta(hours=9))
OBSERVED = datetime(2026, 8, 1, 9, 30, tzinfo=KST)


def _bundle(*, evidence_id: str = "E-한글") -> IncidentBundle:
    investigation = Investigation(
        facts=(SupportedStatement("서비스 오류를 확인했습니다.", (evidence_id,)),),
        directions=(SupportedStatement("로그를 비교합니다.", (evidence_id,)),),
        missing=(),
        classification="애플리케이션 오류",
        tool_calls=(),
        classification_evidence_ids=(evidence_id,),
    )
    return IncidentBundle(
        incident_id="inc-한글",
        alarm=AlarmEvent(
            event_id="evt-001",
            alarm_arn="synthetic",
            alarm_name="한글 알람",
            state_timestamp=OBSERVED,
            detail={"z": 1, "a": {"나": "값", "가": "값"}},
        ),
        snapshot=Snapshot(
            "inc-한글",
            (Evidence(evidence_id, "ecs", OBSERVED, "오류", {"z": 2, "a": 1}),),
            (),
        ),
        investigation=investigation,
        created_at=OBSERVED,
        metadata={"z": "last", "a": "first"},
    )


def test_canonical_bundle_json_is_stable_utf8_sorted_and_utc() -> None:
    first = canonical_bundle_json(_bundle())
    second = canonical_bundle_json(_bundle())

    assert first == second
    assert b"\\u" not in first
    decoded = first.decode("utf-8")
    assert "한글 알람" in decoded
    assert '"a":"first","z":"last"' in decoded
    assert "2026-08-01T00:30:00Z" in decoded
    assert not decoded.endswith("\n")
    assert json.loads(decoded)["incident_id"] == "inc-한글"


def test_canonical_bundle_json_redacts_secrets_before_returning_bytes() -> None:
    bundle = _bundle()
    bundle.metadata["credential"] = "ghp_abcdefghijklmnopqrstuvwxyz123456"

    payload = canonical_bundle_json(bundle)

    assert b"ghp_" not in payload
    assert b"REDACTED" in payload


def test_canonical_bundle_json_returns_no_bytes_for_invalid_citations() -> None:
    bundle = _bundle(evidence_id="E-001")
    invalid = Investigation(
        facts=(SupportedStatement("잘못된 주장", ("E-999",)),),
        directions=(),
        missing=(),
        classification="unclassified",
        tool_calls=(),
    )
    bundle = IncidentBundle(
        bundle.incident_id,
        bundle.alarm,
        bundle.snapshot,
        invalid,
        bundle.created_at,
        bundle.metadata,
    )

    with pytest.raises(UnsafeBundleError) as caught:
        canonical_bundle_json(bundle)

    assert "E-999" not in str(caught.value)
