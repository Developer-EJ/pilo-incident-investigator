from __future__ import annotations

from pathlib import Path

RUNBOOK = Path(__file__).parents[2] / "docs" / "runbooks" / "investigator-operations.md"


def test_operations_runbook_covers_metrics_and_safety_boundaries() -> None:
    text = RUNBOOK.read_text(encoding="utf-8")

    for required in (
        "## Alert Brief 읽기",
        "## 지표 확인",
        "## 실패 대응",
        "## 안전 경계",
        "PILO/IncidentInvestigator",
        "EventsReceived",
        "IncidentsPublished",
        "IncidentsDegraded",
        "IncidentsFailed",
        "CollectorFailures",
        "ProcessingDuration",
        "snapshot_only",
        "자동 복구",
        "GetSecretValue",
        "Evidence",
        "EventBridge retry",
        "idempotency",
    ):
        assert required in text


def test_operations_runbook_states_delivery_sources_of_record() -> None:
    text = RUNBOOK.read_text(encoding="utf-8")

    assert "Agent 출력은 가설" in text
    assert "degraded Slack" in text
    assert "Issue가 source of record" in text
