from __future__ import annotations

from pathlib import Path

RUNBOOK = Path(__file__).parents[2] / "docs" / "runbooks" / "dev-smoke-test.md"


def test_dynamodb_filter_uses_windows_safe_cli_shorthand() -> None:
    text = RUNBOOK.read_text(encoding="utf-8")

    assert '$dynamoValues = ":incident_id={S=$incidentId}"' in text
    assert '$dynamoValues = @{ ":incident_id"' not in text


def test_smoke_runbook_requires_manual_brief_field_confirmation_without_persisting_values() -> None:
    text = RUNBOOK.read_text(encoding="utf-8")

    assert "서비스, Alarm, 확인된 사실, 정보 공백, private Issue 링크" in text
    assert "입력·출력·저장하지 않는다" in text
