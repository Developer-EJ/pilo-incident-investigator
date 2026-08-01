from __future__ import annotations

from pathlib import Path

RUNBOOK = Path(__file__).parents[2] / "docs" / "runbooks" / "dev-smoke-test.md"


def test_dynamodb_filter_uses_windows_safe_cli_shorthand() -> None:
    text = RUNBOOK.read_text(encoding="utf-8")

    assert '$dynamoValues = ":incident_id={S=$incidentId}"' in text
    assert '$dynamoValues = @{ ":incident_id"' not in text
