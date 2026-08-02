"""Contract tests for the protected application Alarm route runbook."""

from pathlib import Path

RUNBOOK = Path(__file__).parents[2] / "docs" / "runbooks" / "application-alarm-route.md"


def read_runbook() -> str:
    return RUNBOOK.read_text(encoding="utf-8")


def test_runbook_updates_topology_before_event_route() -> None:
    text = read_runbook()

    assert text.index("validate-transition") < text.index("s3api put-object")
    assert text.index("s3api put-object") < text.index("terraform -chdir=infra plan")
    assert text.index("validate-plan") < text.index("terraform -chdir=infra apply")


def test_runbook_never_mutates_application_alarms() -> None:
    text = read_runbook().lower()

    assert "set-alarm-state" not in text
    assert "put-metric-alarm" not in text
    assert "delete-alarms" not in text
    assert "-target" not in text


def test_runbook_requires_protected_inputs_and_dev_preflight() -> None:
    text = read_runbook()

    for name in (
        "PILO_DEV_ACCOUNT_ID",
        "PILO_BASELINE_TOPOLOGY_FILE",
        "PILO_CANDIDATE_TOPOLOGY_FILE",
        "PILO_NEW_ALARM_MAPPINGS_FILE",
        "PILO_TOPOLOGY_BUCKET",
        "PILO_TOPOLOGY_KEY",
        "PILO_EVENT_RULE_NAME",
        "PILO_LAMBDA_FUNCTION_NAME",
        "PILO_DEPLOY_TFVARS_FILE",
    ):
        assert name in text
    assert "Set-StrictMode -Version Latest" in text
    assert "$ErrorActionPreference = 'Stop'" in text
    assert "aws sts get-caller-identity" in text
    assert "ap-northeast-2" in text


def test_runbook_requires_exact_route_safety_settings() -> None:
    text = read_runbook()

    assert "26" in text
    assert "8" in text
    assert "34" in text
    assert 'operating_mode="snapshot_only"' in text
    assert "lambda_reserved_concurrency=2" in text
    assert "event_route_enabled=true" in text


def test_runbook_validates_checksum_and_reuses_saved_plan() -> None:
    text = read_runbook()

    assert "--checksum-algorithm SHA256" in text
    assert "--checksum-mode ENABLED" in text
    assert "ChecksumSHA256" in text
    assert "application-route.tfplan" in text
    assert "terraform -chdir=infra apply -input=false application-route.tfplan" in text


def test_runbook_requires_manual_rollback_boundary() -> None:
    text = read_runbook().lower()

    assert "자동 rollback하지" in text
    assert "사용자 승인" in text
