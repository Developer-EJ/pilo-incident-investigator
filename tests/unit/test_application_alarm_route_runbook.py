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
    assert "terraform -chdir=infra apply -input=false $savedPlanFile" in text


def test_runbook_requires_manual_rollback_boundary() -> None:
    text = read_runbook().lower()

    assert "자동 rollback하지" in text
    assert "사용자 승인" in text


def test_runbook_writes_plan_json_as_bomless_utf8() -> None:
    text = read_runbook()

    assert "Out-File -Encoding utf8" not in text
    assert (
        "[IO.File]::WriteAllText($planJsonFile, $planJson, [Text.UTF8Encoding]::new($false))"
        in text
    )


def test_runbook_captures_terraform_output_outside_the_console() -> None:
    text = read_runbook()

    assert "terraform -chdir=infra plan" in text
    assert "*> $terraformPlanLog" in text
    assert "terraform -chdir=infra apply -input=false $savedPlanFile *> $terraformApplyLog" in text


def test_runbook_expands_tfvars_path_for_powershell_native_commands() -> None:
    text = read_runbook()

    assert "-var-file=$($deployTfvarsFile)" in text
    assert "-var-file=$deployTfvarsFile" not in text


def test_runbook_rejects_protected_paths_inside_repository() -> None:
    text = read_runbook()

    assert "function Assert-OutsideRepositoryPath" in text
    assert "Resolve-Path -LiteralPath" in text
    assert "[IO.Path]::GetFullPath" in text
    for name in (
        "PILO_BASELINE_TOPOLOGY_FILE",
        "PILO_CANDIDATE_TOPOLOGY_FILE",
        "PILO_NEW_ALARM_MAPPINGS_FILE",
        "PILO_DEPLOY_TFVARS_FILE",
    ):
        assert f"$env:{name}" in text


def test_runbook_uses_windows_powershell_51_compatible_absolute_path_check() -> None:
    text = read_runbook()

    assert "[IO.Path]::IsPathFullyQualified" not in text
    assert "[IO.Path]::IsPathRooted" in text
    assert "$absolutePath = [IO.Path]::GetFullPath($Path)" in text


def test_runbook_post_apply_checks_exact_live_route_configuration() -> None:
    text = read_runbook()

    assert "terraform -chdir=infra output -raw lambda_function_name" in text
    assert "lambda_function_arn" not in text
    assert "aws events describe-rule" in text
    assert ".State -cne 'ENABLED'" in text
    assert ".FunctionArn" in text
    assert "aws lambda get-function-concurrency" in text
    assert ".ReservedConcurrentExecutions -ne 2" in text
    assert "get-function-configuration" in text
    assert "configuration.ReservedConcurrentExecutions" not in text


def test_runbook_binds_protected_topology_to_deployed_lambda_before_mutation() -> None:
    text = read_runbook()
    binding_check = text.index("Lambda deployment binding is invalid")

    assert "$terraformLambdaFunctionName -cne $env:PILO_LAMBDA_FUNCTION_NAME" in text
    assert (
        "$configuration.Environment.Variables.PILO_TOPOLOGY_BUCKET "
        "-cne $env:PILO_TOPOLOGY_BUCKET" in text
    )
    assert (
        "$configuration.Environment.Variables.PILO_TOPOLOGY_KEY -cne $env:PILO_TOPOLOGY_KEY" in text
    )
    assert binding_check < text.index("s3api put-object")
    assert binding_check < text.index("terraform -chdir=infra plan")
