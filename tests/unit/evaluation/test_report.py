from __future__ import annotations

import json
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from threading import Barrier
from typing import Literal

import pytest

import pilo_incident_investigator.evaluation.report as report_module
import scripts.run_eval as run_eval_module
from pilo_incident_investigator.evaluation.loader import load_manifest
from pilo_incident_investigator.evaluation.report import (
    METRIC_NAMES,
    EvaluationReport,
    LiveEvaluationUnavailable,
    ReportReservation,
    aggregate_payload,
    build_offline_report,
    render_report,
    reserve_report_slot,
    write_report,
)
from scripts.run_eval import main

ROOT = Path(__file__).parents[3]
MANIFEST_PATH = ROOT / "fixtures" / "eval" / "manifest.yaml"
GENERATED_AT = datetime(2026, 8, 2, 3, 4, 5, tzinfo=UTC)


@pytest.fixture(scope="module")
def report() -> EvaluationReport:
    return build_offline_report(
        load_manifest(MANIFEST_PATH),
        generated_at=GENERATED_AT,
        git_commit="f9180a210e9650bea4b96c551865e8d51bb1bb77",
        model_id="offline-deterministic-v1",
        input_cost_per_million=Decimal("0"),
        output_cost_per_million=Decimal("0"),
    )


def test_report_contains_all_required_metrics(report: EvaluationReport) -> None:
    assert set(report.metric_names) == {
        "required_evidence_recall",
        "correct_investigation_direction",
        "unnecessary_tool_ratio",
        "unsupported_claims",
        "unclassified_accuracy",
        "latency_ms",
        "input_tokens",
        "output_tokens",
        "estimated_cost",
        "handoff_additional_tool_calls",
        "handoff_clarification_requests",
        "handoff_safety",
    }
    assert report.metric_names == METRIC_NAMES


def test_offline_report_executes_exact_sorted_investigation_and_handoff_matrices(
    report: EvaluationReport,
) -> None:
    investigation_keys = tuple((row.fixture_id, row.mode) for row in report.investigation_metrics)
    handoff_keys = tuple((row.fixture_id, row.condition) for row in report.handoff_runs)

    assert len(investigation_keys) == len(set(investigation_keys)) == 42
    assert len(handoff_keys) == len(set(handoff_keys)) == 42
    assert investigation_keys == tuple(sorted(investigation_keys))
    assert handoff_keys == tuple(sorted(handoff_keys))
    assert report.operating_mode == "snapshot_only"
    assert len(report.gate_reasons) == 6
    assert any(not reason.passed for reason in report.gate_reasons)


@pytest.mark.parametrize("output_format", ["json", "markdown"])
def test_report_never_contains_fixture_secret_canary(
    report: EvaluationReport, output_format: Literal["json", "markdown"]
) -> None:
    canary = "ghp_secret_canary"
    first_metric = replace(report.investigation_metrics[0], fixture_id=canary)
    first_handoff = replace(report.handoff_runs[0], first_direction_label=canary)
    first_reason = replace(report.gate_reasons[0], detail=canary)
    report_with_canary = replace(
        report,
        model_id=canary,
        investigation_metrics=(first_metric, *report.investigation_metrics[1:]),
        handoff_runs=(first_handoff, *report.handoff_runs[1:]),
        gate_reasons=(first_reason, *report.gate_reasons[1:]),
    )
    rendered = render_report(report_with_canary, output_format=output_format)
    stdout_payload = json.dumps(aggregate_payload(report_with_canary), ensure_ascii=False)

    assert canary not in rendered
    assert canary not in stdout_payload
    assert "[REDACTED:GITHUB_TOKEN]" in rendered
    assert "[REDACTED:GITHUB_TOKEN]" in stdout_payload


def test_report_rendering_is_stable_and_includes_metadata_gate_and_reasons(
    report: EvaluationReport,
) -> None:
    json_text = render_report(report, output_format="json")
    markdown = render_report(report, output_format="markdown")

    assert json_text == render_report(report, output_format="json")
    payload = json.loads(json_text)
    assert payload["metadata"] == {
        "generated_at": "2026-08-02T03:04:05Z",
        "git_commit": "f9180a210e9650bea4b96c551865e8d51bb1bb77",
        "input_cost_per_million": "0",
        "model_id": "offline-deterministic-v1",
        "output_cost_per_million": "0",
    }
    assert payload["operating_mode"] == "snapshot_only"
    assert payload["execution_kind"] == "offline_neutral_recording"
    assert payload["model_called"] is False
    assert "미측정" in payload["measurement_notice"]
    assert "주장하지 않습니다" in payload["measurement_notice"]
    assert len(payload["gate_reasons"]) == 6
    assert "운영 권장 모드: snapshot_only" in markdown
    assert "Execution kind: offline_neutral_recording" in markdown
    assert "Model called: false" in markdown
    assert "미측정" in markdown
    assert "주장하지 않습니다" in markdown
    assert all(f"`{metric_name}`" in markdown for metric_name in METRIC_NAMES)
    assert all(reason.name in markdown for reason in report.gate_reasons)


def test_write_report_uses_timestamped_json_and_markdown_names(
    report: EvaluationReport,
    tmp_path: Path,
) -> None:
    json_path, markdown_path = write_report(report, tmp_path)

    assert json_path.name == "eval-20260802T030405Z.json"
    assert markdown_path.name == "eval-20260802T030405Z.md"
    assert json_path.read_text(encoding="utf-8") == render_report(report, output_format="json")
    assert markdown_path.read_text(encoding="utf-8") == render_report(
        report, output_format="markdown"
    )
    assert b"\r\n" not in json_path.read_bytes()
    assert b"\r\n" not in markdown_path.read_bytes()


def test_same_timestamp_reservations_select_distinct_slots(tmp_path: Path) -> None:
    first = reserve_report_slot(tmp_path, GENERATED_AT)
    second = reserve_report_slot(tmp_path, GENERATED_AT)
    try:
        assert first.generated_at == GENERATED_AT
        assert second.generated_at == GENERATED_AT.replace(second=6)
        assert first.lock_path != second.lock_path
        assert first.lock_path.exists()
        assert second.lock_path.exists()
    finally:
        first.release()
        second.release()


def test_second_temp_write_failure_leaves_no_final_pair(
    report: EvaluationReport, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_write = report_module._write_lf_text
    calls = 0

    def fail_second_write(path: Path, content: str) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("synthetic second write failure")
        real_write(path, content)

    monkeypatch.setattr(report_module, "_write_lf_text", fail_second_write)

    with pytest.raises(OSError, match="second write failure"):
        write_report(report, tmp_path)

    assert list(tmp_path.iterdir()) == []


def test_preexisting_report_is_never_overwritten(report: EvaluationReport, tmp_path: Path) -> None:
    existing = tmp_path / "eval-20260802T030405Z.json"
    existing.write_bytes(b"preexisting")

    with pytest.raises(FileExistsError):
        write_report(report, tmp_path)

    assert existing.read_bytes() == b"preexisting"
    assert not (tmp_path / "eval-20260802T030405Z.md").exists()
    assert not tuple(tmp_path.glob(".*.tmp"))
    assert not tuple(tmp_path.glob("*.lock"))


def test_failed_write_does_not_remove_a_preexisting_temp(
    report: EvaluationReport, tmp_path: Path
) -> None:
    existing_temp = tmp_path / ".eval-20260802T030405Z.json.tmp"
    existing_temp.write_bytes(b"preexisting-temp")

    with pytest.raises(FileExistsError):
        write_report(report, tmp_path)

    assert existing_temp.read_bytes() == b"preexisting-temp"
    assert not tuple(tmp_path.glob("eval-*.json"))
    assert not tuple(tmp_path.glob("eval-*.md"))
    assert not tuple(tmp_path.glob("*.lock"))


def test_generated_report_residue_is_ignored_without_hiding_reviewed_baselines() -> None:
    reports_dir = ROOT / "reports"
    generated_paths = (
        reports_dir / ".eval-20990101T000000Z.lock",
        reports_dir / ".eval-20990101T000000Z.json.tmp",
        reports_dir / ".eval-20990101T000000Z.md.tmp",
        reports_dir / "eval-20990101T000000Z.json",
        reports_dir / "eval-20990101T000000Z.md",
    )
    try:
        for path in generated_paths:
            path.write_text("synthetic residue", encoding="utf-8")
        for path in generated_paths:
            relative = path.relative_to(ROOT).as_posix()
            ignored = subprocess.run(
                ["git", "check-ignore", "--quiet", "--", relative],
                cwd=ROOT,
                check=False,
            )
            assert ignored.returncode == 0, relative
    finally:
        for path in generated_paths:
            path.unlink(missing_ok=True)

    tracked_keep = subprocess.run(
        ["git", "ls-files", "--error-unmatch", "--", "reports/.gitkeep"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    baseline = subprocess.run(
        [
            "git",
            "check-ignore",
            "--quiet",
            "--",
            "fixtures/eval/baselines/reviewed.json",
        ],
        cwd=ROOT,
        check=False,
    )
    assert tracked_keep.returncode == 0
    assert tracked_keep.stdout.strip() == "reports/.gitkeep"
    assert baseline.returncode == 1


@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        (["--live-bedrock"], "--live-bedrock requires --acknowledge-cost"),
        (
            ["--live-bedrock", "--acknowledge-cost"],
            "--live-bedrock requires --model-id",
        ),
        (
            [
                "--live-bedrock",
                "--acknowledge-cost",
                "--model-id",
                "synthetic-model",
            ],
            "--live-bedrock requires explicit input and output token rates",
        ),
    ],
)
def test_live_cli_flags_fail_closed(
    arguments: list[str], message: str, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as error:
        main(arguments)

    assert error.value.code == 2
    assert message in capsys.readouterr().err


def test_fully_acknowledged_live_cli_still_refuses_without_a_safe_adapter() -> None:
    with pytest.raises(LiveEvaluationUnavailable, match="not implemented safely"):
        main(
            [
                "--live-bedrock",
                "--acknowledge-cost",
                "--model-id",
                "synthetic-model",
                "--input-cost-per-million",
                "1.25",
                "--output-cost-per-million",
                "5.00",
            ]
        )


def test_live_cli_rejects_whitespace_only_model_id(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as error:
        main(
            [
                "--live-bedrock",
                "--acknowledge-cost",
                "--model-id",
                "   ",
                "--input-cost-per-million",
                "1.25",
                "--output-cost-per-million",
                "5.00",
            ]
        )

    assert error.value.code == 2
    assert "--live-bedrock requires --model-id" in capsys.readouterr().err


def test_offline_cli_prints_only_aggregate_metrics_and_writes_reports(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = main(["--reports-dir", str(tmp_path)])

    assert exit_code == 0
    stdout = capsys.readouterr().out
    payload = json.loads(stdout)
    assert set(payload) == {
        "execution_kind",
        "gate_reasons",
        "handoff",
        "hybrid_agent",
        "measurement_notice",
        "model_called",
        "operating_mode",
        "snapshot_only",
    }
    assert payload["execution_kind"] == "offline_neutral_recording"
    assert payload["model_called"] is False
    assert "미측정" in payload["measurement_notice"]
    assert "주장하지 않습니다" in payload["measurement_notice"]
    assert "ecs-oom-complete" not in stdout
    assert len(tuple(tmp_path.glob("eval-*.json"))) == 1
    assert len(tuple(tmp_path.glob("eval-*.md"))) == 1


def test_concurrent_offline_cli_runs_publish_distinct_complete_pairs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    barrier = Barrier(2)
    real_reserve = run_eval_module.reserve_report_slot

    def reserve_together(reports_dir: Path, candidate: datetime) -> ReportReservation:
        barrier.wait()
        return real_reserve(reports_dir, candidate)

    monkeypatch.setattr(run_eval_module, "_utc_now", lambda: GENERATED_AT)
    monkeypatch.setattr(run_eval_module, "reserve_report_slot", reserve_together)

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = tuple(
            executor.map(
                lambda _: main(["--reports-dir", str(tmp_path)]),
                range(2),
            )
        )

    assert results == (0, 0)
    json_paths = tuple(sorted(tmp_path.glob("eval-*.json")))
    markdown_paths = tuple(sorted(tmp_path.glob("eval-*.md")))
    assert len(json_paths) == len(markdown_paths) == 2
    assert {path.stem for path in json_paths} == {path.stem for path in markdown_paths}
    assert not tuple(tmp_path.glob("*.lock"))
    assert not tuple(tmp_path.glob(".*.tmp"))
