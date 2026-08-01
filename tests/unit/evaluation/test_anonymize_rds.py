import io
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest
import yaml

from pilo_incident_investigator.domain import JsonValue
from pilo_incident_investigator.evaluation.schema import EvalFixture, FixtureValidationError
from scripts.anonymize_rds_fixture import anonymize, main

REPO_ROOT = Path(__file__).parents[3]
RDS_COMPLETE_PATH = (
    REPO_ROOT / "fixtures" / "eval" / "representative" / "rds-secret-rotation-auth-complete.yaml"
)


def source_record() -> dict[str, JsonValue]:
    return {
        "event_time": "2031-07-15T04:35:00Z",
        "db_status": "available",
        "rotation_enabled": True,
        "last_rotated_time": "2031-07-15T04:30:00Z",
        "application_error_kind": "authentication_failure",
        "application_error_count": 12,
    }


def test_anonymizer_is_deterministic_and_schema_approved() -> None:
    first = anonymize(source_record())
    second = anonymize(source_record())

    assert first == second
    fixture = EvalFixture.from_dict(first)
    assert fixture.fixture_id == "rds-secret-rotation-auth-complete"
    assert fixture.topology.environment == "dev"
    assert fixture.topology.region == "ap-northeast-2"


def test_anonymizer_shifts_timestamps_to_fixed_synthetic_window() -> None:
    fixture = EvalFixture.from_dict(anonymize(source_record()))
    observed = [item.observed_at for item in fixture.snapshot.evidence]
    observed.extend(
        item.observed_at for result in fixture.tool_results.values() for item in result.evidence
    )

    assert min(observed) == datetime(2026, 1, 1, 0, 5, tzinfo=UTC)
    assert max(observed) <= datetime(2026, 1, 1, 1, 0, tzinfo=UTC)


@pytest.mark.parametrize("unknown_field", ["raw_log", "account_id", "service_name"])
def test_anonymizer_rejects_unknown_private_source_fields(unknown_field: str) -> None:
    source = source_record()
    source[unknown_field] = "must-not-survive"

    with pytest.raises(FixtureValidationError, match="unknown source fields"):
        anonymize(source)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("db_status", "private-db-name available"),
        ("application_error_kind", "raw log line with user identifier"),
    ],
)
def test_anonymizer_rejects_unapproved_semantic_values(field: str, value: str) -> None:
    source = source_record()
    source[field] = value

    with pytest.raises(FixtureValidationError, match="semantic"):
        anonymize(source)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("db_status", "starting", "available"),
        ("db_status", "stopped", "available"),
        ("rotation_enabled", False, "rotation_enabled"),
        ("last_rotated_time", "2031-07-15T04:40:00Z", "rotation chronology"),
        ("event_time", "2031-07-15T05:31:00Z", "rotation chronology"),
    ],
)
def test_anonymizer_rejects_inputs_that_cannot_form_complete_rds_case(
    field: str, value: JsonValue, message: str
) -> None:
    source = source_record()
    source[field] = value

    with pytest.raises(FixtureValidationError, match=message):
        anonymize(source)


def test_cli_reads_json_from_stdin_and_writes_only_schema_yaml() -> None:
    stdout = io.StringIO()
    stderr = io.StringIO()

    exit_code = main(
        [],
        stdin=io.StringIO(json.dumps(source_record())),
        stdout=stdout,
        stderr=stderr,
    )

    assert exit_code == 0
    assert stderr.getvalue() == ""
    raw = cast(dict[str, JsonValue], yaml.safe_load(stdout.getvalue()))
    EvalFixture.from_dict(raw)
    assert stdout.getvalue().startswith("fixture_id:")


def test_cli_rejects_filename_argument_without_reading_or_writing(tmp_path: Path) -> None:
    private_path = tmp_path / "private.json"
    private_path.write_text("PRIVATE-SOURCE-MARKER", encoding="utf-8")
    stdout = io.StringIO()
    stderr = io.StringIO()

    exit_code = main(
        [str(private_path)],
        stdin=io.StringIO(""),
        stdout=stdout,
        stderr=stderr,
    )

    assert exit_code == 2
    assert stdout.getvalue() == ""
    assert "PRIVATE-SOURCE-MARKER" not in stderr.getvalue()
    assert private_path.read_text(encoding="utf-8") == "PRIVATE-SOURCE-MARKER"


def test_cli_rejects_duplicate_json_keys_without_output() -> None:
    source = json.dumps(source_record())
    duplicate = source.replace(
        '"db_status": "available"',
        '"db_status": "available", "db_status": "stopped"',
    )
    stdout = io.StringIO()
    stderr = io.StringIO()

    exit_code = main([], stdin=io.StringIO(duplicate), stdout=stdout, stderr=stderr)

    assert exit_code == 2
    assert stdout.getvalue() == ""
    assert stderr.getvalue() == "invalid source input\n"


def test_committed_complete_rds_fixture_is_anonymizer_output() -> None:
    committed = cast(
        dict[str, JsonValue], yaml.safe_load(RDS_COMPLETE_PATH.read_text(encoding="utf-8"))
    )

    assert committed == anonymize(source_record())
