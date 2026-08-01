from pathlib import Path
from typing import cast

import pytest
import yaml

from pilo_incident_investigator.domain import JsonValue
from pilo_incident_investigator.evaluation.loader import load_fixture, load_manifest
from pilo_incident_investigator.evaluation.schema import FixtureValidationError

TOPOLOGY_PATH = Path(__file__).parents[2] / "fixtures" / "topology" / "valid.yaml"


def _fixture_raw(fixture_id: str = "eval-loader-complete") -> dict[str, JsonValue]:
    topology = cast(dict[str, JsonValue], yaml.safe_load(TOPOLOGY_PATH.read_text(encoding="utf-8")))
    return {
        "fixture_id": fixture_id,
        "scenario": "synthetic_loader",
        "variant": "complete",
        "alarm": {"state": "ALARM"},
        "topology": topology,
        "snapshot": {
            "incident_id": "inc-loader-001",
            "evidence": [
                {
                    "evidence_id": "E-LOADER-1",
                    "source": "synthetic.loader",
                    "observed_at": "2026-01-01T00:00:00Z",
                    "summary": "synthetic loader observation",
                    "data": {"state": "ALARM"},
                }
            ],
            "failures": [],
        },
        "tool_results": {},
        "expected": {
            "required_evidence_ids": ["E-LOADER-1"],
            "acceptable_direction_labels": ["inspect_loader_signal"],
            "useful_tools": [],
            "classification": "unclassified",
            "facts": [{"text": "synthetic alarm is active", "evidence_ids": ["E-LOADER-1"]}],
            "missing_information": [],
        },
        "handoff": {
            "acceptable_first_direction_labels": ["inspect_loader_signal"],
            "allowed_clarification_kinds": [],
        },
    }


def _write_yaml(path: Path, value: object) -> None:
    path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")


def test_load_fixture_parses_yaml_without_external_calls(tmp_path: Path) -> None:
    fixture_path = tmp_path / "fixture.yaml"
    _write_yaml(fixture_path, _fixture_raw())

    fixture = load_fixture(fixture_path)

    assert fixture.fixture_id == "eval-loader-complete"
    assert fixture.snapshot.evidence[0].observed_at.isoformat() == "2026-01-01T00:00:00+00:00"


def test_load_fixture_rejects_duplicate_yaml_keys(tmp_path: Path) -> None:
    fixture_path = tmp_path / "fixture.yaml"
    fixture_path.write_text(
        "fixture_id: first\nfixture_id: second\n",
        encoding="utf-8",
    )

    with pytest.raises(FixtureValidationError, match="duplicate YAML key"):
        load_fixture(fixture_path)


def test_load_fixture_rejects_cyclic_yaml_alias(tmp_path: Path) -> None:
    fixture_path = tmp_path / "fixture.yaml"
    fixture_path.write_text("fixture: &node\n  self: *node\n", encoding="utf-8")

    with pytest.raises(FixtureValidationError, match="YAML aliases"):
        load_fixture(fixture_path)


def test_load_fixture_rejects_excessive_plain_nesting(tmp_path: Path) -> None:
    raw = _fixture_raw()
    nested: JsonValue = "leaf"
    for _ in range(70):
        nested = [nested]
    alarm = cast(dict[str, JsonValue], raw["alarm"])
    alarm["nested"] = nested
    fixture_path = tmp_path / "fixture.yaml"
    _write_yaml(fixture_path, raw)

    with pytest.raises(FixtureValidationError, match="nesting depth"):
        load_fixture(fixture_path)


def test_load_fixture_rejects_sensitive_content_before_parsing(tmp_path: Path) -> None:
    raw = _fixture_raw()
    alarm = cast(dict[str, JsonValue], raw["alarm"])
    alarm["credential"] = "AKIAABCDEFGHIJKLMNOP"
    fixture_path = tmp_path / "fixture.yaml"
    _write_yaml(fixture_path, raw)

    with pytest.raises(FixtureValidationError, match="sensitive"):
        load_fixture(fixture_path)


def test_load_fixture_rejects_yaml_numeric_account_id(tmp_path: Path) -> None:
    raw = _fixture_raw()
    alarm = cast(dict[str, JsonValue], raw["alarm"])
    alarm["account_id"] = 123456789012
    fixture_path = tmp_path / "fixture.yaml"
    _write_yaml(fixture_path, raw)

    with pytest.raises(FixtureValidationError, match="account"):
        load_fixture(fixture_path)


def test_manifest_rejects_duplicate_fixture_ids_before_loading(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifest.yaml"
    _write_yaml(
        manifest_path,
        {
            "version": 1,
            "fixtures": [
                {
                    "fixture_id": "eval-duplicate",
                    "path": "first.yaml",
                    "scenario": "synthetic_loader",
                    "variant": "complete",
                },
                {
                    "fixture_id": "eval-duplicate",
                    "path": "second.yaml",
                    "scenario": "synthetic_loader",
                    "variant": "noisy",
                },
            ],
        },
    )

    with pytest.raises(FixtureValidationError, match="duplicate fixture_id"):
        load_manifest(manifest_path)


@pytest.mark.parametrize("version", [True, 1.0, "1"])
def test_manifest_requires_exact_integer_version(tmp_path: Path, version: JsonValue) -> None:
    manifest_path = tmp_path / "manifest.yaml"
    _write_yaml(manifest_path, {"version": version, "fixtures": []})

    with pytest.raises(FixtureValidationError, match="manifest version"):
        load_manifest(manifest_path)


def test_manifest_loads_fixture_and_checks_declared_metadata(tmp_path: Path) -> None:
    fixture_path = tmp_path / "fixture.yaml"
    manifest_path = tmp_path / "manifest.yaml"
    _write_yaml(fixture_path, _fixture_raw())
    _write_yaml(
        manifest_path,
        {
            "version": 1,
            "fixtures": [
                {
                    "fixture_id": "eval-loader-complete",
                    "path": "fixture.yaml",
                    "scenario": "synthetic_loader",
                    "variant": "complete",
                }
            ],
        },
    )

    fixtures = load_manifest(manifest_path)

    assert tuple(item.fixture_id for item in fixtures) == ("eval-loader-complete",)


def test_manifest_rejects_metadata_that_disagrees_with_fixture(tmp_path: Path) -> None:
    fixture_path = tmp_path / "fixture.yaml"
    manifest_path = tmp_path / "manifest.yaml"
    _write_yaml(fixture_path, _fixture_raw())
    _write_yaml(
        manifest_path,
        {
            "version": 1,
            "fixtures": [
                {
                    "fixture_id": "eval-loader-complete",
                    "path": "fixture.yaml",
                    "scenario": "different_scenario",
                    "variant": "complete",
                }
            ],
        },
    )

    with pytest.raises(FixtureValidationError, match="manifest metadata"):
        load_manifest(manifest_path)


def test_manifest_rejects_path_outside_manifest_directory(tmp_path: Path) -> None:
    manifest_dir = tmp_path / "manifest"
    manifest_dir.mkdir()
    manifest_path = manifest_dir / "manifest.yaml"
    _write_yaml(
        manifest_path,
        {
            "version": 1,
            "fixtures": [
                {
                    "fixture_id": "eval-loader-complete",
                    "path": "../fixture.yaml",
                    "scenario": "synthetic_loader",
                    "variant": "complete",
                }
            ],
        },
    )

    with pytest.raises(FixtureValidationError, match="relative child path"):
        load_manifest(manifest_path)


def test_manifest_rejects_unknown_entry_field(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifest.yaml"
    _write_yaml(
        manifest_path,
        {
            "version": 1,
            "fixtures": [
                {
                    "fixture_id": "eval-loader-complete",
                    "path": "fixture.yaml",
                    "scenario": "synthetic_loader",
                    "variant": "complete",
                    "allow_live_aws": True,
                }
            ],
        },
    )

    with pytest.raises(FixtureValidationError, match="unknown fields"):
        load_manifest(manifest_path)
