import re
from pathlib import Path

import pytest
import yaml

from pilo_incident_investigator.topology import Topology, TopologyDenied, TopologyError, main

FIXTURE_DIR = Path(__file__).parents[1] / "fixtures" / "topology"
REPO_ROOT = Path(__file__).parents[2]


@pytest.fixture
def topology() -> Topology:
    return Topology.load((FIXTURE_DIR / "valid.yaml").read_text(encoding="utf-8"))


def test_valid_topology_has_exact_pilo_scope(topology: Topology) -> None:
    assert topology.environment == "dev"
    assert topology.region == "ap-northeast-2"
    assert tuple(service.key for service in topology.services) == tuple(
        f"pilo-dev-service-{index:02d}" for index in range(1, 9)
    )


def test_unknown_alarm_maps_to_no_service(topology: Topology) -> None:
    alarm_arn = "arn:aws:cloudwatch:ap-northeast-2:000000000000:alarm:unknown"

    assert topology.resolve_alarm(alarm_arn) == ()


def test_known_alarm_resolves_only_mapped_service(topology: Topology) -> None:
    alarm_arn = "arn:aws:cloudwatch:ap-northeast-2:000000000000:alarm:pilo-dev-service-03"

    assert tuple(service.key for service in topology.resolve_alarm(alarm_arn)) == (
        "pilo-dev-service-03",
    )


def test_resource_outside_allowlist_is_rejected(topology: Topology) -> None:
    with pytest.raises(TopologyDenied, match="not allowlisted"):
        topology.require_allowed("log_group", "/aws/ecs/not-pilo")


def test_allowlisted_resource_is_accepted(topology: Topology) -> None:
    topology.require_allowed("log_group", "/aws/ecs/pilo-dev-service-01")


def test_wrong_region_is_rejected() -> None:
    text = (FIXTURE_DIR / "valid.yaml").read_text(encoding="utf-8")

    with pytest.raises(TopologyError, match="region must be ap-northeast-2"):
        Topology.load(text.replace("region: ap-northeast-2", "region: us-east-1", 1))


def test_wrong_environment_is_rejected() -> None:
    text = (FIXTURE_DIR / "valid.yaml").read_text(encoding="utf-8")

    with pytest.raises(TopologyError, match="environment must be dev"):
        Topology.load(text.replace("environment: dev", "environment: prod", 1))


def test_wrong_schema_version_is_rejected() -> None:
    text = (FIXTURE_DIR / "valid.yaml").read_text(encoding="utf-8")

    with pytest.raises(TopologyError, match="version must be 1"):
        Topology.load(text.replace("version: 1", "version: 2", 1))


def test_service_count_must_be_exactly_eight() -> None:
    raw = yaml.safe_load((FIXTURE_DIR / "valid.yaml").read_text(encoding="utf-8"))
    raw["services"].pop()

    with pytest.raises(TopologyError, match="exactly 8 services"):
        Topology.load(yaml.safe_dump(raw))


def test_duplicate_service_key_is_rejected() -> None:
    raw = yaml.safe_load((FIXTURE_DIR / "valid.yaml").read_text(encoding="utf-8"))
    raw["services"][7]["key"] = "pilo-dev-service-07"

    with pytest.raises(TopologyError, match="service keys must be unique"):
        Topology.load(yaml.safe_dump(raw))


def test_duplicate_service_resources_are_rejected() -> None:
    text = (FIXTURE_DIR / "duplicate.yaml").read_text(encoding="utf-8")

    with pytest.raises(TopologyError, match="duplicate resource"):
        Topology.load(text)


@pytest.mark.parametrize("field", ["rds_instances", "queues"])
def test_duplicate_rds_and_queue_resources_are_rejected(field: str) -> None:
    raw = yaml.safe_load((FIXTURE_DIR / "valid.yaml").read_text(encoding="utf-8"))
    raw["services"][1][field] = raw["services"][0][field]

    with pytest.raises(TopologyError, match="duplicate resource"):
        Topology.load(yaml.safe_dump(raw))


def test_duplicate_top_level_yaml_key_is_rejected() -> None:
    text = (FIXTURE_DIR / "valid.yaml").read_text(encoding="utf-8")

    with pytest.raises(TopologyError, match="duplicate YAML key"):
        Topology.load(f"{text}\nregion: ap-northeast-2\n")


def test_duplicate_service_yaml_key_is_rejected() -> None:
    text = (FIXTURE_DIR / "valid.yaml").read_text(encoding="utf-8")
    duplicated = text.replace(
        "  - key: pilo-dev-service-01\n",
        "  - key: pilo-dev-service-01\n    key: pilo-dev-service-01\n",
        1,
    )

    with pytest.raises(TopologyError, match="duplicate YAML key"):
        Topology.load(duplicated)


def test_duplicate_alarm_yaml_key_is_rejected() -> None:
    text = (FIXTURE_DIR / "valid.yaml").read_text(encoding="utf-8")
    alarm = (
        "  arn:aws:cloudwatch:ap-northeast-2:000000000000:alarm:"
        "pilo-dev-service-01: [pilo-dev-service-01]\n"
    )

    with pytest.raises(TopologyError, match="duplicate YAML key"):
        Topology.load(text.replace("alarms:\n", f"alarms:\n{alarm}", 1))


def test_alarm_mapping_to_unknown_service_is_rejected() -> None:
    text = (FIXTURE_DIR / "valid.yaml").read_text(encoding="utf-8")

    with pytest.raises(TopologyError, match="unknown services"):
        Topology.load(text.replace("[pilo-dev-service-08]", "[not-pilo]", 1))


def test_unknown_top_level_field_is_rejected() -> None:
    text = (FIXTURE_DIR / "valid.yaml").read_text(encoding="utf-8")

    with pytest.raises(TopologyError, match="unknown fields"):
        Topology.load(f"{text}\naccount_scan_enabled: true\n")


def test_unknown_service_field_is_rejected() -> None:
    raw = yaml.safe_load((FIXTURE_DIR / "valid.yaml").read_text(encoding="utf-8"))
    raw["services"][0]["scan_all_accounts"] = True

    with pytest.raises(TopologyError, match="service contains unknown fields"):
        Topology.load(yaml.safe_dump(raw))


def test_unsafe_yaml_constructor_is_rejected() -> None:
    with pytest.raises(TopologyError, match="invalid YAML"):
        Topology.load("!!python/object/apply:os.system ['echo unsafe']")


def test_validate_cli_prints_only_service_count(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["validate", str(FIXTURE_DIR / "valid.yaml")])

    assert exit_code == 0
    assert capsys.readouterr().out == "valid topology: 8 services\n"


def test_validate_cli_does_not_expose_invalid_topology_details(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sensitive_marker = "SENSITIVE-ALARM-ARN"
    topology_path = tmp_path / "topology.yaml"
    topology_path.write_text(
        f"{sensitive_marker}: first\n{sensitive_marker}: second\n", encoding="utf-8"
    )

    exit_code = main(["validate", str(topology_path)])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.out == ""
    assert captured.err == "invalid topology\n"
    assert sensitive_marker not in captured.out + captured.err


def test_public_example_is_valid_and_uses_only_synthetic_account() -> None:
    text = (REPO_ROOT / "config" / "pilo-topology.example.yaml").read_text(encoding="utf-8")

    topology = Topology.load(text)

    assert len(topology.services) == 8
    assert set(re.findall(r"(?<!\d)\d{12}(?!\d)", text)) == {"000000000000"}
