from __future__ import annotations

import pytest

from pilo_incident_investigator.config import RuntimeConfig


def valid_environment() -> dict[str, str]:
    return {
        "PILO_REGION": "ap-northeast-2",
        "PILO_TOPOLOGY_BUCKET": "pilo-topology-private",
        "PILO_TOPOLOGY_KEY": "config/pilo-topology.yaml",
        "PILO_STATE_TABLE": "pilo-incident-state",
        "PILO_BUNDLE_BUCKET": "pilo-incident-bundles",
        "PILO_GITHUB_REPOSITORY": "synthetic-org/private-incidents",
        "PILO_GITHUB_TOKEN_PARAMETER": "/pilo/investigator/github-token",
        "PILO_SLACK_WEBHOOK_PARAMETER": "/pilo/investigator/slack-webhook",
        "PILO_BEDROCK_MODEL_ID": "apac.anthropic.claude-test-v1:0",
    }


def test_runtime_config_defaults_to_snapshot_only() -> None:
    config = RuntimeConfig.from_environment(valid_environment())

    assert config.region == "ap-northeast-2"
    assert config.mode == "snapshot_only"


@pytest.mark.parametrize("mode", ["snapshot_only", "hybrid_agent"])
def test_runtime_config_accepts_only_supported_modes(mode: str) -> None:
    environment = valid_environment()
    environment["PILO_MODE"] = mode

    assert RuntimeConfig.from_environment(environment).mode == mode


@pytest.mark.parametrize("mode", ["hybrid", "SNAPSHOT_ONLY", "", " snapshot_only"])
def test_runtime_config_rejects_invalid_modes(mode: str) -> None:
    environment = valid_environment()
    environment["PILO_MODE"] = mode

    with pytest.raises(ValueError, match="PILO_MODE"):
        RuntimeConfig.from_environment(environment)


@pytest.mark.parametrize("missing", list(valid_environment()))
def test_runtime_config_requires_every_non_mode_key(missing: str) -> None:
    environment = valid_environment()
    del environment[missing]

    with pytest.raises(ValueError, match="configuration is invalid"):
        RuntimeConfig.from_environment(environment)


def test_runtime_config_rejects_non_pilo_region_and_unsafe_topology_key() -> None:
    wrong_region = valid_environment()
    wrong_region["PILO_REGION"] = "us-east-1"
    unsafe_key = valid_environment()
    unsafe_key["PILO_TOPOLOGY_KEY"] = "../pilo-topology.yaml"

    with pytest.raises(ValueError, match="PILO_REGION"):
        RuntimeConfig.from_environment(wrong_region)
    with pytest.raises(ValueError, match="PILO_TOPOLOGY_KEY"):
        RuntimeConfig.from_environment(unsafe_key)


def test_runtime_config_rejects_publication_repository_dot_segments() -> None:
    environment = valid_environment()
    environment["PILO_GITHUB_REPOSITORY"] = "synthetic-org/.."

    with pytest.raises(ValueError, match="repository"):
        RuntimeConfig.from_environment(environment)


def test_direct_runtime_config_construction_cannot_bypass_validation() -> None:
    environment = valid_environment()
    config = RuntimeConfig.from_environment(environment)

    with pytest.raises(ValueError, match="PILO_REGION"):
        RuntimeConfig(
            region="us-east-1",
            topology_bucket=config.topology_bucket,
            topology_key=config.topology_key,
            state_table=config.state_table,
            bundle_bucket=config.bundle_bucket,
            github_repository=config.github_repository,
            github_token_parameter=config.github_token_parameter,
            slack_webhook_parameter=config.slack_webhook_parameter,
            bedrock_model_id=config.bedrock_model_id,
        )
