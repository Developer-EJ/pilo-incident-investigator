"""Validated runtime configuration for the PILO dev Lambda."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal, cast

from pilo_incident_investigator.integrations.github import validate_repository

type RuntimeMode = Literal["snapshot_only", "hybrid_agent"]

_EXPECTED_REGION = "ap-northeast-2"
_BUCKET_PATTERN = re.compile(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]")
_TABLE_PATTERN = re.compile(r"[A-Za-z0-9_.-]{3,255}")
_MAX_PARAMETER_NAME_LENGTH = 2_048
_MAX_MODEL_ID_LENGTH = 2_048


@dataclass(frozen=True, slots=True)
class RuntimeConfig:
    region: str
    topology_bucket: str
    topology_key: str
    state_table: str
    bundle_bucket: str
    github_repository: str
    github_token_parameter: str
    slack_webhook_parameter: str
    bedrock_model_id: str
    mode: RuntimeMode = "snapshot_only"

    def __post_init__(self) -> None:
        if self.mode not in {"snapshot_only", "hybrid_agent"}:
            raise ValueError("PILO_MODE must be snapshot_only or hybrid_agent")
        if self.region != _EXPECTED_REGION:
            raise ValueError("PILO_REGION must be ap-northeast-2")
        _validate_bucket(self.topology_bucket, "PILO_TOPOLOGY_BUCKET")
        _validate_bucket(self.bundle_bucket, "PILO_BUNDLE_BUCKET")
        _validate_topology_key(self.topology_key)
        if _TABLE_PATTERN.fullmatch(self.state_table) is None:
            raise ValueError("PILO_STATE_TABLE is invalid")
        validate_repository(self.github_repository)
        _validate_bounded_value(
            self.github_token_parameter,
            "PILO_GITHUB_TOKEN_PARAMETER",
            _MAX_PARAMETER_NAME_LENGTH,
        )
        _validate_bounded_value(
            self.slack_webhook_parameter,
            "PILO_SLACK_WEBHOOK_PARAMETER",
            _MAX_PARAMETER_NAME_LENGTH,
        )
        if self.github_token_parameter == self.slack_webhook_parameter:
            raise ValueError("credential parameter names must be distinct")
        _validate_bounded_value(
            self.bedrock_model_id,
            "PILO_BEDROCK_MODEL_ID",
            _MAX_MODEL_ID_LENGTH,
        )

    @classmethod
    def from_environment(cls, environment: Mapping[str, str] | None = None) -> RuntimeConfig:
        values = os.environ if environment is None else environment
        try:
            region = _required(values, "PILO_REGION")
            topology_bucket = _required(values, "PILO_TOPOLOGY_BUCKET")
            topology_key = _required(values, "PILO_TOPOLOGY_KEY")
            state_table = _required(values, "PILO_STATE_TABLE")
            bundle_bucket = _required(values, "PILO_BUNDLE_BUCKET")
            github_repository = _required(values, "PILO_GITHUB_REPOSITORY")
            github_token_parameter = _required(values, "PILO_GITHUB_TOKEN_PARAMETER")
            slack_webhook_parameter = _required(values, "PILO_SLACK_WEBHOOK_PARAMETER")
            bedrock_model_id = _required(values, "PILO_BEDROCK_MODEL_ID")
        except (KeyError, TypeError, ValueError):
            raise ValueError("runtime configuration is invalid") from None

        mode_value = values.get("PILO_MODE", "snapshot_only")
        if mode_value not in {"snapshot_only", "hybrid_agent"}:
            raise ValueError("PILO_MODE must be snapshot_only or hybrid_agent")
        mode = cast(RuntimeMode, mode_value)

        return cls(
            region=region,
            topology_bucket=topology_bucket,
            topology_key=topology_key,
            state_table=state_table,
            bundle_bucket=bundle_bucket,
            github_repository=github_repository,
            github_token_parameter=github_token_parameter,
            slack_webhook_parameter=slack_webhook_parameter,
            bedrock_model_id=bedrock_model_id,
            mode=mode,
        )


def _required(environment: Mapping[str, str], name: str) -> str:
    value = environment[name]
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError
    return value


def _validate_bucket(value: str, field: str) -> None:
    if _BUCKET_PATTERN.fullmatch(value) is None or ".." in value:
        raise ValueError(f"{field} is invalid")


def _validate_topology_key(value: str) -> None:
    if (
        len(value.encode("utf-8")) > 1_024
        or value.startswith(("/", "\\"))
        or "\\" in value
        or any(part in {"", ".", ".."} for part in value.split("/"))
    ):
        raise ValueError("PILO_TOPOLOGY_KEY is invalid")


def _validate_bounded_value(value: str, field: str, maximum: int) -> None:
    if len(value) > maximum or any(
        character.isspace() or ord(character) < 32 for character in value
    ):
        raise ValueError(f"{field} is invalid")
