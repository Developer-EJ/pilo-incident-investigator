from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import pytest

import pilo_incident_investigator.handler as handler_module
from pilo_incident_investigator.agent.contracts import AgentProposal
from pilo_incident_investigator.config import RuntimeConfig
from pilo_incident_investigator.domain import (
    AlarmEvent,
    Evidence,
    Investigation,
    JsonValue,
    Snapshot,
    SupportedStatement,
    ToolResult,
)
from pilo_incident_investigator.event import incident_id_for
from pilo_incident_investigator.handler import Runtime, S3TopologyProvider, TopologyLoadError
from pilo_incident_investigator.publishers import Publisher
from pilo_incident_investigator.topology import Topology

ROOT = Path(__file__).parents[2]
NOW = datetime(2026, 8, 1, 1, 2, 3, tzinfo=UTC)


def load_json(path: str) -> dict[str, JsonValue]:
    raw: object = json.loads((ROOT / path).read_text(encoding="utf-8"))
    assert isinstance(raw, dict)
    return cast(dict[str, JsonValue], raw)


class FakeTopologyProvider:
    def __init__(self) -> None:
        self.calls = 0
        self.topology = Topology.load(
            (ROOT / "tests/fixtures/topology/valid.yaml").read_text(encoding="utf-8")
        )

    def load(self) -> Topology:
        self.calls += 1
        return self.topology


class FakeSnapshotCollector:
    def __init__(self) -> None:
        self.calls = 0

    def collect(self, event: AlarmEvent, topology: Topology) -> Snapshot:
        self.calls += 1
        assert topology.resolve_alarm(event.alarm_arn)
        incident_id = incident_id_for(event.event_id)
        return Snapshot(
            incident_id=incident_id,
            evidence=(
                Evidence(
                    evidence_id="E-001",
                    source="fake.snapshot",
                    observed_at=NOW,
                    summary="synthetic service is unhealthy",
                    data={"running": 0},
                ),
            ),
            failures=(),
        )


class FakePlanner:
    def __init__(self) -> None:
        self.propose_calls = 0
        self.summarize_calls = 0

    def propose(
        self,
        snapshot: Snapshot,
        prior_results: tuple[ToolResult, ...],
        remaining_budget: int,
    ) -> AgentProposal:
        self.propose_calls += 1
        raise AssertionError("snapshot_only must not propose Tools")

    def summarize(
        self, snapshot: Snapshot, tool_results: tuple[ToolResult, ...] = ()
    ) -> Investigation:
        self.summarize_calls += 1
        return Investigation(
            facts=(SupportedStatement("service is unhealthy", ("E-001",)),),
            directions=(SupportedStatement("inspect the stopped task", ("E-001",)),),
            missing=(),
            classification="unclassified",
            tool_calls=tool_results,
        )


class FakeHybridAgent:
    def __init__(self, *, fail_on_call: bool) -> None:
        self.calls = 0
        self._fail_on_call = fail_on_call

    def run(self, snapshot: Snapshot, topology: Topology) -> Investigation:
        self.calls += 1
        if self._fail_on_call:
            raise AssertionError("snapshot_only must not run the hybrid Agent")
        assert topology.services
        return Investigation(
            facts=(SupportedStatement("hybrid fact", ("E-001",)),),
            directions=(SupportedStatement("hybrid direction", ("E-001",)),),
            missing=(),
            classification="unclassified",
            tool_calls=(),
        )


class FakeState:
    def __init__(self, *, claimed: bool = True) -> None:
        self.claimed = claimed
        self.claims: list[tuple[str, str]] = []
        self.snapshot_events: list[str] = []
        self.bundle_events: list[str] = []
        self.issue_events: list[str] = []
        self.slack_events: list[tuple[str, str]] = []

    def claim_event(self, event_id: str, incident_id: str) -> bool:
        self.claims.append((event_id, incident_id))
        return self.claimed

    def mark_snapshot_complete(self, event_id: str) -> bool:
        self.snapshot_events.append(event_id)
        return True

    def mark_bundle_stored(self, event_id: str) -> bool:
        self.bundle_events.append(event_id)
        return True

    def mark_issue_published(self, event_id: str) -> bool:
        self.issue_events.append(event_id)
        return True

    def mark_slack_attempted(self, event_id: str, status: str) -> bool:
        self.slack_events.append((event_id, status))
        return True


class FakeS3:
    def __init__(self) -> None:
        self.keys: list[str] = []
        self.bodies: list[bytes] = []

    def put_object(self, **kwargs: Any) -> dict[str, Any]:
        self.keys.append(kwargs["Key"])
        self.bodies.append(kwargs["Body"])
        return {}


class FakeGitHub:
    def __init__(self) -> None:
        self.created_issue_count = 0

    def find_issue_by_incident_id(self, repository: str, incident_id: str) -> str | None:
        return None

    def create_incident_issue(self, repository: str, incident_id: str, issue_markdown: str) -> str:
        self.created_issue_count += 1
        return f"https://github.com/{repository}/issues/1"


class FakeSlack:
    def __init__(self) -> None:
        self.messages: list[str] = []

    def send_text(self, text: str) -> None:
        self.messages.append(text)


@dataclass
class RuntimeFixture:
    runtime: Runtime
    planner: FakePlanner
    hybrid_agent: FakeHybridAgent
    state: FakeState
    s3: FakeS3
    github: FakeGitHub
    slack: FakeSlack
    topology: FakeTopologyProvider
    snapshots: FakeSnapshotCollector


def runtime_fixture(*, mode: str = "snapshot_only", claimed: bool = True) -> RuntimeFixture:
    planner = FakePlanner()
    hybrid_agent = FakeHybridAgent(fail_on_call=mode == "snapshot_only")
    state = FakeState(claimed=claimed)
    s3 = FakeS3()
    github = FakeGitHub()
    slack = FakeSlack()
    topology = FakeTopologyProvider()
    snapshots = FakeSnapshotCollector()
    publisher = Publisher(
        bundle_bucket="pilo-incident-bundles",
        github_repository="synthetic-org/private-incidents",
        s3=s3,
        github=github,
        slack=slack,
        state=state,
    )
    runtime = Runtime(
        mode=mode,  # type: ignore[arg-type]
        topology=topology,
        snapshots=snapshots,
        planner=planner,
        hybrid_agent=hybrid_agent,
        state=state,
        publisher=publisher,
        now=lambda: NOW,
    )
    return RuntimeFixture(
        runtime, planner, hybrid_agent, state, s3, github, slack, topology, snapshots
    )


def test_alarm_reaches_slack_with_issue_link() -> None:
    fixture = runtime_fixture()
    event = load_json("tests/fixtures/events/alarm.json")
    expected_id = incident_id_for("evt-001")

    response = fixture.runtime.handle(event)

    assert response == {"incident_id": expected_id, "status": "published"}
    assert fixture.s3.keys == [f"incidents/{expected_id}/bundle.json"]
    assert fixture.github.created_issue_count == 1
    assert len(fixture.slack.messages) == 1
    assert expected_id in fixture.slack.messages[0]
    assert "classification=unclassified" in fixture.slack.messages[0]
    assert (
        "https://github.com/synthetic-org/private-incidents/issues/1" in fixture.slack.messages[0]
    )
    assert fixture.state.snapshot_events == ["evt-001"]


def test_snapshot_only_mode_never_exposes_tool_schema() -> None:
    fixture = runtime_fixture()

    fixture.runtime.handle(load_json("tests/fixtures/events/alarm.json"))

    assert fixture.planner.summarize_calls == 1
    assert fixture.planner.propose_calls == 0
    assert fixture.hybrid_agent.calls == 0


def test_hybrid_mode_uses_bounded_agent_instead_of_direct_summary() -> None:
    fixture = runtime_fixture(mode="hybrid_agent")

    response = fixture.runtime.handle(load_json("tests/fixtures/events/alarm.json"))

    assert response["status"] == "published"
    assert fixture.hybrid_agent.calls == 1
    assert fixture.planner.summarize_calls == 0
    assert fixture.planner.propose_calls == 0


def test_duplicate_event_stops_before_snapshot_or_publication() -> None:
    fixture = runtime_fixture(claimed=False)

    response = fixture.runtime.handle(load_json("tests/fixtures/events/alarm.json"))

    assert response == {
        "incident_id": incident_id_for("evt-001"),
        "status": "duplicate",
    }
    assert fixture.topology.calls == 1
    assert fixture.snapshots.calls == 0
    assert fixture.s3.keys == []
    assert fixture.github.created_issue_count == 0
    assert fixture.slack.messages == []


class FakeTopologyBody:
    def __init__(self, body: bytes) -> None:
        self.body = body
        self.read_amounts: list[int | None] = []
        self.closed = False

    def read(self, amount: int | None = None) -> bytes:
        self.read_amounts.append(amount)
        if amount is None:
            return self.body
        return self.body[:amount]

    def close(self) -> None:
        self.closed = True


class FakeTopologyS3:
    def __init__(self, body: bytes) -> None:
        self.body = FakeTopologyBody(body)
        self.calls: list[dict[str, object]] = []

    def get_object(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(kwargs)
        return {"Body": self.body}


def test_protected_topology_is_bounded_validated_and_cached() -> None:
    body = (ROOT / "tests/fixtures/topology/valid.yaml").read_bytes()
    s3 = FakeTopologyS3(body)
    provider = S3TopologyProvider(
        s3,
        bucket="pilo-topology-private",
        key="config/pilo-topology.yaml",
    )

    first = provider.load()
    second = provider.load()

    assert first is second
    assert len(first.services) == 8
    assert s3.calls == [{"Bucket": "pilo-topology-private", "Key": "config/pilo-topology.yaml"}]
    assert s3.body.read_amounts == [256_001]
    assert s3.body.closed is True


def test_invalid_protected_topology_fails_with_sanitized_error() -> None:
    provider = S3TopologyProvider(
        FakeTopologyS3(b"not: [valid"),
        bucket="pilo-topology-private",
        key="config/pilo-topology.yaml",
    )

    try:
        provider.load()
    except TopologyLoadError as error:
        assert str(error) == "protected topology is unavailable"
    else:
        raise AssertionError("invalid protected topology must fail closed")


def test_oversized_protected_topology_fails_before_parsing() -> None:
    provider = S3TopologyProvider(
        FakeTopologyS3(b"x" * 256_001),
        bucket="pilo-topology-private",
        key="config/pilo-topology.yaml",
    )

    with pytest.raises(TopologyLoadError, match="protected topology is unavailable"):
        provider.load()


class FakeLambdaRuntime:
    def __init__(self) -> None:
        self.events: list[dict[str, JsonValue]] = []

    def handle(self, event: dict[str, JsonValue]) -> dict[str, str]:
        self.events.append(event)
        return {"incident_id": "inc-00000000000000000000", "status": "published"}


def runtime_config() -> RuntimeConfig:
    return RuntimeConfig(
        region="ap-northeast-2",
        topology_bucket="pilo-topology-private",
        topology_key="config/pilo-topology.yaml",
        state_table="pilo-incident-state",
        bundle_bucket="pilo-incident-bundles",
        github_repository="synthetic-org/private-incidents",
        github_token_parameter="/pilo/investigator/github-token",
        slack_webhook_parameter="/pilo/investigator/slack-webhook",
        bedrock_model_id="apac.anthropic.claude-test-v1:0",
    )


def test_lambda_handler_builds_runtime_once_per_warm_process(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = runtime_config()
    runtime = FakeLambdaRuntime()
    builds: list[RuntimeConfig] = []

    def fake_build(actual: RuntimeConfig) -> FakeLambdaRuntime:
        builds.append(actual)
        return runtime

    monkeypatch.setattr(
        RuntimeConfig,
        "from_environment",
        classmethod(lambda cls: config),
    )
    monkeypatch.setattr(handler_module, "build_runtime", fake_build)
    monkeypatch.setattr(handler_module, "_RUNTIME", None)
    event = load_json("tests/fixtures/events/alarm.json")

    first = handler_module.lambda_handler(event, object())
    second = handler_module.lambda_handler(event, object())

    assert (
        first
        == second
        == {
            "incident_id": "inc-00000000000000000000",
            "status": "published",
        }
    )
    assert builds == [config]
    assert runtime.events == [event, event]


class FakeSsm:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def get_parameter(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(kwargs)
        if kwargs["Name"] == "/pilo/investigator/github-token":
            return {"Parameter": {"Value": "synthetic-github-token"}}
        return {"Parameter": {"Value": "https://hooks.slack.com/services/TEST/ONLY/SYNTHETIC"}}


class FakeAwsClient:
    pass


class FakeDynamoResource:
    def __init__(self) -> None:
        self.tables: list[str] = []

    def Table(self, name: str) -> object:  # noqa: N802
        self.tables.append(name)
        return object()


class FakeSession:
    def __init__(self) -> None:
        self.clients: list[str] = []
        self.ssm = FakeSsm()
        self.dynamo = FakeDynamoResource()

    def client(self, name: str) -> object:
        self.clients.append(name)
        return self.ssm if name == "ssm" else FakeAwsClient()

    def resource(self, name: str) -> FakeDynamoResource:
        assert name == "dynamodb"
        return self.dynamo


def test_build_runtime_composes_only_expected_clients_without_live_calls() -> None:
    session = FakeSession()
    runtime = handler_module.build_runtime(runtime_config(), session=session)

    assert isinstance(runtime, Runtime)
    assert session.clients == [
        "s3",
        "ecs",
        "logs",
        "rds",
        "ssm",
        "bedrock-runtime",
        "secretsmanager",
        "sqs",
        "elbv2",
    ]
    assert session.dynamo.tables == ["pilo-incident-state"]
    assert session.ssm.calls == [
        {"Name": "/pilo/investigator/github-token", "WithDecryption": True},
        {"Name": "/pilo/investigator/slack-webhook", "WithDecryption": True},
    ]
