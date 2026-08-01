"""Lambda composition root and one-event runtime orchestration."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, Protocol, cast

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from pilo_incident_investigator.agent.bedrock import (
    BedrockPlanner,
    BedrockRuntimeClient,
    Planner,
)
from pilo_incident_investigator.agent.loop import InvestigationAgent
from pilo_incident_investigator.agent.tools import (
    AwsClient as ToolAwsClient,
)
from pilo_incident_investigator.agent.tools import (
    GitHubChangedFilesTool,
    RdsEventsTool,
    SecretRotationMetadataTool,
    ServiceLogSearchTool,
    SqsStatusTool,
    ToolRegistry,
)
from pilo_incident_investigator.brief import render_issue_markdown
from pilo_incident_investigator.bundle import canonical_bundle_json
from pilo_incident_investigator.collectors.aws import AwsClient as CollectorAwsClient
from pilo_incident_investigator.collectors.aws import default_collectors
from pilo_incident_investigator.config import RuntimeConfig, RuntimeMode
from pilo_incident_investigator.domain import (
    AlarmEvent,
    IncidentBundle,
    Investigation,
    JsonValue,
    Snapshot,
)
from pilo_incident_investigator.event import incident_id_for, parse_alarm_event
from pilo_incident_investigator.integrations.credentials import SsmClient, SsmCredentialProvider
from pilo_incident_investigator.integrations.github import GitHubClient
from pilo_incident_investigator.publishers import (
    PublicationPayload,
    Publisher,
    PublishResult,
    SlackWebhookClient,
)
from pilo_incident_investigator.publishers import (
    S3Client as PublisherS3Client,
)
from pilo_incident_investigator.redaction import Redactor
from pilo_incident_investigator.snapshot import SnapshotCollector
from pilo_incident_investigator.state import DynamoIncidentStateStore, DynamoTable
from pilo_incident_investigator.topology import Topology

_LOGGER = logging.getLogger(__name__)
_MAX_TOPOLOGY_BYTES = 256_000


class RuntimeState(Protocol):
    def claim_event(self, event_id: str, incident_id: str) -> bool: ...

    def mark_snapshot_complete(self, event_id: str) -> bool: ...


class TopologyProvider(Protocol):
    def load(self) -> Topology: ...


class SnapshotSource(Protocol):
    def collect(self, event: AlarmEvent, topology: Topology) -> Snapshot: ...


class AgentRunner(Protocol):
    def run(self, snapshot: Snapshot, topology: Topology) -> Investigation: ...


class IncidentPublisher(Protocol):
    def publish(self, publication: PublicationPayload) -> PublishResult: ...


class TopologyBody(Protocol):
    def read(self, amount: int | None = None) -> bytes: ...

    def close(self) -> None: ...


class TopologyObjectClient(Protocol):
    def get_object(self, **kwargs: Any) -> dict[str, Any]: ...


class RuntimeStateError(RuntimeError):
    """Raised when a claimed event cannot advance its durable checkpoint."""


class TopologyLoadError(RuntimeError):
    """Sanitized protected-topology loading failure."""


class S3TopologyProvider:
    """Load and validate the protected topology once per warm Lambda process."""

    def __init__(self, client: TopologyObjectClient, *, bucket: str, key: str) -> None:
        self._client = client
        self._bucket = bucket
        self._key = key
        self._cached: Topology | None = None

    def load(self) -> Topology:
        if self._cached is not None:
            return self._cached
        try:
            response = self._client.get_object(Bucket=self._bucket, Key=self._key)
            body = cast(TopologyBody, response["Body"])
            try:
                raw = body.read(_MAX_TOPOLOGY_BYTES + 1)
            finally:
                body.close()
            if not isinstance(raw, bytes) or not 1 <= len(raw) <= _MAX_TOPOLOGY_BYTES:
                raise ValueError
            topology = Topology.load(raw.decode("utf-8"))
        except (
            BotoCoreError,
            ClientError,
            AttributeError,
            KeyError,
            OSError,
            TypeError,
            UnicodeError,
            ValueError,
        ):
            raise TopologyLoadError("protected topology is unavailable") from None
        self._cached = topology
        return topology


class Runtime:
    def __init__(
        self,
        *,
        mode: RuntimeMode,
        topology: TopologyProvider,
        snapshots: SnapshotSource,
        planner: Planner,
        hybrid_agent: AgentRunner,
        state: RuntimeState,
        publisher: IncidentPublisher,
        now: Callable[[], datetime] | None = None,
        monotonic: Callable[[], float] | None = None,
    ) -> None:
        if mode not in {"snapshot_only", "hybrid_agent"}:
            raise ValueError("runtime mode is invalid")
        self._mode = mode
        self._topology = topology
        self._snapshots = snapshots
        self._planner = planner
        self._hybrid_agent = hybrid_agent
        self._state = state
        self._publisher = publisher
        self._now = now or (lambda: datetime.now(UTC))
        self._monotonic = monotonic or time.monotonic

    def handle(self, event: dict[str, JsonValue]) -> dict[str, str]:
        started = self._monotonic()
        incident_id = "unavailable"
        stage = "parse_event"
        try:
            alarm = parse_alarm_event(event)
            incident_id = incident_id_for(alarm.event_id)
            stage = "load_topology"
            topology = self._topology.load()
            stage = "claim_event"
            if not self._state.claim_event(alarm.event_id, incident_id):
                self._log(incident_id, "duplicate", started)
                return {"incident_id": incident_id, "status": "duplicate"}

            stage = "snapshot"
            snapshot = self._snapshots.collect(alarm, topology)
            if not self._state.mark_snapshot_complete(alarm.event_id):
                raise RuntimeStateError("snapshot checkpoint was not recorded")

            stage = "investigation"
            if self._mode == "snapshot_only":
                investigation = self._planner.summarize(snapshot, tool_results=())
            else:
                investigation = self._hybrid_agent.run(snapshot, topology)

            stage = "render"
            bundle = IncidentBundle(
                incident_id=incident_id,
                alarm=alarm,
                snapshot=snapshot,
                investigation=investigation,
                created_at=self._now(),
                metadata={"mode": self._mode},
            )
            safe_bundle, _ = Redactor().redact_bundle(bundle)
            publication = PublicationPayload(
                event_id=alarm.event_id,
                incident_id=incident_id,
                bundle_bytes=canonical_bundle_json(safe_bundle),
                issue_markdown=render_issue_markdown(safe_bundle),
                slack_summary=f"classification={safe_bundle.investigation.classification}"[:500],
            )

            stage = "publish"
            result = self._publisher.publish(publication)
            status = (
                "published"
                if result.issue_url is not None and result.slack_status == "sent"
                else "degraded"
            )
            self._log(incident_id, status, started)
            return {"incident_id": incident_id, "status": status}
        except Exception as error:
            _LOGGER.error(
                "incident_failed",
                extra={
                    "incident_id": incident_id,
                    "stage": stage,
                    "duration_ms": _duration_ms(started, self._monotonic()),
                    "failure_code": type(error).__name__,
                },
            )
            raise

    def _log(self, incident_id: str, stage: str, started: float) -> None:
        _LOGGER.info(
            "incident_complete",
            extra={
                "incident_id": incident_id,
                "stage": stage,
                "duration_ms": _duration_ms(started, self._monotonic()),
            },
        )


def build_runtime(config: RuntimeConfig, *, session: Any | None = None) -> Runtime:
    aws_session = session if session is not None else boto3.Session(region_name=config.region)
    s3 = aws_session.client("s3")
    ecs = cast(CollectorAwsClient, aws_session.client("ecs"))
    logs = aws_session.client("logs")
    rds = aws_session.client("rds")
    credentials = SsmCredentialProvider(
        cast(SsmClient, aws_session.client("ssm")),
        config.github_token_parameter,
        config.slack_webhook_parameter,
    )
    github = GitHubClient(credentials.github_token())
    planner = BedrockPlanner(
        cast(BedrockRuntimeClient, aws_session.client("bedrock-runtime")),
        model_id=config.bedrock_model_id,
    )
    registry = ToolRegistry(
        {
            "service_log_search": ServiceLogSearchTool(cast(ToolAwsClient, logs)),
            "rds_events": RdsEventsTool(cast(ToolAwsClient, rds)),
            "secret_rotation_metadata": SecretRotationMetadataTool(
                cast(ToolAwsClient, aws_session.client("secretsmanager"))
            ),
            "sqs_status": SqsStatusTool(cast(ToolAwsClient, aws_session.client("sqs"))),
            "github_changed_files": GitHubChangedFilesTool(github),
        }
    )
    state = DynamoIncidentStateStore(
        cast(DynamoTable, aws_session.resource("dynamodb").Table(config.state_table))
    )
    snapshots = SnapshotCollector(
        default_collectors(
            ecs,
            cast(CollectorAwsClient, logs),
            cast(CollectorAwsClient, aws_session.client("elbv2")),
            cast(CollectorAwsClient, rds),
            github,
        )
    )
    return Runtime(
        mode=config.mode,
        topology=S3TopologyProvider(
            cast(TopologyObjectClient, s3),
            bucket=config.topology_bucket,
            key=config.topology_key,
        ),
        snapshots=snapshots,
        planner=planner,
        hybrid_agent=InvestigationAgent(planner, registry),
        state=state,
        publisher=Publisher(
            bundle_bucket=config.bundle_bucket,
            github_repository=config.github_repository,
            s3=cast(PublisherS3Client, s3),
            github=github,
            slack=SlackWebhookClient(credentials.slack_webhook_url()),
            state=state,
        ),
    )


_RUNTIME: Runtime | None = None


def lambda_handler(event: dict[str, JsonValue], context: object) -> dict[str, str]:
    del context
    global _RUNTIME
    if _RUNTIME is None:
        _RUNTIME = build_runtime(RuntimeConfig.from_environment())
    return _RUNTIME.handle(event)


def _duration_ms(started: float, finished: float) -> int:
    return max(0, round((finished - started) * 1_000))
