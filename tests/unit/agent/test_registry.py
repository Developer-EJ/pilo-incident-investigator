from pathlib import Path

import pytest

from pilo_incident_investigator.agent.contracts import AgentProposal
from pilo_incident_investigator.agent.tools import TOOL_NAMES, ToolDenied, ToolRegistry
from pilo_incident_investigator.domain import ToolRequest, ToolResult
from pilo_incident_investigator.topology import Topology

FIXTURE = Path(__file__).parents[2] / "fixtures" / "topology" / "valid.yaml"


class RecordingHandler:
    def __init__(self) -> None:
        self.requests: list[ToolRequest] = []

    def execute(self, request: ToolRequest) -> ToolResult:
        self.requests.append(request)
        return ToolResult(request=request, evidence=(), failure=None)


def topology() -> Topology:
    return Topology.load(FIXTURE.read_text(encoding="utf-8"))


def handlers() -> dict[str, RecordingHandler]:
    return {name: RecordingHandler() for name in TOOL_NAMES}


def request_for(
    tool: str = "sqs_status",
    resource_key: str = "https://sqs.ap-northeast-2.amazonaws.com/000000000000/pilo-dev-queue-01",
    reason: str = "Alarm 이후 backlog 여부 확인",
) -> ToolRequest:
    return ToolRequest(tool=tool, resource_key=resource_key, parameters={}, reason=reason)


def test_tool_names_are_exact_and_closed() -> None:
    assert (
        frozenset(
            {
                "service_log_search",
                "rds_events",
                "secret_rotation_metadata",
                "sqs_status",
                "github_changed_files",
            }
        )
        == TOOL_NAMES
    )


def test_registry_requires_exact_handler_set() -> None:
    incomplete = handlers()
    incomplete.pop("sqs_status")

    with pytest.raises(ValueError, match="exact Tool set"):
        ToolRegistry(incomplete)


def test_request_without_reason_is_rejected() -> None:
    registry = ToolRegistry(handlers())

    with pytest.raises(ToolDenied, match="reason is required"):
        registry.execute(request_for(reason="  "), topology(), set())


def test_identical_request_is_not_executed_twice() -> None:
    registry = ToolRegistry(handlers())
    request = request_for()
    seen = {request.deduplication_key()}

    with pytest.raises(ToolDenied, match="duplicate"):
        registry.execute(request, topology(), seen)


def test_unknown_tool_and_non_allowlisted_resource_are_rejected() -> None:
    registry = ToolRegistry(handlers())

    with pytest.raises(ToolDenied, match="unknown Tool"):
        registry.execute(request_for(tool="arbitrary_aws_call"), topology(), set())
    with pytest.raises(ToolDenied, match="not allowlisted"):
        registry.execute(request_for(resource_key="not-pilo"), topology(), set())


def test_successful_request_is_executed_once_and_marked_seen() -> None:
    selected_handlers = handlers()
    registry = ToolRegistry(selected_handlers)
    request = request_for()
    seen: set[str] = set()

    result = registry.execute(request, topology(), seen)

    assert result.request is request
    assert selected_handlers["sqs_status"].requests == [request]
    assert seen == {request.deduplication_key()}


def test_deduplication_key_uses_canonical_request_fields_only() -> None:
    first = ToolRequest(
        tool="sqs_status",
        resource_key="queue",
        parameters={"b": 2, "a": 1},
        reason="first reason",
    )
    reordered = ToolRequest(
        tool="sqs_status",
        resource_key="queue",
        parameters={"a": 1, "b": 2},
        reason="different reason",
    )

    assert first.deduplication_key() == reordered.deduplication_key()
    assert first.deduplication_key().startswith("tool-")


def test_agent_proposal_reuses_domain_tool_request() -> None:
    request = request_for()
    proposal = AgentProposal(
        tool_requests=(request,),
        facts=(),
        directions=(),
        missing=("추가 Evidence 필요",),
        classification="unclassified",
    )

    assert proposal.tool_requests == (request,)
