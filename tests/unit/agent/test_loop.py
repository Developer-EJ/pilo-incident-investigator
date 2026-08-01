from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

import pytest
from botocore.exceptions import ClientError

from pilo_incident_investigator.agent.bedrock import PlannerOutputError
from pilo_incident_investigator.agent.contracts import AgentProposal
from pilo_incident_investigator.agent.loop import InvestigationAgent
from pilo_incident_investigator.agent.tools import TOOL_NAMES, ToolHandler, ToolRegistry
from pilo_incident_investigator.domain import (
    CollectorFailure,
    Evidence,
    Investigation,
    Snapshot,
    SupportedStatement,
    ToolRequest,
    ToolResult,
)
from pilo_incident_investigator.topology import Topology


class ScriptedPlanner:
    def __init__(
        self,
        outputs: Sequence[AgentProposal | BaseException],
        *,
        summary: Investigation | BaseException | None = None,
    ) -> None:
        self.outputs = list(outputs)
        self.summary = summary
        self.call_count = 0
        self.remaining_budgets: list[int] = []
        self.summarize_count = 0
        self.summarized_results: tuple[ToolResult, ...] = ()

    def propose(
        self,
        snapshot: Snapshot,
        prior_results: tuple[ToolResult, ...],
        remaining_budget: int,
    ) -> AgentProposal:
        del snapshot, prior_results
        self.remaining_budgets.append(remaining_budget)
        output = self.outputs[self.call_count]
        self.call_count += 1
        if isinstance(output, BaseException):
            raise output
        return output

    def summarize(
        self, snapshot: Snapshot, tool_results: tuple[ToolResult, ...] = ()
    ) -> Investigation:
        self.summarize_count += 1
        self.summarized_results = tool_results
        if isinstance(self.summary, BaseException):
            raise self.summary
        if self.summary is not None:
            return self.summary
        citation = tool_results[-1].evidence[-1].evidence_id
        return Investigation(
            facts=(SupportedStatement("final tool-supported fact", (citation,)),),
            directions=(SupportedStatement("follow the final evidence", (citation,)),),
            missing=(),
            classification="tool_supported",
            tool_calls=tool_results,
            classification_evidence_ids=(citation,),
        )


class RecordingHandler(ToolHandler):
    def __init__(self) -> None:
        self.requests: list[ToolRequest] = []

    def execute(self, request: ToolRequest) -> ToolResult:
        self.requests.append(request)
        index = len(self.requests)
        return ToolResult(
            request=request,
            evidence=(
                Evidence(
                    evidence_id=f"T-{request.tool}-{index}",
                    source=request.tool,
                    observed_at=datetime(2026, 8, 1, tzinfo=UTC),
                    summary="additional evidence",
                    data={"index": index},
                ),
            ),
            failure=None,
        )


def snapshot(*, failures: tuple[CollectorFailure, ...] = ()) -> Snapshot:
    return Snapshot(
        incident_id="inc-test",
        evidence=(
            Evidence(
                evidence_id="E-001",
                source="ecs.describe_services",
                observed_at=datetime(2026, 8, 1, tzinfo=UTC),
                summary="service has no running task",
                data={"running": 0},
            ),
        ),
        failures=failures,
    )


def topology() -> Topology:
    return Topology.load(Path("tests/fixtures/topology/valid.yaml").read_text(encoding="utf-8"))


def request(tool: str, resource_key: str, index: int) -> ToolRequest:
    return ToolRequest(
        tool=tool,
        resource_key=resource_key,
        parameters={"index": index},
        reason="E-001 requires a bounded follow-up",
    )


def proposal(
    *requests: ToolRequest,
    citation: str = "E-001",
    classification: str = "unclassified",
    classification_evidence_ids: tuple[str, ...] = (),
) -> AgentProposal:
    return AgentProposal(
        tool_requests=requests,
        facts=(SupportedStatement("service is stopped", (citation,)),),
        directions=(SupportedStatement("inspect service logs", (citation,)),),
        missing=("application failure reason",),
        classification=classification,
        classification_evidence_ids=classification_evidence_ids,
    )


def registry() -> tuple[ToolRegistry, RecordingHandler]:
    handler = RecordingHandler()
    return ToolRegistry({name: handler for name in TOOL_NAMES}), handler


def test_agent_executes_at_most_two_rounds_and_six_tools() -> None:
    valid = topology()
    log_group = valid.services[0].log_groups[0]
    queue = valid.services[0].queues[0]
    repository = valid.services[0].github_repository
    planner = ScriptedPlanner(
        [
            proposal(
                request("service_log_search", log_group, 1),
                request("sqs_status", queue, 2),
                request("github_changed_files", repository, 3),
            ),
            proposal(
                request("service_log_search", log_group, 4),
                request("sqs_status", queue, 5),
                request("github_changed_files", repository, 6),
            ),
            proposal(request("sqs_status", queue, 7)),
        ]
    )
    tools, handler = registry()

    result = InvestigationAgent(planner, tools).run(snapshot(), valid)

    assert len(result.tool_calls) == 6
    assert len(handler.requests) == 6
    assert planner.call_count == 2
    assert planner.remaining_budgets == [6, 3]
    assert planner.summarize_count == 1
    assert len(planner.summarized_results) == 6
    assert result.facts == (
        SupportedStatement("final tool-supported fact", ("T-github_changed_files-6",)),
    )


def test_agent_finalizes_once_after_tools_when_later_proposal_requests_none() -> None:
    valid = topology()
    planner = ScriptedPlanner(
        [
            proposal(request("sqs_status", valid.services[0].queues[0], 1)),
            proposal(),
        ]
    )
    tools, handler = registry()

    result = InvestigationAgent(planner, tools).run(snapshot(), valid)

    assert planner.call_count == 2
    assert planner.summarize_count == 1
    assert len(handler.requests) == 1
    assert result.facts[0].evidence_ids == ("T-sqs_status-1",)
    assert result.classification_evidence_ids == ("T-sqs_status-1",)


def test_agent_falls_back_if_final_synthesis_fails_and_preserves_tools() -> None:
    valid = topology()
    planner = ScriptedPlanner(
        [
            proposal(request("sqs_status", valid.services[0].queues[0], 1)),
            proposal(),
        ],
        summary=RuntimeError("raw final synthesis failure"),
    )
    tools, handler = registry()

    result = InvestigationAgent(planner, tools).run(snapshot(), valid)

    assert planner.call_count == 2
    assert planner.summarize_count == 1
    assert len(handler.requests) == 1
    assert len(result.tool_calls) == 1
    assert result.classification == "unclassified"
    assert result.classification_evidence_ids == ()
    assert "raw final" not in repr(result)


@pytest.mark.parametrize(
    "failure",
    [
        TimeoutError("sensitive upstream details"),
        ClientError(
            {"Error": {"Code": "ThrottlingException", "Message": "sensitive upstream details"}},
            "Converse",
        ),
        PlannerOutputError("malformed output with sensitive details"),
    ],
    ids=["timeout", "throttling", "malformed-output"],
)
def test_agent_returns_snapshot_fallback_without_tool_execution(failure: BaseException) -> None:
    planner = ScriptedPlanner([failure])
    tools, handler = registry()

    result = InvestigationAgent(planner, tools).run(snapshot(), topology())

    assert result.classification == "unclassified"
    assert result.facts == ()
    assert result.directions == ()
    assert result.tool_calls == ()
    assert handler.requests == []
    assert result.missing == ("추가 조사를 완료하지 못했습니다.",)


def test_snapshot_fallback_records_collector_failure_count_without_raw_detail() -> None:
    planner = ScriptedPlanner([TimeoutError("model secret")])
    tools, _ = registry()
    partial = snapshot(
        failures=(
            CollectorFailure(
                collector="ecs",
                code="aws_api_error",
                detail="raw account identifier and exception",
            ),
        )
    )

    result = InvestigationAgent(planner, tools).run(partial, topology())

    assert result.missing == (
        "추가 조사를 완료하지 못했습니다.",
        "기본 Snapshot 수집 실패 1건이 있습니다.",
    )
    assert "account identifier" not in repr(result)


def test_agent_preserves_completed_tools_when_later_planner_call_fails() -> None:
    valid = topology()
    planner = ScriptedPlanner(
        [
            proposal(request("sqs_status", valid.services[0].queues[0], 1)),
            RuntimeError("model unavailable"),
        ]
    )
    tools, handler = registry()

    result = InvestigationAgent(planner, tools).run(snapshot(), valid)

    assert result.classification == "unclassified"
    assert len(result.tool_calls) == 1
    assert len(handler.requests) == 1
    assert result.facts == ()


@pytest.mark.parametrize("violation", ["duplicate", "topology", "oversized"])
def test_agent_denies_invalid_request_set_before_executing_that_set(violation: str) -> None:
    valid = topology()
    allowed = valid.services[0].queues[0]
    first = request("sqs_status", allowed, 1)
    bad_requests: tuple[ToolRequest, ...]
    if violation == "duplicate":
        bad_requests = (first, first)
    elif violation == "topology":
        bad_requests = (request("sqs_status", "https://example.invalid/not-allowed", 1),)
    else:
        bad_requests = tuple(request("sqs_status", allowed, index) for index in range(4))
    planner = ScriptedPlanner([proposal(*bad_requests)])
    tools, handler = registry()

    result = InvestigationAgent(planner, tools).run(snapshot(), valid)

    assert result.classification == "unclassified"
    assert result.tool_calls == ()
    assert handler.requests == []


def test_agent_rejects_invalid_statement_citation_before_tool_execution() -> None:
    valid = topology()
    planner = ScriptedPlanner(
        [proposal(request("sqs_status", valid.services[0].queues[0], 1), citation="E-999")]
    )
    tools, handler = registry()

    result = InvestigationAgent(planner, tools).run(snapshot(), valid)

    assert result.classification == "unclassified"
    assert result.tool_calls == ()
    assert handler.requests == []


def test_agent_rejects_tool_reason_evidence_prefix_collision() -> None:
    valid = topology()
    bad_request = ToolRequest(
        tool="sqs_status",
        resource_key=valid.services[0].queues[0],
        parameters={},
        reason="E-0010 is not current Evidence",
    )
    planner = ScriptedPlanner([proposal(bad_request)])
    tools, handler = registry()

    result = InvestigationAgent(planner, tools).run(snapshot(), valid)

    assert result.classification == "unclassified"
    assert result.tool_calls == ()
    assert handler.requests == []


@pytest.mark.parametrize("citation_ids", [(), ("E-999",)])
def test_agent_rejects_classification_without_current_evidence(
    citation_ids: tuple[str, ...],
) -> None:
    planner = ScriptedPlanner(
        [
            proposal(
                classification="ecs_oom",
                classification_evidence_ids=citation_ids,
            )
        ]
    )
    tools, _ = registry()

    result = InvestigationAgent(planner, tools).run(snapshot(), topology())

    assert result.classification == "unclassified"
    assert result.classification_evidence_ids == ()


def test_agent_returns_successful_evidence_backed_no_tool_investigation() -> None:
    planner = ScriptedPlanner([proposal()])
    tools, handler = registry()

    result = InvestigationAgent(planner, tools).run(snapshot(), topology())

    assert result.facts == (SupportedStatement("service is stopped", ("E-001",)),)
    assert result.directions == (SupportedStatement("inspect service logs", ("E-001",)),)
    assert result.classification == "unclassified"
    assert result.classification_evidence_ids == ()
    assert result.tool_calls == ()
    assert handler.requests == []
    assert planner.call_count == 1
