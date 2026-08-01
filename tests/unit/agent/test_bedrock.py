import json
from datetime import UTC, datetime
from typing import Any

import pytest

from pilo_incident_investigator.agent.bedrock import BedrockPlanner, PlannerOutputError
from pilo_incident_investigator.domain import Evidence, Snapshot


class FakeBedrockClient:
    def __init__(self, output: str | BaseException) -> None:
        self.output = output
        self.requests: list[dict[str, Any]] = []

    def converse(self, **kwargs: Any) -> dict[str, Any]:
        self.requests.append(kwargs)
        if isinstance(self.output, BaseException):
            raise self.output
        return {"output": {"message": {"role": "assistant", "content": [{"text": self.output}]}}}


def snapshot() -> Snapshot:
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
        failures=(),
    )


def valid_proposal_json(*, requests: str = "[]") -> str:
    return (
        '{"tool_requests":'
        + requests
        + ',"facts":[{"text":"no running task","evidence_ids":["E-001"]}],'
        '"directions":[{"text":"inspect stopped tasks","evidence_ids":["E-001"]}],'
        '"missing":["stopped task reason"],"classification":"unclassified"}'
    )


def test_propose_decodes_evidence_backed_tool_request_and_sends_bounded_context() -> None:
    request_json = (
        '[{"tool":"service_log_search","resource_key":"/aws/ecs/pilo-dev-service-01",'
        '"parameters":{"query":"ERROR"},"reason":"E-001 shows no running task"}]'
    )
    client = FakeBedrockClient(valid_proposal_json(requests=request_json))
    planner = BedrockPlanner(client, model_id="model-test")

    proposal = planner.propose(snapshot(), (), remaining_budget=2)

    assert proposal.tool_requests[0].tool == "service_log_search"
    assert proposal.tool_requests[0].reason == "E-001 shows no running task"
    sent = client.requests[0]
    assert sent["modelId"] == "model-test"
    assert "toolConfig" not in sent
    prompt = sent["messages"][0]["content"][0]["text"]
    payload = json.loads(prompt)
    assert payload["remaining_budget"] == 2
    assert len(payload["permitted_tools"]) == 5
    assert payload["permitted_tools"][0] == {
        "name": "github_changed_files",
        "parameters": "JSON object",
        "reason": "non-empty string citing current Evidence ID",
        "resource_key": "topology-allowlisted string",
    }
    assert "inc-test" not in prompt
    assert "alarm" not in prompt.lower()


@pytest.mark.parametrize(
    "output",
    [
        "not-json",
        '{"tool_requests":[],"facts":[],"directions":[],"missing":[],'
        '"classification":"unclassified","extra":true}',
        valid_proposal_json(
            requests='[{"tool":"unknown","resource_key":"x","parameters":{},"reason":"why"}]'
        ),
        valid_proposal_json(
            requests='[{"tool":"sqs_status","resource_key":"x","parameters":{},"reason":" "}]'
        ),
        valid_proposal_json(
            requests='[{"tool":"sqs_status","resource_key":"x","parameters":{},'
            '"reason":"queue state is needed"}]'
        ),
        '{"tool_requests":[],"facts":[{"text":"claim","evidence_ids":["E-999"]}],'
        '"directions":[],"missing":[],"classification":"unclassified"}',
    ],
    ids=[
        "malformed",
        "unknown-field",
        "unknown-tool",
        "blank-reason",
        "uncited-reason",
        "invalid-citation",
    ],
)
def test_propose_rejects_malformed_or_unsupported_output(output: str) -> None:
    planner = BedrockPlanner(FakeBedrockClient(output), model_id="model-test")

    with pytest.raises(PlannerOutputError):
        planner.propose(snapshot(), (), remaining_budget=3)


def test_propose_rejects_more_than_round_or_remaining_budget_without_truncation() -> None:
    one = '{"tool":"sqs_status","resource_key":"queue","parameters":{},"reason":"needed"}'
    planner = BedrockPlanner(
        FakeBedrockClient(valid_proposal_json(requests=f"[{one},{one},{one},{one}]")),
        model_id="model-test",
    )

    with pytest.raises(PlannerOutputError):
        planner.propose(snapshot(), (), remaining_budget=3)

    planner = BedrockPlanner(
        FakeBedrockClient(valid_proposal_json(requests=f"[{one},{one}]")),
        model_id="model-test",
    )
    with pytest.raises(PlannerOutputError):
        planner.propose(snapshot(), (), remaining_budget=1)


def test_summarize_omits_tool_schema_and_returns_no_tool_calls() -> None:
    output = (
        '{"facts":[{"text":"no running task","evidence_ids":["E-001"]}],'
        '"directions":[],"missing":["task reason"],"classification":"unclassified"}'
    )
    client = FakeBedrockClient(output)
    planner = BedrockPlanner(client, model_id="model-test")

    investigation = planner.summarize(snapshot())

    assert investigation.tool_calls == ()
    prompt = client.requests[0]["messages"][0]["content"][0]["text"]
    assert "permitted_tools" not in prompt
    assert "tool_requests" not in prompt
