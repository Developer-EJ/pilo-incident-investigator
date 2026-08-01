"""Strict Bedrock Converse adapter for bounded incident investigation planning."""

import json
from typing import Any, Protocol, cast

from pilo_incident_investigator.agent.contracts import AgentProposal
from pilo_incident_investigator.agent.tools import TOOL_NAMES
from pilo_incident_investigator.domain import (
    Evidence,
    Investigation,
    JsonValue,
    Snapshot,
    SupportedStatement,
    ToolRequest,
    ToolResult,
)

MAX_TOOLS_PER_PROPOSAL = 3


class BedrockRuntimeClient(Protocol):
    def converse(self, **kwargs: Any) -> dict[str, Any]: ...


class Planner(Protocol):
    def propose(
        self,
        snapshot: Snapshot,
        prior_results: tuple[ToolResult, ...],
        remaining_budget: int,
    ) -> AgentProposal: ...

    def summarize(
        self,
        snapshot: Snapshot,
        tool_results: tuple[ToolResult, ...] = (),
    ) -> Investigation: ...


class PlannerOutputError(ValueError):
    """Raised when a model response cannot be accepted as supported output."""


class BedrockPlanner:
    def __init__(self, client: BedrockRuntimeClient, *, model_id: str) -> None:
        if not model_id.strip():
            raise ValueError("model_id must be non-empty")
        self._client = client
        self._model_id = model_id

    def propose(
        self,
        snapshot: Snapshot,
        prior_results: tuple[ToolResult, ...],
        remaining_budget: int,
    ) -> AgentProposal:
        if isinstance(remaining_budget, bool) or not 0 <= remaining_budget <= 6:
            raise ValueError("remaining_budget must be between zero and six")
        evidence = _all_evidence(snapshot, prior_results)
        permitted_tools: list[JsonValue] = []
        permitted_tools.extend(
            {
                "name": name,
                "resource_key": "topology-allowlisted string",
                "parameters": "JSON object",
                "reason": "non-empty string citing current Evidence ID",
            }
            for name in sorted(TOOL_NAMES)
        )
        payload: dict[str, JsonValue] = {
            "snapshot_evidence": [_encode_evidence(item) for item in snapshot.evidence],
            "prior_tool_evidence": [
                _encode_evidence(item) for result in prior_results for item in result.evidence
            ],
            "permitted_tools": permitted_tools,
            "remaining_budget": remaining_budget,
        }
        raw = self._converse(
            "Return one JSON object with tool_requests, facts, directions, missing, and "
            "classification. Cite only supplied Evidence IDs.",
            payload,
        )
        return _decode_proposal(
            raw, frozenset(item.evidence_id for item in evidence), remaining_budget
        )

    def summarize(
        self,
        snapshot: Snapshot,
        tool_results: tuple[ToolResult, ...] = (),
    ) -> Investigation:
        evidence = _all_evidence(snapshot, tool_results)
        payload: dict[str, JsonValue] = {
            "snapshot_evidence": [_encode_evidence(item) for item in snapshot.evidence],
            "prior_tool_evidence": [
                _encode_evidence(item) for result in tool_results for item in result.evidence
            ],
        }
        raw = self._converse(
            "Return one JSON object with facts, directions, missing, and classification. "
            "Cite only supplied Evidence IDs. Do not request tools.",
            payload,
        )
        facts, directions, missing, classification = _decode_summary(
            raw, frozenset(item.evidence_id for item in evidence)
        )
        return Investigation(
            facts=facts,
            directions=directions,
            missing=missing,
            classification=classification,
            tool_calls=tool_results,
        )

    def _converse(self, instruction: str, payload: dict[str, JsonValue]) -> object:
        response = self._client.converse(
            modelId=self._model_id,
            system=[{"text": instruction}],
            messages=[
                {
                    "role": "user",
                    "content": [
                        {
                            "text": json.dumps(
                                payload,
                                ensure_ascii=False,
                                separators=(",", ":"),
                                sort_keys=True,
                            )
                        }
                    ],
                }
            ],
        )
        try:
            output = response["output"]
            message = output["message"]
            content = message["content"]
            text = content[0]["text"]
        except (KeyError, IndexError, TypeError):
            raise PlannerOutputError("model response shape is invalid") from None
        if not isinstance(text, str):
            raise PlannerOutputError("model response text is invalid")
        try:
            return json.loads(text)
        except (json.JSONDecodeError, RecursionError):
            raise PlannerOutputError("model response is not valid JSON") from None


def _all_evidence(snapshot: Snapshot, tool_results: tuple[ToolResult, ...]) -> tuple[Evidence, ...]:
    return snapshot.evidence + tuple(item for result in tool_results for item in result.evidence)


def _encode_evidence(evidence: Evidence) -> dict[str, JsonValue]:
    return {
        "evidence_id": evidence.evidence_id,
        "source": evidence.source,
        "observed_at": evidence.observed_at.isoformat(),
        "summary": evidence.summary,
        "data": evidence.data,
    }


def _decode_proposal(
    raw: object, allowed_evidence: frozenset[str], remaining_budget: int
) -> AgentProposal:
    row = _exact_mapping(
        raw,
        {"tool_requests", "facts", "directions", "missing", "classification"},
        "proposal",
    )
    requests_raw = row["tool_requests"]
    if not isinstance(requests_raw, list):
        raise PlannerOutputError("tool_requests must be a list")
    if len(requests_raw) > MAX_TOOLS_PER_PROPOSAL or len(requests_raw) > remaining_budget:
        raise PlannerOutputError("tool request budget exceeded")
    requests = tuple(_decode_request(item, allowed_evidence) for item in requests_raw)
    facts = _decode_statements(row["facts"], allowed_evidence, "facts")
    directions = _decode_statements(row["directions"], allowed_evidence, "directions")
    missing = _decode_missing(row["missing"])
    classification = _non_empty_string(row["classification"], "classification")
    return AgentProposal(requests, facts, directions, missing, classification)


def _decode_summary(
    raw: object, allowed_evidence: frozenset[str]
) -> tuple[
    tuple[SupportedStatement, ...],
    tuple[SupportedStatement, ...],
    tuple[str, ...],
    str,
]:
    row = _exact_mapping(raw, {"facts", "directions", "missing", "classification"}, "summary")
    return (
        _decode_statements(row["facts"], allowed_evidence, "facts"),
        _decode_statements(row["directions"], allowed_evidence, "directions"),
        _decode_missing(row["missing"]),
        _non_empty_string(row["classification"], "classification"),
    )


def _decode_request(raw: object, allowed_evidence: frozenset[str]) -> ToolRequest:
    row = _exact_mapping(raw, {"tool", "resource_key", "parameters", "reason"}, "tool request")
    tool = _non_empty_string(row["tool"], "tool")
    if tool not in TOOL_NAMES:
        raise PlannerOutputError("unknown Tool")
    resource_key = _non_empty_string(row["resource_key"], "resource_key")
    reason = _non_empty_string(row["reason"], "reason")
    if not any(evidence_id in reason for evidence_id in allowed_evidence):
        raise PlannerOutputError("Tool selection reason must cite available Evidence")
    parameters = row["parameters"]
    if not isinstance(parameters, dict) or any(not isinstance(key, str) for key in parameters):
        raise PlannerOutputError("parameters must be a JSON object")
    try:
        return ToolRequest(
            tool=tool,
            resource_key=resource_key,
            parameters=cast(dict[str, JsonValue], parameters),
            reason=reason,
        )
    except (TypeError, ValueError):
        raise PlannerOutputError("Tool request contains invalid parameters") from None


def _decode_statements(
    raw: object, allowed_evidence: frozenset[str], field: str
) -> tuple[SupportedStatement, ...]:
    if not isinstance(raw, list):
        raise PlannerOutputError(f"{field} must be a list")
    statements: list[SupportedStatement] = []
    for item in raw:
        row = _exact_mapping(item, {"text", "evidence_ids"}, field)
        text = _non_empty_string(row["text"], "statement text")
        citations = row["evidence_ids"]
        if (
            not isinstance(citations, list)
            or not citations
            or any(not isinstance(value, str) or not value for value in citations)
        ):
            raise PlannerOutputError("statement citations are invalid")
        evidence_ids = tuple(cast(list[str], citations))
        if len(evidence_ids) != len(set(evidence_ids)) or not set(evidence_ids) <= allowed_evidence:
            raise PlannerOutputError("statement cites unavailable Evidence")
        statements.append(SupportedStatement(text, evidence_ids))
    return tuple(statements)


def _decode_missing(raw: object) -> tuple[str, ...]:
    if not isinstance(raw, list):
        raise PlannerOutputError("missing must be a list")
    values = tuple(_non_empty_string(item, "missing item") for item in raw)
    return values


def _exact_mapping(raw: object, fields: set[str], name: str) -> dict[str, object]:
    if not isinstance(raw, dict) or any(not isinstance(key, str) for key in raw):
        raise PlannerOutputError(f"{name} must be an object")
    if set(raw) != fields:
        raise PlannerOutputError(f"{name} fields are invalid")
    return cast(dict[str, object], raw)


def _non_empty_string(raw: object, field: str) -> str:
    if not isinstance(raw, str) or not raw.strip():
        raise PlannerOutputError(f"{field} must be a non-empty string")
    return raw
