"""Bounded, fail-closed orchestration for additional incident investigation."""

from pilo_incident_investigator.agent.bedrock import Planner
from pilo_incident_investigator.agent.contracts import AgentProposal, cites_available_evidence
from pilo_incident_investigator.agent.tools import ToolRegistry
from pilo_incident_investigator.domain import (
    Investigation,
    Snapshot,
    SupportedStatement,
    ToolResult,
)
from pilo_incident_investigator.topology import Topology

MAX_ROUNDS = 2
MAX_TOOLS_PER_ROUND = 3
MAX_TOTAL_TOOLS = 6
FALLBACK_MISSING = ("추가 조사를 완료하지 못했습니다.",)


class InvestigationAgent:
    def __init__(self, planner: Planner, registry: ToolRegistry) -> None:
        self._planner = planner
        self._registry = registry

    def run(self, snapshot: Snapshot, topology: Topology) -> Investigation:
        executed: list[ToolResult] = []
        seen: set[str] = set()
        for _ in range(MAX_ROUNDS):
            remaining = MAX_TOTAL_TOOLS - len(executed)
            try:
                proposal = self._planner.propose(snapshot, tuple(executed), remaining)
                _validate_proposal(proposal, snapshot, tuple(executed), remaining)
                self._registry.validate_batch(proposal.tool_requests, topology, seen)
            except Exception:
                return _fallback(snapshot, tuple(executed))

            if not proposal.tool_requests:
                if executed:
                    return self._finalize(snapshot, tuple(executed))
                return _investigation(proposal, tuple(executed))

            try:
                for request in proposal.tool_requests:
                    executed.append(self._registry.execute(request, topology, seen))
            except Exception:
                return _fallback(snapshot, tuple(executed))

        return self._finalize(snapshot, tuple(executed))

    def _finalize(self, snapshot: Snapshot, tool_calls: tuple[ToolResult, ...]) -> Investigation:
        try:
            investigation = self._planner.summarize(snapshot, tool_calls)
            _validate_investigation(investigation, snapshot, tool_calls)
            return investigation
        except Exception:
            return _fallback(snapshot, tool_calls)


def _validate_proposal(
    proposal: AgentProposal,
    snapshot: Snapshot,
    prior_results: tuple[ToolResult, ...],
    remaining_budget: int,
) -> None:
    if not isinstance(proposal, AgentProposal):
        raise TypeError("planner returned an invalid proposal")
    if (
        len(proposal.tool_requests) > MAX_TOOLS_PER_ROUND
        or len(proposal.tool_requests) > remaining_budget
    ):
        raise ValueError("planner exceeded Tool budget")
    if not isinstance(proposal.classification, str) or not proposal.classification.strip():
        raise ValueError("classification is invalid")
    if any(not isinstance(item, str) or not item.strip() for item in proposal.missing):
        raise ValueError("missing information is invalid")
    allowed = _allowed_evidence(snapshot, prior_results)
    for request in proposal.tool_requests:
        if not cites_available_evidence(request.reason, allowed):
            raise ValueError("Tool selection reason does not cite available Evidence")
    _validate_supported_output(
        proposal.facts,
        proposal.directions,
        proposal.classification,
        proposal.classification_evidence_ids,
        allowed,
    )


def _validate_investigation(
    investigation: Investigation,
    snapshot: Snapshot,
    tool_calls: tuple[ToolResult, ...],
) -> None:
    if not isinstance(investigation, Investigation):
        raise TypeError("planner returned an invalid Investigation")
    if investigation.tool_calls != tool_calls:
        raise ValueError("final synthesis changed completed Tool calls")
    if any(not isinstance(item, str) or not item.strip() for item in investigation.missing):
        raise ValueError("missing information is invalid")
    _validate_supported_output(
        investigation.facts,
        investigation.directions,
        investigation.classification,
        investigation.classification_evidence_ids,
        _allowed_evidence(snapshot, tool_calls),
    )


def _validate_supported_output(
    facts: tuple[object, ...],
    directions: tuple[object, ...],
    classification: object,
    classification_evidence_ids: tuple[str, ...],
    allowed: set[str],
) -> None:
    if not isinstance(classification, str) or not classification.strip():
        raise ValueError("classification is invalid")
    if (
        any(not isinstance(item, str) or not item for item in classification_evidence_ids)
        or len(classification_evidence_ids) != len(set(classification_evidence_ids))
        or not set(classification_evidence_ids) <= allowed
    ):
        raise ValueError("classification citations are invalid")
    if classification != "unclassified" and not classification_evidence_ids:
        raise ValueError("classified output requires Evidence citations")
    for statement in facts + directions:
        if (
            not isinstance(statement, SupportedStatement)
            or not statement.evidence_ids
            or len(statement.evidence_ids) != len(set(statement.evidence_ids))
            or not set(statement.evidence_ids) <= allowed
        ):
            raise ValueError("statement cites unavailable Evidence")


def _allowed_evidence(snapshot: Snapshot, tool_results: tuple[ToolResult, ...]) -> set[str]:
    return {item.evidence_id for item in snapshot.evidence}.union(
        item.evidence_id for result in tool_results for item in result.evidence
    )


def _investigation(proposal: AgentProposal, tool_calls: tuple[ToolResult, ...]) -> Investigation:
    return Investigation(
        facts=proposal.facts,
        directions=proposal.directions,
        missing=proposal.missing,
        classification=proposal.classification,
        tool_calls=tool_calls,
        classification_evidence_ids=proposal.classification_evidence_ids,
    )


def _fallback(snapshot: Snapshot, tool_calls: tuple[ToolResult, ...]) -> Investigation:
    missing: tuple[str, ...] = FALLBACK_MISSING
    if snapshot.failures:
        missing += (f"기본 Snapshot 수집 실패 {len(snapshot.failures)}건이 있습니다.",)
    return Investigation(
        facts=(),
        directions=(),
        missing=missing,
        classification="unclassified",
        tool_calls=tool_calls,
        classification_evidence_ids=(),
    )
