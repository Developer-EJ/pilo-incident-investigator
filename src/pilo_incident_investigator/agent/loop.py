"""Bounded, fail-closed orchestration for additional incident investigation."""

from pilo_incident_investigator.agent.bedrock import Planner
from pilo_incident_investigator.agent.contracts import AgentProposal
from pilo_incident_investigator.agent.tools import ToolRegistry
from pilo_incident_investigator.domain import Investigation, Snapshot, ToolResult
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
                return _investigation(proposal, tuple(executed))

            try:
                for request in proposal.tool_requests:
                    executed.append(self._registry.execute(request, topology, seen))
            except Exception:
                return _fallback(snapshot, tuple(executed))

        return _investigation(proposal, tuple(executed))


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
    allowed = {item.evidence_id for item in snapshot.evidence}
    allowed.update(item.evidence_id for result in prior_results for item in result.evidence)
    for request in proposal.tool_requests:
        if not any(evidence_id in request.reason for evidence_id in allowed):
            raise ValueError("Tool selection reason does not cite available Evidence")
    for statement in proposal.facts + proposal.directions:
        if not statement.evidence_ids or not set(statement.evidence_ids) <= allowed:
            raise ValueError("statement cites unavailable Evidence")


def _investigation(proposal: AgentProposal, tool_calls: tuple[ToolResult, ...]) -> Investigation:
    return Investigation(
        facts=proposal.facts,
        directions=proposal.directions,
        missing=proposal.missing,
        classification=proposal.classification,
        tool_calls=tool_calls,
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
    )
