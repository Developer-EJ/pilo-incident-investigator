"""Canonical structured contracts emitted by the bounded Agent planner."""

from dataclasses import dataclass

from pilo_incident_investigator.domain import SupportedStatement, ToolRequest


@dataclass(frozen=True, slots=True)
class AgentProposal:
    tool_requests: tuple[ToolRequest, ...]
    facts: tuple[SupportedStatement, ...]
    directions: tuple[SupportedStatement, ...]
    missing: tuple[str, ...]
    classification: str
