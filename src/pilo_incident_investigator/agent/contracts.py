"""Canonical structured contracts emitted by the bounded Agent planner."""

import re
from collections.abc import Collection
from dataclasses import dataclass

from pilo_incident_investigator.domain import SupportedStatement, ToolRequest


@dataclass(frozen=True, slots=True)
class AgentProposal:
    tool_requests: tuple[ToolRequest, ...]
    facts: tuple[SupportedStatement, ...]
    directions: tuple[SupportedStatement, ...]
    missing: tuple[str, ...]
    classification: str
    classification_evidence_ids: tuple[str, ...] = ()


def cites_available_evidence(text: str, evidence_ids: Collection[str]) -> bool:
    """Return true only for a complete Evidence ID token, never a prefix collision."""
    return any(
        re.search(rf"(?<![A-Za-z0-9_-]){re.escape(evidence_id)}(?![A-Za-z0-9_-])", text) is not None
        for evidence_id in evidence_ids
    )
