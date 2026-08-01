"""Evidence validation and the human-readable incident brief."""

import html
from collections.abc import Collection

from pilo_incident_investigator.domain import IncidentBundle, Investigation, SupportedStatement
from pilo_incident_investigator.redaction import (
    Redactor,
    UnsafeBundleError,
    is_safe_structural_id,
)


class UnsupportedClaim(ValueError):
    """Raised when an investigation statement is not supported by unique Evidence."""


def validate_evidence_citations(
    investigation: Investigation, evidence_ids: Collection[str]
) -> None:
    available = tuple(evidence_ids)
    if any(not is_safe_structural_id(item) for item in available) or len(available) != len(
        set(available)
    ):
        raise UnsupportedClaim("evidence collection is invalid")
    allowed = set(available)
    for statement in investigation.facts + investigation.directions:
        _validate_statement(statement, allowed)
    classification_ids = investigation.classification_evidence_ids
    if any(not is_safe_structural_id(item) for item in classification_ids) or len(
        classification_ids
    ) != len(set(classification_ids)):
        raise UnsupportedClaim("classification citations are invalid")
    if not set(classification_ids) <= allowed:
        raise UnsupportedClaim("classification citations are invalid")
    if investigation.classification != "unclassified" and not classification_ids:
        raise UnsupportedClaim("classification citations are invalid")


def render_issue_markdown(bundle: IncidentBundle) -> str:
    try:
        safe_bundle, _ = Redactor().redact_bundle(bundle)
        _validate_bundle(safe_bundle)
        investigation = safe_bundle.investigation
        sections = (
            ("확인된 사실", _render_statements(investigation.facts)),
            ("조사 방향", _render_statements(investigation.directions)),
            ("누락 정보", _render_missing(investigation.missing)),
            ("분류 상태", _render_classification(investigation)),
        )
        return "\n\n".join(f"## {heading}\n\n{body}" for heading, body in sections)
    except Exception:
        raise UnsafeBundleError("incident brief generation failed") from None


def _validate_statement(statement: SupportedStatement, allowed: set[str]) -> None:
    citations = statement.evidence_ids
    if (
        not citations
        or any(not is_safe_structural_id(item) for item in citations)
        or len(citations) != len(set(citations))
        or not set(citations) <= allowed
    ):
        raise UnsupportedClaim("statement citations are invalid")


def _validate_bundle(bundle: IncidentBundle) -> None:
    evidence_ids = [item.evidence_id for item in bundle.snapshot.evidence]
    evidence_ids.extend(
        item.evidence_id for result in bundle.investigation.tool_calls for item in result.evidence
    )
    validate_evidence_citations(bundle.investigation, evidence_ids)


def _render_statements(statements: tuple[SupportedStatement, ...]) -> str:
    if not statements:
        return "- 없음"
    return "\n".join(
        f"- {_safe_inline(statement.text)} (근거: {', '.join(statement.evidence_ids)})"
        for statement in statements
    )


def _render_missing(missing: tuple[str, ...]) -> str:
    return "\n".join(f"- {_safe_inline(item)}" for item in missing) if missing else "- 없음"


def _render_classification(investigation: Investigation) -> str:
    if not investigation.classification_evidence_ids:
        return f"- {_safe_inline(investigation.classification)}"
    citations = ", ".join(investigation.classification_evidence_ids)
    return f"- {_safe_inline(investigation.classification)} (근거: {citations})"


def _safe_inline(value: str) -> str:
    normalized = " ".join(value.split())
    escaped = html.escape(normalized, quote=False)
    for control in "\\`*_{}[]()#+!|>~":
        escaped = escaped.replace(control, f"\\{control}")
    return escaped
