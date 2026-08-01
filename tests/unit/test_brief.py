from datetime import UTC, datetime

import pytest

from pilo_incident_investigator.brief import (
    UnsupportedClaim,
    render_issue_markdown,
    validate_evidence_citations,
)
from pilo_incident_investigator.domain import (
    AlarmEvent,
    Evidence,
    IncidentBundle,
    Investigation,
    Snapshot,
    SupportedStatement,
)
from pilo_incident_investigator.redaction import UnsafeBundleError

NOW = datetime(2026, 8, 1, tzinfo=UTC)


def _investigation(
    *,
    fact_ids: tuple[str, ...] = ("E-001",),
    direction_ids: tuple[str, ...] = ("E-002",),
    classification: str = "resource_pressure",
    classification_ids: tuple[str, ...] = ("E-001",),
) -> Investigation:
    return Investigation(
        facts=(SupportedStatement("서비스 실행 수가 감소했습니다.", fact_ids),),
        directions=(SupportedStatement("중지 원인을 확인합니다.", direction_ids),),
        missing=("컨테이너 종료 상세",),
        classification=classification,
        tool_calls=(),
        classification_evidence_ids=classification_ids,
    )


def _bundle(investigation: Investigation | None = None) -> IncidentBundle:
    evidence = (
        Evidence("E-001", "ecs", NOW, "running=0", {"running": 0}),
        Evidence("E-002", "ecs", NOW, "task stopped", {"stopped": True}),
    )
    return IncidentBundle(
        incident_id="inc-001",
        alarm=AlarmEvent("evt-001", "synthetic", "alarm", NOW, {"state": "ALARM"}),
        snapshot=Snapshot("inc-001", evidence, ()),
        investigation=investigation or _investigation(),
        created_at=NOW,
        metadata={},
    )


@pytest.mark.parametrize(
    "investigation",
    [
        _investigation(fact_ids=("E-999",)),
        _investigation(direction_ids=("E-002", "E-002")),
        _investigation(classification_ids=("E-999",)),
        _investigation(classification="known", classification_ids=()),
    ],
)
def test_validate_evidence_citations_rejects_unsupported_claims(
    investigation: Investigation,
) -> None:
    with pytest.raises(UnsupportedClaim) as caught:
        validate_evidence_citations(investigation, ("E-001", "E-002"))

    assert "unsupported" not in str(caught.value).lower()


def test_validate_evidence_citations_rejects_duplicate_available_ids() -> None:
    with pytest.raises(UnsupportedClaim):
        validate_evidence_citations(_investigation(), ("E-001", "E-001", "E-002"))


def test_validate_evidence_citations_rejects_empty_structural_ids() -> None:
    investigation = _investigation(
        fact_ids=("",), classification="unclassified", classification_ids=()
    )

    with pytest.raises(UnsupportedClaim):
        validate_evidence_citations(investigation, ("", "E-002"))


def test_unclassified_may_have_no_classification_citation() -> None:
    validate_evidence_citations(
        _investigation(classification="unclassified", classification_ids=()),
        ("E-001", "E-002"),
    )


def test_render_issue_markdown_has_four_sections_and_adjacent_evidence() -> None:
    markdown = render_issue_markdown(_bundle())

    assert [line for line in markdown.splitlines() if line.startswith("## ")] == [
        "## 확인된 사실",
        "## 조사 방향",
        "## 누락 정보",
        "## 분류 상태",
    ]
    assert "서비스 실행 수가 감소했습니다. (근거: E-001)" in markdown
    assert "중지 원인을 확인합니다. (근거: E-002)" in markdown
    assert "resource_pressure (근거: E-001)" in markdown


def test_render_issue_markdown_redacts_before_returning_text() -> None:
    investigation = _investigation()
    investigation = Investigation(
        facts=investigation.facts,
        directions=investigation.directions,
        missing=investigation.missing + ("password=missing-secret",),
        classification=investigation.classification,
        tool_calls=investigation.tool_calls,
        classification_evidence_ids=investigation.classification_evidence_ids,
    )
    bundle = _bundle(investigation)
    bundle.metadata["note"] = "token=metadata-secret"

    markdown = render_issue_markdown(bundle)

    assert "metadata-secret" not in markdown
    assert "missing-secret" not in markdown


def test_render_issue_markdown_fails_closed_for_invalid_citations() -> None:
    with pytest.raises(UnsafeBundleError) as caught:
        render_issue_markdown(_bundle(_investigation(fact_ids=("E-999",))))

    assert "E-999" not in str(caught.value)
