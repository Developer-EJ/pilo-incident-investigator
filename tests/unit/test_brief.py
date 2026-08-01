from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime

import pytest

from pilo_incident_investigator.brief import (
    UnsupportedClaim,
    render_issue_markdown,
    validate_evidence_citations,
)
from pilo_incident_investigator.bundle import canonical_bundle_json
from pilo_incident_investigator.domain import (
    AlarmEvent,
    Evidence,
    IncidentBundle,
    Investigation,
    Snapshot,
    SupportedStatement,
    ToolRequest,
    ToolResult,
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
    assert "resource\\_pressure (근거: E-001)" in markdown


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


def _bundle_with_unsafe_structural_id(location: str) -> IncidentBundle:
    unsafe_id = "E-xoxb-1234567890-secret"
    bundle = _bundle()
    if location == "snapshot":
        unsafe_evidence = replace(bundle.snapshot.evidence[0], evidence_id=unsafe_id)
        investigation = Investigation(
            facts=(SupportedStatement("unsafe evidence", (unsafe_id,)),),
            directions=(SupportedStatement("safe direction", ("E-002",)),),
            missing=(),
            classification="unsafe evidence classification",
            tool_calls=(),
            classification_evidence_ids=(unsafe_id,),
        )
        return replace(
            bundle,
            snapshot=replace(
                bundle.snapshot,
                evidence=(unsafe_evidence, bundle.snapshot.evidence[1]),
            ),
            investigation=investigation,
        )
    tool_evidence = Evidence(unsafe_id, "rds", NOW, "event", {})
    result = ToolResult(
        ToolRequest("rds_events", "rds-01", {}, "E-001 supports lookup"),
        (tool_evidence,),
        None,
    )
    if location == "tool":
        return replace(bundle, investigation=replace(bundle.investigation, tool_calls=(result,)))
    if location == "statement":
        fact = SupportedStatement("unsafe citation", (unsafe_id,))
        return replace(
            bundle,
            investigation=replace(bundle.investigation, facts=(fact,), tool_calls=(result,)),
        )
    return replace(
        bundle,
        investigation=replace(
            bundle.investigation,
            classification_evidence_ids=(unsafe_id,),
            tool_calls=(result,),
        ),
    )


@pytest.mark.parametrize("location", ["snapshot", "tool", "statement", "classification"])
@pytest.mark.parametrize("output", [render_issue_markdown, canonical_bundle_json])
def test_outputs_fail_closed_for_credential_shaped_structural_ids(
    location: str, output: Callable[[IncidentBundle], str | bytes]
) -> None:
    with pytest.raises(UnsafeBundleError) as caught:
        output(_bundle_with_unsafe_structural_id(location))

    assert "xoxb" not in str(caught.value)


def test_validate_evidence_citations_rejects_markdown_or_control_ids() -> None:
    for unsafe_id in ("E-001\n## injected", "E-[link](target)", "E-001\tmore"):
        investigation = _investigation(
            fact_ids=(unsafe_id,), classification="unclassified", classification_ids=()
        )
        with pytest.raises(UnsupportedClaim) as caught:
            validate_evidence_citations(investigation, (unsafe_id, "E-002"))
        assert unsafe_id not in str(caught.value)


def test_render_issue_markdown_neutralizes_multiline_markdown_and_html() -> None:
    investigation = Investigation(
        facts=(
            SupportedStatement(
                "상태 확인\n## 주입 제목\n- 주입 항목 <script>alert(1)</script> [링크](evil)",
                ("E-001",),
            ),
        ),
        directions=(SupportedStatement("확인\r\n## 다섯번째\t- 항목", ("E-002",)),),
        missing=("누락\n## 여섯번째\n* 항목",),
        classification="분류\n## 일곱번째 <b>html</b>",
        tool_calls=(),
        classification_evidence_ids=("E-001",),
    )

    markdown = render_issue_markdown(_bundle(investigation))

    assert [line for line in markdown.splitlines() if line.startswith("## ")] == [
        "## 확인된 사실",
        "## 조사 방향",
        "## 누락 정보",
        "## 분류 상태",
    ]
    assert "<script>" not in markdown
    assert "<b>" not in markdown
    assert "[링크](evil)" not in markdown
    assert "\t" not in markdown


def _bundle_with_matching_id(evidence_id: str) -> IncidentBundle:
    bundle = _bundle()
    evidence = replace(bundle.snapshot.evidence[0], evidence_id=evidence_id)
    investigation = Investigation(
        facts=(SupportedStatement("matched evidence", (evidence_id,)),),
        directions=(),
        missing=(),
        classification="matched",
        tool_calls=(),
        classification_evidence_ids=(evidence_id,),
    )
    return replace(
        bundle,
        snapshot=replace(
            bundle.snapshot,
            evidence=(evidence, bundle.snapshot.evidence[1]),
        ),
        investigation=investigation,
    )


@pytest.mark.parametrize("output", [render_issue_markdown, canonical_bundle_json])
def test_outputs_reject_sensitive_key_assignment_structural_id(
    output: Callable[[IncidentBundle], str | bytes],
) -> None:
    with pytest.raises(UnsafeBundleError) as caught:
        output(_bundle_with_matching_id("github_token:opaque-value"))

    assert "opaque-value" not in str(caught.value)


@pytest.mark.parametrize("output", [render_issue_markdown, canonical_bundle_json])
def test_outputs_allow_existing_secret_rotation_tool_id(
    output: Callable[[IncidentBundle], str | bytes],
) -> None:
    result = output(_bundle_with_matching_id("secret-rotation-metadata-a1b2-001"))

    assert result
