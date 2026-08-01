"""Deterministic, fail-closed redaction for publishable incident data."""

import re
from collections import Counter
from dataclasses import dataclass

from pilo_incident_investigator.domain import (
    AlarmEvent,
    CollectorFailure,
    Evidence,
    IncidentBundle,
    Investigation,
    JsonValue,
    Snapshot,
    SupportedStatement,
    ToolRequest,
    ToolResult,
)


class UnsafeBundleError(ValueError):
    """Raised when a bundle cannot be made safe for publication."""


@dataclass(frozen=True, slots=True)
class RedactionReport:
    replacements: int
    categories: tuple[tuple[str, int], ...]


_Rule = tuple[re.Pattern[str], str, str]
_RULES: tuple[_Rule, ...] = (
    (re.compile(r"xox[baprs]-[A-Za-z0-9-]+"), "[REDACTED:SLACK_TOKEN]", "SLACK_TOKEN"),
    (
        re.compile(r"(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]+"),
        "[REDACTED:GITHUB_TOKEN]",
        "GITHUB_TOKEN",
    ),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED:AWS_ACCESS_KEY]", "AWS_ACCESS_KEY"),
    (
        re.compile(
            r"(?i)\bauthorization\s*[:=]?\s*(?:bearer|basic)\s+"
            r"(?!\[REDACTED:AUTHORIZATION\])[^\s,;]+"
        ),
        "Authorization: [REDACTED:AUTHORIZATION]",
        "AUTHORIZATION",
    ),
    (
        re.compile(r"https://hooks\.slack\.com/services/[^\s,;]+", re.IGNORECASE),
        "[REDACTED:WEBHOOK_URL]",
        "WEBHOOK_URL",
    ),
    (
        re.compile(
            r"(?i)([?&](?:access_token|api_key|apikey|token|secret|password)=)"
            r"(?!\[REDACTED:QUERY_CREDENTIAL\])[^&#\s,;]+"
        ),
        r"\1[REDACTED:QUERY_CREDENTIAL]",
        "QUERY_CREDENTIAL",
    ),
    (
        re.compile(
            r"(?i)\b(password|passwd|secret|token)\s*[=:]\s*"
            r"(?!\[REDACTED:)[^\s,;]+"
        ),
        r"\1=[REDACTED:CREDENTIAL]",
        "CREDENTIAL_ASSIGNMENT",
    ),
)
_SENSITIVE_KEYS = frozenset(
    {"authorization", "password", "passwd", "secret", "token", "access_token", "api_key"}
)


class Redactor:
    def redact_text(self, value: str) -> tuple[str, RedactionReport]:
        counts: Counter[str] = Counter()
        redacted = self._redact_text(value, counts)
        return redacted, _report(counts)

    def redact_bundle(self, bundle: IncidentBundle) -> tuple[IncidentBundle, RedactionReport]:
        counts: Counter[str] = Counter()
        try:
            redacted = IncidentBundle(
                incident_id=self._redact_text(bundle.incident_id, counts),
                alarm=self._redact_alarm(bundle.alarm, counts),
                snapshot=self._redact_snapshot(bundle.snapshot, counts),
                investigation=self._redact_investigation(bundle.investigation, counts),
                created_at=bundle.created_at,
                metadata=self._redact_mapping(bundle.metadata, counts),
            )
        except Exception:
            raise UnsafeBundleError("incident bundle redaction failed") from None
        return redacted, _report(counts)

    def _redact_alarm(self, alarm: AlarmEvent, counts: Counter[str]) -> AlarmEvent:
        return AlarmEvent(
            event_id=self._redact_text(alarm.event_id, counts),
            alarm_arn=self._redact_text(alarm.alarm_arn, counts),
            alarm_name=self._redact_text(alarm.alarm_name, counts),
            state_timestamp=alarm.state_timestamp,
            detail=self._redact_mapping(alarm.detail, counts),
        )

    def _redact_snapshot(self, snapshot: Snapshot, counts: Counter[str]) -> Snapshot:
        return Snapshot(
            incident_id=self._redact_text(snapshot.incident_id, counts),
            evidence=tuple(self._redact_evidence(item, counts) for item in snapshot.evidence),
            failures=tuple(self._redact_failure(item, counts) for item in snapshot.failures),
        )

    def _redact_evidence(self, evidence: Evidence, counts: Counter[str]) -> Evidence:
        return Evidence(
            evidence_id=evidence.evidence_id,
            source=self._redact_text(evidence.source, counts),
            observed_at=evidence.observed_at,
            summary=self._redact_text(evidence.summary, counts),
            data=self._redact_mapping(evidence.data, counts),
        )

    def _redact_failure(self, failure: CollectorFailure, counts: Counter[str]) -> CollectorFailure:
        return CollectorFailure(
            collector=self._redact_text(failure.collector, counts),
            code=self._redact_text(failure.code, counts),
            detail=self._redact_text(failure.detail, counts),
        )

    def _redact_request(self, request: ToolRequest, counts: Counter[str]) -> ToolRequest:
        return ToolRequest(
            tool=self._redact_text(request.tool, counts),
            resource_key=self._redact_text(request.resource_key, counts),
            parameters=self._redact_mapping(request.parameters, counts),
            reason=self._redact_text(request.reason, counts),
        )

    def _redact_result(self, result: ToolResult, counts: Counter[str]) -> ToolResult:
        return ToolResult(
            request=self._redact_request(result.request, counts),
            evidence=tuple(self._redact_evidence(item, counts) for item in result.evidence),
            failure=None
            if result.failure is None
            else self._redact_failure(result.failure, counts),
        )

    def _redact_statement(
        self, statement: SupportedStatement, counts: Counter[str]
    ) -> SupportedStatement:
        return SupportedStatement(
            text=self._redact_text(statement.text, counts),
            evidence_ids=statement.evidence_ids,
        )

    def _redact_investigation(
        self, investigation: Investigation, counts: Counter[str]
    ) -> Investigation:
        return Investigation(
            facts=tuple(self._redact_statement(item, counts) for item in investigation.facts),
            directions=tuple(
                self._redact_statement(item, counts) for item in investigation.directions
            ),
            missing=tuple(self._redact_text(item, counts) for item in investigation.missing),
            classification=self._redact_text(investigation.classification, counts),
            tool_calls=tuple(
                self._redact_result(item, counts) for item in investigation.tool_calls
            ),
            classification_evidence_ids=investigation.classification_evidence_ids,
        )

    def _redact_mapping(
        self, value: dict[str, JsonValue], counts: Counter[str]
    ) -> dict[str, JsonValue]:
        redacted: dict[str, JsonValue] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError
            safe_key = self._redact_text(key, counts)
            if safe_key in redacted:
                raise ValueError
            if key.casefold() in _SENSITIVE_KEYS and isinstance(item, str):
                safe_item: JsonValue = self._redact_sensitive_field(item, counts)
            else:
                safe_item = self._redact_json(item, counts)
            redacted[safe_key] = safe_item
        return redacted

    def _redact_json(self, value: JsonValue, counts: Counter[str]) -> JsonValue:
        if value is None or isinstance(value, bool | int | float):
            return value
        if isinstance(value, str):
            return self._redact_text(value, counts)
        if isinstance(value, list):
            return [self._redact_json(item, counts) for item in value]
        if isinstance(value, dict):
            return self._redact_mapping(value, counts)
        raise TypeError

    def _redact_sensitive_field(self, value: str, counts: Counter[str]) -> str:
        if value.startswith("[REDACTED:") and value.endswith("]"):
            return value
        counts["SENSITIVE_FIELD"] += 1
        return "[REDACTED:SENSITIVE_FIELD]"

    def _redact_text(self, value: str, counts: Counter[str]) -> str:
        redacted = value
        for pattern, replacement, category in _RULES:
            redacted, replacements = pattern.subn(replacement, redacted)
            counts[category] += replacements
        return redacted


def _report(counts: Counter[str]) -> RedactionReport:
    categories = tuple(sorted((name, count) for name, count in counts.items() if count))
    return RedactionReport(
        replacements=sum(count for _, count in categories), categories=categories
    )
