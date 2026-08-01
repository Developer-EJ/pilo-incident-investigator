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
    (
        re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}"),
        "[REDACTED:AWS_ACCESS_KEY]",
        "AWS_ACCESS_KEY",
    ),
    (
        re.compile(
            r"(?i)\b(?:authorization\s*[:=]?\s*)?(?:bearer|basic)\s+"
            r"(?!\[REDACTED:AUTHORIZATION\])[^\s,;]+"
        ),
        "[REDACTED:AUTHORIZATION]",
        "AUTHORIZATION",
    ),
    (
        re.compile(r"https://hooks\.slack\.com/services/[^\s,;]+", re.IGNORECASE),
        "[REDACTED:WEBHOOK_URL]",
        "WEBHOOK_URL",
    ),
    (
        re.compile(
            r"(?i)([?&](?:access[_-]?token|client[_-]?secret|refresh[_-]?token|"
            r"id[_-]?token|auth[_-]?token|x[_-]?api[_-]?key|api[_-]?key|token|"
            r"secret|password)=)"
            r"(?!\[REDACTED:QUERY_CREDENTIAL\])[^&#\s,;]+"
        ),
        r"\1[REDACTED:QUERY_CREDENTIAL]",
        "QUERY_CREDENTIAL",
    ),
    (
        re.compile(
            r"(?i)\b(password|passwd|secret|token|client[_-]?secret|"
            r"aws[_-]?secret[_-]?access[_-]?key|x[_-]?api[_-]?key|api[_-]?key|"
            r"refresh[_-]?token|id[_-]?token|auth[_-]?token|webhook[_-]?url|"
            r"private[_-]?key|credentials?)\s*[=:]\s*(?!\[REDACTED:)"
            r"""(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;]+)"""
        ),
        r"\1=[REDACTED:CREDENTIAL]",
        "CREDENTIAL_ASSIGNMENT",
    ),
)
_SENSITIVE_KEYS = frozenset(
    {
        "clientsecret",
        "accesstoken",
        "awssecretaccesskey",
        "xapikey",
        "apikey",
        "refreshtoken",
        "idtoken",
        "authtoken",
        "authorization",
        "webhookurl",
        "privatekey",
        "credential",
        "credentials",
        "password",
        "passwd",
        "secret",
        "token",
    }
)
_REDACTED_SENTINEL = re.compile(r"\[REDACTED:[A-Z_]+\]")


class Redactor:
    def redact_text(self, value: str) -> tuple[str, RedactionReport]:
        counts: Counter[str] = Counter()
        redacted = self._redact_text(value, counts)
        return redacted, _report(counts)

    def redact_bundle(self, bundle: IncidentBundle) -> tuple[IncidentBundle, RedactionReport]:
        counts: Counter[str] = Counter()
        try:
            _validate_bundle_structural_ids(bundle)
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
            sensitive = _normalize_key(key) in _SENSITIVE_KEYS
            safe_item = self._redact_json(item, counts, sensitive=sensitive)
            redacted[safe_key] = safe_item
        return redacted

    def _redact_json(
        self, value: JsonValue, counts: Counter[str], *, sensitive: bool = False
    ) -> JsonValue:
        if value is None or isinstance(value, bool | int | float):
            return value
        if isinstance(value, str):
            return (
                self._redact_sensitive_field(value, counts)
                if sensitive
                else self._redact_text(value, counts)
            )
        if isinstance(value, list):
            return [self._redact_json(item, counts, sensitive=sensitive) for item in value]
        if isinstance(value, dict):
            if sensitive:
                return self._redact_sensitive_mapping(value, counts)
            return self._redact_mapping(value, counts)
        raise TypeError

    def _redact_sensitive_field(self, value: str, counts: Counter[str]) -> str:
        if _REDACTED_SENTINEL.fullmatch(value):
            return value
        counts["SENSITIVE_FIELD"] += 1
        return "[REDACTED:SENSITIVE_FIELD]"

    def _redact_text(self, value: str, counts: Counter[str]) -> str:
        redacted = value
        for pattern, replacement, category in _RULES:
            redacted, replacements = pattern.subn(replacement, redacted)
            counts[category] += replacements
        return redacted

    def _redact_sensitive_mapping(
        self, value: dict[str, JsonValue], counts: Counter[str]
    ) -> dict[str, JsonValue]:
        redacted: dict[str, JsonValue] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError
            safe_key = self._redact_text(key, counts)
            if safe_key in redacted:
                raise ValueError
            redacted[safe_key] = self._redact_json(item, counts, sensitive=True)
        return redacted


def _report(counts: Counter[str]) -> RedactionReport:
    categories = tuple(sorted((name, count) for name, count in counts.items() if count))
    return RedactionReport(
        replacements=sum(count for _, count in categories), categories=categories
    )


def is_safe_structural_id(value: object) -> bool:
    if not isinstance(value, str) or not value or not any(char.isalnum() for char in value):
        return False
    if not value[0].isalnum() or not value[-1].isalnum():
        return False
    if any(not (char.isalnum() or char in "-_.:") for char in value):
        return False
    redacted, report = Redactor().redact_text(value)
    return report.replacements == 0 and redacted == value


def _validate_bundle_structural_ids(bundle: IncidentBundle) -> None:
    ids: list[object] = [item.evidence_id for item in bundle.snapshot.evidence]
    ids.extend(
        item.evidence_id for result in bundle.investigation.tool_calls for item in result.evidence
    )
    ids.extend(
        evidence_id
        for statement in bundle.investigation.facts + bundle.investigation.directions
        for evidence_id in statement.evidence_ids
    )
    ids.extend(bundle.investigation.classification_evidence_ids)
    if any(not is_safe_structural_id(value) for value in ids):
        raise ValueError


def _normalize_key(value: str) -> str:
    return "".join(char for char in value.casefold() if char.isascii() and char.isalnum())
