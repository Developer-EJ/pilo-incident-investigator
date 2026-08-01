"""Deterministic, fail-closed redaction for publishable incident data."""

import base64
import binascii
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
    (
        re.compile(r"(?:xox[baprs]|xapp)-[A-Za-z0-9-]+"),
        "[REDACTED:SLACK_TOKEN]",
        "SLACK_TOKEN",
    ),
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
            r"(?i)\bauthorization\s*[:=]?\s*(?:bearer|basic)\s+"
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
)
_SENSITIVE_EXACT_KEYS = frozenset(
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
_STANDALONE_AUTHORIZATION = re.compile(
    r"(?i)\b(?P<scheme>bearer|basic)\s+"
    r"(?P<credential>(?!\[REDACTED:AUTHORIZATION\])[^\s,;]+)"
)
_QUERY_CREDENTIAL = re.compile(
    r"(?i)(?P<prefix>[?&])(?P<key>[A-Za-z][A-Za-z0-9_.-]{0,127})="
    r"(?P<value>(?!\[REDACTED:)[^&#\s,;]+)"
)
_CREDENTIAL_ASSIGNMENT = re.compile(
    r"(?i)(?P<key>[A-Za-z][A-Za-z0-9_.-]{0,127})\s*[=:]\s*"
    r"(?![A-Za-z][A-Za-z0-9_.-]{0,127}\s*[=:])"
    r"""(?P<value>(?!\[REDACTED:)(?:"(?:\\[\s\S]|[^"\\])*"|"""
    r"'(?:\\[\s\S]|[^'\\])*'|"
    r""""(?:\\[\s\S]|[^"\\])*(?:\\)?\Z|"""
    r"'(?:\\[\s\S]|[^'\\])*(?:\\)?\Z|"
    r"""[^"'\s,;]+))"""
)
_SENSITIVE_SINGLE_TOKENS = frozenset(
    {"password", "passwd", "secret", "token", "authorization", "credential", "credentials"}
)
_SENSITIVE_TOKEN_PAIRS = frozenset(
    {
        ("client", "secret"),
        ("refresh", "token"),
        ("id", "token"),
        ("auth", "token"),
        ("api", "key"),
        ("access", "key"),
        ("private", "key"),
        ("webhook", "url"),
    }
)


class Redactor:
    def redact_text(self, value: str) -> tuple[str, RedactionReport]:
        counts: Counter[str] = Counter()
        redacted = self._redact_text(value, counts)
        return redacted, _report(counts)

    def redact_json(self, value: JsonValue) -> tuple[JsonValue, RedactionReport]:
        """Redact a JSON tree using the same sensitive-key context as Bundles."""
        counts: Counter[str] = Counter()
        try:
            redacted = self._redact_json(value, counts)
        except Exception:
            raise UnsafeBundleError("JSON redaction failed") from None
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
            sensitive = _is_sensitive_key(key)
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
        redacted = self._redact_query_credentials(redacted, counts)
        redacted = self._redact_standalone_authorization(redacted, counts)
        redacted = self._redact_assignments(redacted, counts)
        return redacted

    def _redact_standalone_authorization(self, value: str, counts: Counter[str]) -> str:
        def replace(match: re.Match[str]) -> str:
            if not _looks_like_authorization_credential(
                match.group("scheme"), match.group("credential")
            ):
                return match.group(0)
            counts["AUTHORIZATION"] += 1
            return "[REDACTED:AUTHORIZATION]"

        return _STANDALONE_AUTHORIZATION.sub(replace, value)

    def _redact_query_credentials(self, value: str, counts: Counter[str]) -> str:
        def replace(match: re.Match[str]) -> str:
            if not _is_sensitive_key(match.group("key")):
                return match.group(0)
            counts["QUERY_CREDENTIAL"] += 1
            return f"{match.group('prefix')}{match.group('key')}=[REDACTED:QUERY_CREDENTIAL]"

        return _QUERY_CREDENTIAL.sub(replace, value)

    def _redact_assignments(self, value: str, counts: Counter[str]) -> str:
        def replace(match: re.Match[str]) -> str:
            if not _is_sensitive_key(match.group("key")):
                return match.group(0)
            counts["CREDENTIAL_ASSIGNMENT"] += 1
            return f"{match.group('key')}=[REDACTED:CREDENTIAL]"

        return _CREDENTIAL_ASSIGNMENT.sub(replace, value)

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


def _key_tokens(value: str) -> tuple[str, ...]:
    camel_split = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", value)
    camel_split = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", camel_split)
    return tuple(token.casefold() for token in re.findall(r"[A-Za-z0-9]+", camel_split))


def _is_sensitive_key(value: str) -> bool:
    tokens = _key_tokens(value)
    collapsed = "".join(tokens)
    if collapsed in _SENSITIVE_EXACT_KEYS or any(
        token in _SENSITIVE_SINGLE_TOKENS for token in tokens
    ):
        return True
    return any(pair in _SENSITIVE_TOKEN_PAIRS for pair in zip(tokens, tokens[1:], strict=False))


def _looks_like_authorization_credential(scheme: str, credential: str) -> bool:
    if scheme.casefold() == "basic":
        return _is_basic_userinfo(credential)
    if not re.fullmatch(r"[A-Za-z0-9\-._~+/]+={0,}", credential):
        return False
    return len(credential) >= 14 or (
        len(credential) >= 10 and any(not char.isalpha() for char in credential)
    )


def _is_basic_userinfo(credential: str) -> bool:
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", credential):
        return False
    unpadded = credential.rstrip("=")
    if len(unpadded) % 4 == 1:
        return False
    padded = unpadded + "=" * (-len(unpadded) % 4)
    try:
        decoded = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return False
    return b":" in decoded
