"""Canonical, safe Incident Bundle serialization."""

import json
from dataclasses import fields, is_dataclass
from datetime import UTC, datetime

from pilo_incident_investigator.brief import validate_evidence_citations
from pilo_incident_investigator.domain import IncidentBundle, JsonValue
from pilo_incident_investigator.redaction import Redactor, UnsafeBundleError


def canonical_bundle_json(bundle: IncidentBundle) -> bytes:
    try:
        safe_bundle, _ = Redactor().redact_bundle(bundle)
        evidence_ids = [item.evidence_id for item in safe_bundle.snapshot.evidence]
        evidence_ids.extend(
            item.evidence_id
            for result in safe_bundle.investigation.tool_calls
            for item in result.evidence
        )
        validate_evidence_citations(safe_bundle.investigation, evidence_ids)
        normalized = _normalize(safe_bundle)
        return json.dumps(
            normalized,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except Exception:
        raise UnsafeBundleError("incident bundle serialization failed") from None


def _normalize(value: object) -> JsonValue:
    if value is None or isinstance(value, bool | int | float | str):
        return value
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
    if is_dataclass(value) and not isinstance(value, type):
        return {field.name: _normalize(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, tuple | list):
        return [_normalize(item) for item in value]
    if isinstance(value, dict):
        normalized: dict[str, JsonValue] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError
            normalized[key] = _normalize(item)
        return normalized
    raise TypeError
