"""DynamoDB-backed idempotency, retry ownership, and publisher checkpoints."""

from collections.abc import Callable
from dataclasses import dataclass
from decimal import Decimal
from enum import StrEnum
from time import time
from typing import Any, Protocol

from botocore.exceptions import ClientError


class Checkpoint(StrEnum):
    CLAIMED = "claimed"
    SNAPSHOT_COMPLETE = "snapshot_complete"
    BUNDLE_STORED = "bundle_stored"
    ISSUE_PUBLISHED = "issue_published"
    SLACK_ATTEMPTED = "slack_attempted"


_CHECKPOINT_RANK = {checkpoint: rank for rank, checkpoint in enumerate(Checkpoint)}
_ATTEMPT_LEASE_SECONDS = 15 * 60


class ProcessingStatus(StrEnum):
    PROCESSING = "processing"
    RETRYABLE = "retryable"
    COMPLETE = "complete"


class ClaimDisposition(StrEnum):
    STARTED = "started"
    RESUMED = "resumed"
    BUSY = "busy"
    COMPLETE = "complete"


@dataclass(frozen=True, slots=True)
class EventClaim:
    disposition: ClaimDisposition
    attempt_id: str | None


class IncidentStateStore(Protocol):
    def begin_event(self, event_id: str, incident_id: str, attempt_id: str) -> EventClaim: ...

    def claim_event(self, event_id: str, incident_id: str) -> bool: ...

    def mark_retryable(self, event_id: str, attempt_id: str) -> bool: ...

    def mark_complete(self, event_id: str, attempt_id: str) -> bool: ...

    def mark_snapshot_complete(self, event_id: str) -> bool: ...

    def mark_bundle_stored(self, event_id: str) -> bool: ...

    def mark_issue_published(self, event_id: str) -> bool: ...

    def mark_slack_attempted(self, event_id: str, status: str) -> bool: ...


class DynamoTable(Protocol):
    def put_item(self, **kwargs: Any) -> dict[str, Any]: ...

    def update_item(self, **kwargs: Any) -> dict[str, Any]: ...

    def get_item(self, **kwargs: Any) -> dict[str, Any]: ...


class DynamoIncidentStateStore:
    def __init__(
        self, table: DynamoTable, *, epoch_seconds: Callable[[], int] | None = None
    ) -> None:
        self._table = table
        self._epoch_seconds = epoch_seconds or (lambda: int(time()))
        self._active_attempts: dict[str, str] = {}

    def begin_event(self, event_id: str, incident_id: str, attempt_id: str) -> EventClaim:
        _require_identifier(event_id, "event ID")
        _require_identifier(incident_id, "incident ID")
        _require_identifier(attempt_id, "attempt ID")
        now, lease_expires_at = self._lease_window()
        try:
            self._table.put_item(
                Item=_new_event_item(event_id, incident_id, attempt_id, lease_expires_at),
                ConditionExpression="attribute_not_exists(event_id)",
            )
        except ClientError as error:
            if not _is_conditional_failure(error):
                raise
        else:
            self._active_attempts[event_id] = attempt_id
            return EventClaim(ClaimDisposition.STARTED, attempt_id)

        try:
            response = self._table.update_item(
                Key={"event_id": event_id},
                UpdateExpression=(
                    "SET processing_status = :processing, attempt_id = :attempt_id, "
                    "lease_expires_at = :lease_expires_at"
                ),
                ConditionExpression=(
                    "incident_id = :incident_id AND processing_status <> :complete AND "
                    "(processing_status = :retryable OR lease_expires_at < :now)"
                ),
                ExpressionAttributeValues={
                    ":attempt_id": attempt_id,
                    ":complete": ProcessingStatus.COMPLETE.value,
                    ":incident_id": incident_id,
                    ":lease_expires_at": lease_expires_at,
                    ":now": now,
                    ":processing": ProcessingStatus.PROCESSING.value,
                    ":retryable": ProcessingStatus.RETRYABLE.value,
                },
                ReturnValues="ALL_NEW",
            )
        except ClientError as error:
            if not _is_conditional_failure(error):
                raise
            return self._existing_claim(event_id, incident_id)
        if not isinstance(response.get("Attributes"), dict):
            raise RuntimeError("state resume response was invalid")
        self._active_attempts[event_id] = attempt_id
        return EventClaim(ClaimDisposition.RESUMED, attempt_id)

    def claim_event(self, event_id: str, incident_id: str) -> bool:
        _require_identifier(event_id, "event ID")
        _require_identifier(incident_id, "incident ID")
        attempt_id = f"legacy-{incident_id}"
        _, lease_expires_at = self._lease_window()
        try:
            self._table.put_item(
                Item=_new_event_item(
                    event_id,
                    incident_id,
                    attempt_id,
                    lease_expires_at,
                ),
                ConditionExpression="attribute_not_exists(event_id)",
            )
        except ClientError as error:
            if _is_conditional_failure(error):
                return False
            raise
        self._active_attempts[event_id] = attempt_id
        return True

    def mark_retryable(self, event_id: str, attempt_id: str) -> bool:
        updated = self._mark_processing_status(
            event_id,
            attempt_id,
            expected=ProcessingStatus.PROCESSING,
            next_status=ProcessingStatus.RETRYABLE,
        )
        if updated:
            self._active_attempts.pop(event_id, None)
        return updated

    def mark_complete(self, event_id: str, attempt_id: str) -> bool:
        updated = self._mark_processing_status(
            event_id,
            attempt_id,
            expected=ProcessingStatus.PROCESSING,
            next_status=ProcessingStatus.COMPLETE,
        )
        if updated:
            self._active_attempts.pop(event_id, None)
        return updated

    def mark_snapshot_complete(self, event_id: str) -> bool:
        return self._advance(event_id, Checkpoint.SNAPSHOT_COMPLETE)

    def mark_bundle_stored(self, event_id: str) -> bool:
        return self._record_outcome(
            event_id,
            attribute="bundle_stored",
            value=True,
            checkpoint=Checkpoint.BUNDLE_STORED,
        )

    def mark_issue_published(self, event_id: str) -> bool:
        return self._record_outcome(
            event_id,
            attribute="issue_published",
            value=True,
            checkpoint=Checkpoint.ISSUE_PUBLISHED,
        )

    def mark_slack_attempted(self, event_id: str, status: str) -> bool:
        if status not in {"sent", "failed"}:
            raise ValueError("Slack status must be sent or failed")
        return self._record_outcome(
            event_id,
            attribute="slack_status",
            value=status,
            checkpoint=Checkpoint.SLACK_ATTEMPTED,
        )

    def _record_outcome(
        self,
        event_id: str,
        *,
        attribute: str,
        value: bool | str,
        checkpoint: Checkpoint,
    ) -> bool:
        _require_identifier(event_id, "event ID")
        attempt_id = self._active_attempts.get(event_id)
        if attempt_id is None:
            return False
        now, lease_expires_at = self._lease_window()
        try:
            self._table.update_item(
                Key={"event_id": event_id},
                UpdateExpression=("SET #outcome = :outcome, lease_expires_at = :lease_expires_at"),
                ConditionExpression=(
                    "attribute_exists(event_id) AND attempt_id = :attempt_id AND "
                    "processing_status = :processing AND lease_expires_at >= :now"
                ),
                ExpressionAttributeNames={"#outcome": attribute},
                ExpressionAttributeValues={
                    ":attempt_id": attempt_id,
                    ":lease_expires_at": lease_expires_at,
                    ":now": now,
                    ":outcome": value,
                    ":processing": ProcessingStatus.PROCESSING.value,
                },
            )
        except ClientError as error:
            if _is_conditional_failure(error):
                return False
            raise
        return self._advance(event_id, checkpoint)

    def _mark_processing_status(
        self,
        event_id: str,
        attempt_id: str,
        *,
        expected: ProcessingStatus,
        next_status: ProcessingStatus,
    ) -> bool:
        _require_identifier(event_id, "event ID")
        _require_identifier(attempt_id, "attempt ID")
        now, lease_expires_at = self._lease_window()
        try:
            self._table.update_item(
                Key={"event_id": event_id},
                UpdateExpression=(
                    "SET processing_status = :next_status, lease_expires_at = :lease_expires_at"
                ),
                ConditionExpression=(
                    "attribute_exists(event_id) AND attempt_id = :attempt_id AND "
                    "processing_status = :expected_status AND lease_expires_at >= :now"
                ),
                ExpressionAttributeValues={
                    ":attempt_id": attempt_id,
                    ":expected_status": expected.value,
                    ":lease_expires_at": lease_expires_at,
                    ":next_status": next_status.value,
                    ":now": now,
                },
            )
        except ClientError as error:
            if _is_conditional_failure(error):
                return False
            raise
        return True

    def _existing_claim(self, event_id: str, incident_id: str) -> EventClaim:
        response = self._table.get_item(Key={"event_id": event_id}, ConsistentRead=True)
        item = response.get("Item")
        if not isinstance(item, dict) or item.get("incident_id") != incident_id:
            return EventClaim(ClaimDisposition.BUSY, None)
        if item.get("processing_status") == ProcessingStatus.COMPLETE.value:
            return EventClaim(ClaimDisposition.COMPLETE, None)
        return EventClaim(ClaimDisposition.BUSY, None)

    def _advance(self, event_id: str, checkpoint: Checkpoint) -> bool:
        _require_identifier(event_id, "event ID")
        attempt_id = self._active_attempts.get(event_id)
        if attempt_id is None:
            return False
        now, lease_expires_at = self._lease_window()
        try:
            self._table.update_item(
                Key={"event_id": event_id},
                UpdateExpression=(
                    "SET #checkpoint = :next_checkpoint, checkpoint_rank = :next_rank, "
                    "lease_expires_at = :lease_expires_at"
                ),
                ConditionExpression=(
                    "attribute_exists(event_id) AND attempt_id = :attempt_id AND "
                    "processing_status = :processing AND lease_expires_at >= :now AND "
                    "checkpoint_rank < :next_rank"
                ),
                ExpressionAttributeNames={"#checkpoint": "checkpoint"},
                ExpressionAttributeValues={
                    ":attempt_id": attempt_id,
                    ":lease_expires_at": lease_expires_at,
                    ":next_checkpoint": checkpoint.value,
                    ":next_rank": _CHECKPOINT_RANK[checkpoint],
                    ":now": now,
                    ":processing": ProcessingStatus.PROCESSING.value,
                },
            )
        except ClientError as error:
            if _is_conditional_failure(error):
                response = self._table.get_item(Key={"event_id": event_id}, ConsistentRead=True)
                item = response.get("Item")
                if isinstance(item, dict):
                    rank = _dynamo_integer(item.get("checkpoint_rank"))
                    return (
                        item.get("attempt_id") == attempt_id
                        and item.get("processing_status") == ProcessingStatus.PROCESSING.value
                        and (_dynamo_integer(item.get("lease_expires_at")) or -1) >= now
                        and rank is not None
                        and rank >= _CHECKPOINT_RANK[checkpoint]
                    )
                return False
            raise
        return True

    def _lease_window(self) -> tuple[int, int]:
        now = self._epoch_seconds()
        if isinstance(now, bool) or not isinstance(now, int) or now < 0:
            raise ValueError("state clock returned an invalid epoch")
        return now, now + _ATTEMPT_LEASE_SECONDS


def _require_identifier(value: str, field_name: str) -> None:
    if not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")


def _new_event_item(
    event_id: str,
    incident_id: str,
    attempt_id: str,
    lease_expires_at: int,
) -> dict[str, object]:
    return {
        "event_id": event_id,
        "incident_id": incident_id,
        "checkpoint": Checkpoint.CLAIMED.value,
        "checkpoint_rank": _CHECKPOINT_RANK[Checkpoint.CLAIMED],
        "bundle_stored": False,
        "issue_published": False,
        "slack_status": "not_attempted",
        "processing_status": ProcessingStatus.PROCESSING.value,
        "attempt_id": attempt_id,
        "lease_expires_at": lease_expires_at,
    }


def _dynamo_integer(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, Decimal) and value.is_finite() and value == value.to_integral_value():
        return int(value)
    return None


def _is_conditional_failure(error: ClientError) -> bool:
    return error.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException"
