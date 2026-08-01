"""DynamoDB-backed idempotency and publisher checkpoints."""

from enum import StrEnum
from typing import Any, Protocol

from botocore.exceptions import ClientError


class Checkpoint(StrEnum):
    CLAIMED = "claimed"
    SNAPSHOT_COMPLETE = "snapshot_complete"
    BUNDLE_STORED = "bundle_stored"
    ISSUE_PUBLISHED = "issue_published"
    SLACK_ATTEMPTED = "slack_attempted"


_CHECKPOINT_RANK = {checkpoint: rank for rank, checkpoint in enumerate(Checkpoint)}


class IncidentStateStore(Protocol):
    def claim_event(self, event_id: str, incident_id: str) -> bool: ...

    def mark_snapshot_complete(self, event_id: str) -> bool: ...

    def mark_bundle_stored(self, event_id: str) -> bool: ...

    def mark_issue_published(self, event_id: str) -> bool: ...

    def mark_slack_attempted(self, event_id: str, status: str) -> bool: ...


class DynamoTable(Protocol):
    def put_item(self, **kwargs: Any) -> dict[str, Any]: ...

    def update_item(self, **kwargs: Any) -> dict[str, Any]: ...


class DynamoIncidentStateStore:
    def __init__(self, table: DynamoTable) -> None:
        self._table = table

    def claim_event(self, event_id: str, incident_id: str) -> bool:
        _require_identifier(event_id, "event ID")
        _require_identifier(incident_id, "incident ID")
        try:
            self._table.put_item(
                Item={
                    "event_id": event_id,
                    "incident_id": incident_id,
                    "checkpoint": Checkpoint.CLAIMED.value,
                    "checkpoint_rank": _CHECKPOINT_RANK[Checkpoint.CLAIMED],
                    "bundle_stored": False,
                    "issue_published": False,
                    "slack_status": "not_attempted",
                },
                ConditionExpression="attribute_not_exists(event_id)",
            )
        except ClientError as error:
            if _is_conditional_failure(error):
                return False
            raise
        return True

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
        try:
            self._table.update_item(
                Key={"event_id": event_id},
                UpdateExpression="SET #outcome = :outcome",
                ConditionExpression="attribute_exists(event_id)",
                ExpressionAttributeNames={"#outcome": attribute},
                ExpressionAttributeValues={":outcome": value},
            )
        except ClientError as error:
            if _is_conditional_failure(error):
                return False
            raise
        self._advance(event_id, checkpoint)
        return True

    def _advance(self, event_id: str, checkpoint: Checkpoint) -> bool:
        _require_identifier(event_id, "event ID")
        try:
            self._table.update_item(
                Key={"event_id": event_id},
                UpdateExpression=(
                    "SET #checkpoint = :next_checkpoint, checkpoint_rank = :next_rank"
                ),
                ConditionExpression=("attribute_exists(event_id) AND checkpoint_rank < :next_rank"),
                ExpressionAttributeNames={"#checkpoint": "checkpoint"},
                ExpressionAttributeValues={
                    ":next_checkpoint": checkpoint.value,
                    ":next_rank": _CHECKPOINT_RANK[checkpoint],
                },
            )
        except ClientError as error:
            if _is_conditional_failure(error):
                return False
            raise
        return True


def _require_identifier(value: str, field_name: str) -> None:
    if not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")


def _is_conditional_failure(error: ClientError) -> bool:
    return error.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException"
