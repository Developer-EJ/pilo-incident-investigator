from typing import Any, cast

from botocore.exceptions import ClientError

from pilo_incident_investigator.state import Checkpoint, DynamoIncidentStateStore


class InMemoryConditionalTable:
    def __init__(self) -> None:
        self.items: dict[str, dict[str, object]] = {}
        self.put_calls: list[dict[str, Any]] = []
        self.update_calls: list[dict[str, Any]] = []

    def put_item(self, **kwargs: Any) -> dict[str, Any]:
        self.put_calls.append(kwargs)
        item = kwargs["Item"]
        event_id = item["event_id"]
        if event_id in self.items:
            raise conditional_failure()
        self.items[event_id] = dict(item)
        return {}

    def update_item(self, **kwargs: Any) -> dict[str, Any]:
        self.update_calls.append(kwargs)
        event_id = kwargs["Key"]["event_id"]
        values = kwargs["ExpressionAttributeValues"]
        item = self.items.get(event_id)
        if ":outcome" in values:
            if item is None:
                raise conditional_failure()
            attribute = kwargs["ExpressionAttributeNames"]["#outcome"]
            item[attribute] = values[":outcome"]
            return {}
        if item is None or cast(int, item["checkpoint_rank"]) >= cast(int, values[":next_rank"]):
            raise conditional_failure()
        item["checkpoint"] = values[":next_checkpoint"]
        item["checkpoint_rank"] = values[":next_rank"]
        return {}


def conditional_failure() -> ClientError:
    return ClientError(
        {"Error": {"Code": "ConditionalCheckFailedException", "Message": "conditional"}},
        "test-operation",
    )


def test_claim_uses_attribute_not_exists_and_is_idempotent() -> None:
    table = InMemoryConditionalTable()
    store = DynamoIncidentStateStore(table)

    assert store.claim_event("evt-001", "inc-abc") is True
    assert store.claim_event("evt-001", "inc-abc") is False
    assert table.put_calls[0]["ConditionExpression"] == "attribute_not_exists(event_id)"
    assert table.items["evt-001"] == {
        "event_id": "evt-001",
        "incident_id": "inc-abc",
        "checkpoint": "claimed",
        "checkpoint_rank": 0,
        "bundle_stored": False,
        "issue_published": False,
        "slack_status": "not_attempted",
    }


def test_checkpoints_only_move_forward_and_retries_are_idempotent() -> None:
    table = InMemoryConditionalTable()
    store = DynamoIncidentStateStore(table)
    assert store.claim_event("evt-001", "inc-abc") is True

    assert store.mark_snapshot_complete("evt-001") is True
    assert store.mark_bundle_stored("evt-001") is True
    assert store.mark_snapshot_complete("evt-001") is False
    assert store.mark_bundle_stored("evt-001") is True
    assert store.mark_issue_published("evt-001") is True
    assert store.mark_slack_attempted("evt-001", "sent") is True

    assert table.items["evt-001"]["checkpoint"] == "slack_attempted"
    rank_calls = [
        call for call in table.update_calls if ":next_rank" in call["ExpressionAttributeValues"]
    ]
    assert [call["ExpressionAttributeValues"][":next_rank"] for call in rank_calls] == [
        1,
        2,
        1,
        2,
        3,
        4,
    ]
    assert all(
        call["ConditionExpression"] == "attribute_exists(event_id) AND checkpoint_rank < :next_rank"
        for call in rank_calls
    )
    assert table.items["evt-001"]["bundle_stored"] is True
    assert table.items["evt-001"]["issue_published"] is True
    assert table.items["evt-001"]["slack_status"] == "sent"


def test_unclaimed_event_cannot_advance() -> None:
    store = DynamoIncidentStateStore(InMemoryConditionalTable())

    assert store.mark_snapshot_complete("evt-missing") is False


def test_issue_outcome_is_recorded_after_degraded_slack_advanced_checkpoint() -> None:
    table = InMemoryConditionalTable()
    store = DynamoIncidentStateStore(table)
    assert store.claim_event("evt-001", "inc-abc") is True

    assert store.mark_slack_attempted("evt-001", "sent") is True
    assert store.mark_issue_published("evt-001") is True

    assert table.items["evt-001"]["checkpoint"] == "slack_attempted"
    assert table.items["evt-001"]["issue_published"] is True
    assert table.items["evt-001"]["slack_status"] == "sent"


def test_slack_retry_updates_failed_status_to_sent_without_rank_regression() -> None:
    table = InMemoryConditionalTable()
    store = DynamoIncidentStateStore(table)
    assert store.claim_event("evt-001", "inc-abc") is True

    assert store.mark_slack_attempted("evt-001", "failed") is True
    assert store.mark_slack_attempted("evt-001", "sent") is True

    assert table.items["evt-001"]["checkpoint"] == "slack_attempted"
    assert table.items["evt-001"]["slack_status"] == "sent"


def test_unclaimed_event_cannot_record_publisher_outcomes() -> None:
    table = InMemoryConditionalTable()
    store = DynamoIncidentStateStore(table)

    assert store.mark_bundle_stored("evt-missing") is False
    assert store.mark_issue_published("evt-missing") is False
    assert store.mark_slack_attempted("evt-missing", "failed") is False
    assert table.items == {}


def test_invalid_slack_status_is_rejected_before_dynamo_write() -> None:
    table = InMemoryConditionalTable()
    store = DynamoIncidentStateStore(table)
    assert store.claim_event("evt-001", "inc-abc") is True

    try:
        store.mark_slack_attempted("evt-001", "unknown")
    except ValueError as error:
        assert "Slack status" in str(error)
    else:
        raise AssertionError("invalid Slack status must be rejected")

    assert table.update_calls == []


def test_non_conditional_client_error_is_not_hidden() -> None:
    class FailingTable(InMemoryConditionalTable):
        def put_item(self, **kwargs: Any) -> dict[str, Any]:
            raise ClientError(
                {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                "PutItem",
            )

    store = DynamoIncidentStateStore(FailingTable())

    try:
        store.claim_event("evt-001", "inc-abc")
    except ClientError as error:
        assert error.response["Error"]["Code"] == "AccessDeniedException"
    else:
        raise AssertionError("AccessDeniedException must propagate")


def test_checkpoint_values_are_stable() -> None:
    assert tuple(checkpoint.value for checkpoint in Checkpoint) == (
        "claimed",
        "snapshot_complete",
        "bundle_stored",
        "issue_published",
        "slack_attempted",
    )
