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
    }


def test_checkpoints_only_move_forward_and_retries_are_idempotent() -> None:
    table = InMemoryConditionalTable()
    store = DynamoIncidentStateStore(table)
    assert store.claim_event("evt-001", "inc-abc") is True

    assert store.mark_snapshot_complete("evt-001") is True
    assert store.mark_bundle_stored("evt-001") is True
    assert store.mark_snapshot_complete("evt-001") is False
    assert store.mark_bundle_stored("evt-001") is False
    assert store.mark_issue_published("evt-001") is True
    assert store.mark_slack_attempted("evt-001") is True

    assert table.items["evt-001"]["checkpoint"] == "slack_attempted"
    assert [call["ExpressionAttributeValues"][":next_rank"] for call in table.update_calls] == [
        1,
        2,
        1,
        2,
        3,
        4,
    ]
    assert all(
        call["ConditionExpression"] == "attribute_exists(event_id) AND checkpoint_rank < :next_rank"
        for call in table.update_calls
    )


def test_unclaimed_event_cannot_advance() -> None:
    store = DynamoIncidentStateStore(InMemoryConditionalTable())

    assert store.mark_snapshot_complete("evt-missing") is False


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
