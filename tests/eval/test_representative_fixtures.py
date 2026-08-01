import ast
import json
from collections import Counter
from collections.abc import Iterator
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest

from pilo_incident_investigator.agent.contracts import cites_available_evidence
from pilo_incident_investigator.agent.tools import TOOL_NAMES
from pilo_incident_investigator.domain import Evidence, JsonValue
from pilo_incident_investigator.evaluation.loader import load_manifest
from pilo_incident_investigator.evaluation.schema import EvalFixture
from pilo_incident_investigator.event import incident_id_for, parse_alarm_event
from pilo_incident_investigator.snapshot import _allocate_evidence_ids

REPO_ROOT = Path(__file__).parents[2]
MANIFEST_PATH = REPO_ROOT / "fixtures" / "eval" / "manifest.yaml"
WINDOW_START = datetime(2026, 1, 1, tzinfo=UTC)
WINDOW_END = datetime(2026, 1, 1, 1, 0, tzinfo=UTC)
SYNTHETIC_ALARM_NAME = "synthetic-incident-alarm"
SYNTHETIC_ALARM_ARN = (
    "arn:aws:cloudwatch:ap-northeast-2:000000000000:alarm:synthetic-incident-alarm"
)
ALARM_SYMPTOMS = {
    "rds_secret_rotation_auth": (
        "AuthenticationErrorCount",
        "synthetic threshold breached: 12 >= 5",
    ),
    "ecs_oom": ("MemoryUtilization", "synthetic threshold breached: 95 >= 90"),
    "alb_health_check": (
        "UnHealthyHostCount",
        "synthetic threshold breached: 1 >= 1",
    ),
    "deployment_regression": ("HTTP5xx", "synthetic threshold breached: 24 >= 10"),
    "sqs_backlog": (
        "ApproximateNumberOfMessagesVisible",
        "synthetic threshold breached: 240 >= 100",
    ),
    "external_api_rate_limit": (
        "ExternalRequestFailureCount",
        "synthetic threshold breached: 30 >= 20",
    ),
}

SCENARIOS = {
    "rds_secret_rotation_auth",
    "ecs_oom",
    "alb_health_check",
    "deployment_regression",
    "sqs_backlog",
    "external_api_rate_limit",
}
VARIANTS = {"complete", "noisy", "partial"}
BASELINE_SOURCES = {
    "ecs.describe_services",
    "ecs.describe_tasks",
    "logs.filter_log_events",
    "elbv2.describe_target_health",
    "ecs.describe_services.all_pilo",
    "github.deployments",
    "rds.describe_db_instances",
}
ECS_STOP_CODES = {
    "TaskFailedToStart",
    "EssentialContainerExited",
    "UserInitiated",
    "ServiceSchedulerInitiated",
    "SpotInterruption",
    "TerminationNotice",
}
TOOL_EVIDENCE_PREFIXES = {
    "service_log_search": "service-log-search",
    "rds_events": "rds-events",
    "secret_rotation_metadata": "secret-rotation-metadata",
    "sqs_status": "sqs-status",
    "github_changed_files": "github-changed-files",
}
SEMANTIC_EVIDENCE_IDS = {
    "E-RDS-STATUS",
    "E-APP-AUTH-ERROR",
    "E-SECRET-ROTATION-TIME",
    "E-TASK-STOP-REASON",
    "E-CONTAINER-EXIT-137",
    "E-MEMORY-PRESSURE",
    "E-TARGET-UNHEALTHY",
    "E-HEALTH-REASON",
    "E-SERVICE-RUNNING",
    "E-DEPLOYMENT-TIME",
    "E-ERROR-START-TIME",
    "E-CHANGED-FILES",
    "E-QUEUE-DEPTH",
    "E-OLDEST-MESSAGE",
    "E-CONSUMER-STATE",
    "E-HTTP-429",
    "E-RETRY-PATTERN",
    "E-SERVICE-STATE",
}
TRUTH = {
    "rds_secret_rotation_auth": {
        "required": {
            "complete": {
                "E-012",
                "E-013",
                "tool-local-secret-rotation-metadata-898a9bd50e9b53b7-1",
            },
            "noisy": {"E-012", "E-017", "tool-local-secret-rotation-metadata-898a9bd50e9b53b7-1"},
            "partial": {
                "E-012",
                "tool-local-secret-rotation-metadata-898a9bd50e9b53b7-1",
                "tool-local-service-log-search-ba1bcdf6a405dd96-1",
            },
        },
        "direction": "correlate_rotation_time_with_auth_failures",
        "tools": {"secret_rotation_metadata", "rds_events", "service_log_search"},
    },
    "ecs_oom": {
        "required": {
            "complete": {"E-010", "E-013", "E-014"},
            "noisy": {"E-010", "E-014", "E-015"},
            "partial": {"E-010", "E-012", "E-013"},
        },
        "direction": "inspect_task_memory_and_recent_change",
        "tools": {"service_log_search", "github_changed_files"},
    },
    "alb_health_check": {
        "required": {
            "complete": {"E-002", "E-010", "E-012"},
            "noisy": {"E-002", "E-010", "E-012"},
            "partial": {"E-002", "E-004", "tool-local-service-log-search-ba1bcdf6a405dd96-2"},
        },
        "direction": "compare_health_check_contract_with_service_response",
        "tools": {"service_log_search", "github_changed_files"},
    },
    "deployment_regression": {
        "required": {
            "complete": {"E-011", "E-012", "tool-local-github-changed-files-cd5e3383c8fa9d01-1"},
            "noisy": {"E-011", "E-012", "tool-local-github-changed-files-cd5e3383c8fa9d01-1"},
            "partial": {
                "E-011",
                "tool-local-github-changed-files-cd5e3383c8fa9d01-1",
                "tool-local-service-log-search-ba1bcdf6a405dd96-1",
            },
        },
        "direction": "inspect_recent_deployment_diff",
        "tools": {"github_changed_files", "service_log_search"},
    },
    "sqs_backlog": {
        "required": {
            "complete": {"E-002", "E-012", "tool-local-sqs-status-a972adbf6bf1fa8d-1"},
            "noisy": {"E-002", "E-014", "tool-local-sqs-status-a972adbf6bf1fa8d-1"},
            "partial": {
                "E-002",
                "tool-local-sqs-status-a972adbf6bf1fa8d-1",
                "tool-local-service-log-search-ba1bcdf6a405dd96-2",
            },
        },
        "direction": "inspect_consumer_throughput_and_failures",
        "tools": {"sqs_status", "service_log_search"},
    },
    "external_api_rate_limit": {
        "required": {
            "complete": {"E-001", "E-012", "E-013"},
            "noisy": {"E-001", "E-013", "E-014"},
            "partial": {"E-001", "E-011", "E-012"},
        },
        "direction": "inspect_external_rate_limit_and_retry_behavior",
        "tools": {"service_log_search", "github_changed_files"},
    },
}
PARTIAL_CONTRACTS: dict[str, tuple[str, frozenset[str], str, str]] = {
    "rds_secret_rotation_auth": (
        "stopped_tasks_and_logs",
        frozenset({"tool-local-service-log-search-ba1bcdf6a405dd96-1"}),
        "service_log_search",
        "logs.filter_log_events",
    ),
    "ecs_oom": (
        "recent_github_deployments",
        frozenset(),
        "github_changed_files",
        "github.deployments",
    ),
    "alb_health_check": (
        "all_pilo_services",
        frozenset({"tool-local-service-log-search-ba1bcdf6a405dd96-2"}),
        "service_log_search",
        "ecs.describe_services.all_pilo",
    ),
    "deployment_regression": (
        "stopped_tasks_and_logs",
        frozenset({"tool-local-service-log-search-ba1bcdf6a405dd96-1"}),
        "service_log_search",
        "logs.filter_log_events",
    ),
    "sqs_backlog": (
        "stopped_tasks_and_logs",
        frozenset({"tool-local-service-log-search-ba1bcdf6a405dd96-2"}),
        "service_log_search",
        "logs.filter_log_events",
    ),
    "external_api_rate_limit": (
        "recent_github_deployments",
        frozenset(),
        "github_changed_files",
        "github.deployments",
    ),
}

COLLECTOR_SOURCES = {
    "alarm_target_ecs": frozenset({"ecs.describe_services"}),
    "stopped_tasks_and_logs": frozenset({"ecs.describe_tasks", "logs.filter_log_events"}),
    "alb_target_health": frozenset({"elbv2.describe_target_health"}),
    "all_pilo_services": frozenset({"ecs.describe_services.all_pilo"}),
    "recent_github_deployments": frozenset({"github.deployments"}),
    "rds_basic_status": frozenset({"rds.describe_db_instances"}),
}


def _representative_subset(fixtures: tuple[EvalFixture, ...]) -> tuple[EvalFixture, ...]:
    return tuple(fixture for fixture in fixtures if fixture.scenario in SCENARIOS)


@pytest.fixture(scope="module")
def representative_fixtures() -> tuple[EvalFixture, ...]:
    return _representative_subset(load_manifest(MANIFEST_PATH))


def _all_evidence(fixture: EvalFixture) -> Iterator[Evidence]:
    yield from fixture.snapshot.evidence
    for result in fixture.tool_results.values():
        yield from result.evidence


def _evidence_signature(item: Evidence) -> tuple[str, datetime, str, str]:
    return (
        item.source,
        item.observed_at,
        item.summary,
        json.dumps(item.data, sort_keys=True, separators=(",", ":")),
    )


def test_representative_matrix_is_six_by_three(
    representative_fixtures: tuple[EvalFixture, ...],
) -> None:
    assert len(representative_fixtures) == 18
    assert {(item.scenario, item.variant) for item in representative_fixtures} == {
        (scenario, variant) for scenario in SCENARIOS for variant in VARIANTS
    }
    fixture_ids = [item.fixture_id for item in representative_fixtures]
    assert len(fixture_ids) == len(set(fixture_ids))


def test_representative_subset_ignores_future_unknown_fixtures(
    representative_fixtures: tuple[EvalFixture, ...],
) -> None:
    future_unknown = replace(representative_fixtures[0], scenario="unknown_or_composite")

    assert _representative_subset((*representative_fixtures, future_unknown)) == (
        representative_fixtures
    )


def test_representative_fixtures_encode_exact_truth_table(
    representative_fixtures: tuple[EvalFixture, ...],
) -> None:
    for fixture in representative_fixtures:
        truth = TRUTH[fixture.scenario]
        required = cast(dict[str, set[str]], truth["required"])
        assert fixture.expected.required_evidence_ids == frozenset(required[fixture.variant])
        assert fixture.expected.acceptable_direction_labels == frozenset({truth["direction"]})
        assert fixture.handoff.acceptable_first_direction_labels == frozenset({truth["direction"]})
        assert fixture.expected.useful_tools == frozenset(truth["tools"])
        assert {result.request.tool for result in fixture.tool_results.values()} == truth["tools"]
        assert all(
            result.failure is None and result.evidence for result in fixture.tool_results.values()
        )
        cited = {
            evidence_id for fact in fixture.expected.facts for evidence_id in fact.evidence_ids
        }
        assert fixture.expected.required_evidence_ids <= cited


def test_complete_and_noisy_preserve_six_baseline_collectors(
    representative_fixtures: tuple[EvalFixture, ...],
) -> None:
    for fixture in representative_fixtures:
        if fixture.variant not in {"complete", "noisy"}:
            continue
        assert fixture.snapshot.failures == ()
        sources = {item.source for item in fixture.snapshot.evidence}
        for collector_sources in COLLECTOR_SOURCES.values():
            assert sources & collector_sources
        assert (
            sum(
                item.source == "ecs.describe_services.all_pilo"
                for item in fixture.snapshot.evidence
            )
            == 8
        )


def test_noisy_fixtures_add_at_least_four_plausible_uncited_evidence_records(
    representative_fixtures: tuple[EvalFixture, ...],
) -> None:
    complete_by_scenario = {
        fixture.scenario: fixture
        for fixture in representative_fixtures
        if fixture.variant == "complete"
    }
    for fixture in representative_fixtures:
        if fixture.variant != "noisy":
            continue
        complete_evidence = {
            _evidence_signature(item)
            for item in _all_evidence(complete_by_scenario[fixture.scenario])
        }
        extra = [
            item
            for item in _all_evidence(fixture)
            if _evidence_signature(item) not in complete_evidence
        ]
        assert len(extra) >= 4
        extra_ids = {item.evidence_id for item in extra}
        cited = {
            evidence_id for fact in fixture.expected.facts for evidence_id in fact.evidence_ids
        }
        assert extra_ids.isdisjoint(fixture.expected.required_evidence_ids)
        assert extra_ids.isdisjoint(cited)
        assert all(item.source in BASELINE_SOURCES for item in extra)
        for item in extra:
            model_visible = json.dumps(
                {"evidence_id": item.evidence_id, "summary": item.summary, "data": item.data}
            ).lower()
            assert "aux" not in model_visible
            assert "noise" not in model_visible
            assert "irrelevant" not in model_visible


def test_partial_fixtures_preserve_failure_and_missing_information(
    representative_fixtures: tuple[EvalFixture, ...],
) -> None:
    for fixture in representative_fixtures:
        if fixture.variant != "partial":
            continue
        assert fixture.snapshot.failures
        assert fixture.expected.missing_information


def test_partial_fixtures_fail_related_collector_and_compensate_required_signal(
    representative_fixtures: tuple[EvalFixture, ...],
) -> None:
    for fixture in representative_fixtures:
        if fixture.variant != "partial":
            continue
        collector, removed_ids, compensation_tool, _ = PARTIAL_CONTRACTS[fixture.scenario]
        assert {failure.collector for failure in fixture.snapshot.failures} == {collector}
        snapshot_ids = {item.evidence_id for item in fixture.snapshot.evidence}
        assert removed_ids.isdisjoint(snapshot_ids)
        assert COLLECTOR_SOURCES[collector].isdisjoint(
            {item.source for item in fixture.snapshot.evidence}
        )
        compensation = next(
            result
            for result in fixture.tool_results.values()
            if result.request.tool == compensation_tool
        )
        compensated = {
            item.evidence_id: item
            for item in compensation.evidence
            if item.evidence_id in removed_ids
        }
        assert set(compensated) == removed_ids
        assert compensation.evidence
        assert all(item.source == compensation_tool for item in compensation.evidence)
        assert all(collector in detail for detail in fixture.expected.missing_information)


def test_snapshot_evidence_uses_production_collector_contracts(
    representative_fixtures: tuple[EvalFixture, ...],
) -> None:
    for fixture in representative_fixtures:
        for item in fixture.snapshot.evidence:
            assert item.source in BASELINE_SOURCES
            data = item.data
            if item.source == "ecs.describe_services":
                assert item.summary == "target ECS state"
                assert set(data) == {"service", "desired", "running", "pending"}
            elif item.source == "ecs.describe_tasks":
                assert item.summary == "stopped ECS task"
                assert set(data) == {"service", "task", "stop_code"}
                assert all(isinstance(data[key], str) for key in data)
                assert data["stop_code"] in ECS_STOP_CODES
            elif item.source == "logs.filter_log_events":
                assert item.summary == "bounded service log event"
                assert set(data) == {"service", "log_group", "timestamp", "message"}
                assert isinstance(data["timestamp"], int) and not isinstance(
                    data["timestamp"], bool
                )
            elif item.source == "elbv2.describe_target_health":
                assert item.summary == "ALB target health"
                assert set(data) == {"service", "target_group", "states"}
                assert isinstance(data["states"], list)
                assert all(isinstance(state, str) for state in data["states"])
            elif item.source == "ecs.describe_services.all_pilo":
                assert item.summary == "PILO service running state"
                assert set(data) == {"service", "desired", "running", "pending"}
            elif item.source == "github.deployments":
                assert item.summary == "recent GitHub deployment"
                assert set(data) == {
                    "repository",
                    "deployment_id",
                    "environment",
                    "revision",
                    "created_at",
                }
                assert all(isinstance(data[key], str) for key in data)
                created_at = data["created_at"]
                assert isinstance(created_at, str)
                assert datetime.fromisoformat(created_at).utcoffset() is not None
            else:
                assert item.source == "rds.describe_db_instances"
                assert item.summary == "RDS basic status"
                assert set(data) == {"database", "status"}
            if item.source in {
                "ecs.describe_services",
                "ecs.describe_services.all_pilo",
            }:
                for key in ("desired", "running", "pending"):
                    count = data[key]
                    assert isinstance(count, int) and not isinstance(count, bool)
                    assert count >= 0


def test_truth_evidence_has_realistic_provenance(
    representative_fixtures: tuple[EvalFixture, ...],
) -> None:
    expected_sources = {
        "rds_secret_rotation_auth": {
            "complete": Counter(
                {
                    "rds.describe_db_instances": 1,
                    "logs.filter_log_events": 1,
                    "secret_rotation_metadata": 1,
                }
            ),
            "noisy": Counter(
                {
                    "rds.describe_db_instances": 1,
                    "logs.filter_log_events": 1,
                    "secret_rotation_metadata": 1,
                }
            ),
            "partial": Counter(
                {
                    "rds.describe_db_instances": 1,
                    "service_log_search": 1,
                    "secret_rotation_metadata": 1,
                }
            ),
        },
        "ecs_oom": {
            variant: Counter({"ecs.describe_tasks": 1, "logs.filter_log_events": 2})
            for variant in VARIANTS
        },
        "alb_health_check": {
            "complete": Counter(
                {
                    "ecs.describe_services.all_pilo": 1,
                    "elbv2.describe_target_health": 1,
                    "logs.filter_log_events": 1,
                }
            ),
            "noisy": Counter(
                {
                    "ecs.describe_services.all_pilo": 1,
                    "elbv2.describe_target_health": 1,
                    "logs.filter_log_events": 1,
                }
            ),
            "partial": Counter(
                {
                    "elbv2.describe_target_health": 1,
                    "logs.filter_log_events": 1,
                    "service_log_search": 1,
                }
            ),
        },
        "deployment_regression": {
            "complete": Counter(
                {"github.deployments": 1, "logs.filter_log_events": 1, "github_changed_files": 1}
            ),
            "noisy": Counter(
                {"github.deployments": 1, "logs.filter_log_events": 1, "github_changed_files": 1}
            ),
            "partial": Counter(
                {"github.deployments": 1, "service_log_search": 1, "github_changed_files": 1}
            ),
        },
        "sqs_backlog": {
            "complete": Counter(
                {"sqs_status": 1, "logs.filter_log_events": 1, "ecs.describe_services.all_pilo": 1}
            ),
            "noisy": Counter(
                {"sqs_status": 1, "logs.filter_log_events": 1, "ecs.describe_services.all_pilo": 1}
            ),
            "partial": Counter(
                {"sqs_status": 1, "service_log_search": 1, "ecs.describe_services.all_pilo": 1}
            ),
        },
        "external_api_rate_limit": {
            variant: Counter({"logs.filter_log_events": 2, "ecs.describe_services": 1})
            for variant in VARIANTS
        },
    }
    for fixture in representative_fixtures:
        evidence = {item.evidence_id: item for item in _all_evidence(fixture)}
        required = [evidence[evidence_id] for evidence_id in fixture.expected.required_evidence_ids]
        assert (
            Counter(item.source for item in required)
            == expected_sources[fixture.scenario][fixture.variant]
        )
        if fixture.scenario == "sqs_backlog":
            consumer_state = next(
                item for item in required if item.source == "ecs.describe_services.all_pilo"
            )
            assert consumer_state.data == {
                "service": "pilo-dev-service-01",
                "desired": 2,
                "running": 1,
                "pending": 0,
            }
            assert fixture.expected.facts[0].text == (
                "synthetic queue depth and age increased while the consumer was below desired count"
            )


def test_snapshot_evidence_ids_match_production_allocator(
    representative_fixtures: tuple[EvalFixture, ...],
) -> None:
    for fixture in representative_fixtures:
        unallocated = [
            replace(item, evidence_id="unallocated") for item in fixture.snapshot.evidence
        ]
        assert fixture.snapshot.evidence == _allocate_evidence_ids(unallocated)
        assert all(
            item.evidence_id.startswith("E-")
            and len(item.evidence_id) == 5
            and item.evidence_id[2:].isdecimal()
            and int(item.evidence_id[2:]) < 900
            for item in fixture.snapshot.evidence
        )


def test_snapshot_rows_follow_production_collector_order(
    representative_fixtures: tuple[EvalFixture, ...],
) -> None:
    for fixture in representative_fixtures:
        service_order = {
            service.key: index for index, service in enumerate(fixture.topology.services)
        }
        log_group_order = {
            (service.key, log_group): index
            for service in fixture.topology.services
            for index, log_group in enumerate(service.log_groups)
        }
        target_group_order = {
            (service.key, target_group): index
            for service in fixture.topology.services
            for index, target_group in enumerate(service.target_groups)
        }
        repository_order = {
            service.github_repository: index
            for index, service in enumerate(fixture.topology.services)
        }
        database_order = {
            database: (service_order[service.key], index)
            for service in fixture.topology.services
            for index, database in enumerate(service.rds_instances)
        }
        by_source: dict[str, list[Evidence]] = {}
        for item in fixture.snapshot.evidence:
            by_source.setdefault(item.source, []).append(item)

        alarm_targets = by_source.get("ecs.describe_services", [])
        assert [service_order[str(item.data["service"])] for item in alarm_targets] == sorted(
            service_order[str(item.data["service"])] for item in alarm_targets
        )

        logs = by_source.get("logs.filter_log_events", [])
        log_keys = [
            (
                service_order[str(item.data["service"])],
                log_group_order[(str(item.data["service"]), str(item.data["log_group"]))],
                cast(int, item.data["timestamp"]),
                str(item.data["message"]),
            )
            for item in logs
        ]
        assert log_keys == sorted(log_keys)

        tasks = by_source.get("ecs.describe_tasks", [])
        task_keys = [
            (service_order[str(item.data["service"])], str(item.data["task"])) for item in tasks
        ]
        assert task_keys == sorted(task_keys)

        all_pilo = by_source.get("ecs.describe_services.all_pilo", [])
        if all_pilo:
            assert [item.data["service"] for item in all_pilo] == [
                service.key for service in fixture.topology.services
            ]

        alb = by_source.get("elbv2.describe_target_health", [])
        alb_keys = [
            (
                service_order[str(item.data["service"])],
                target_group_order[(str(item.data["service"]), str(item.data["target_group"]))],
            )
            for item in alb
        ]
        assert alb_keys == sorted(alb_keys)
        assert all(
            item.data["states"]
            == sorted(str(state) for state in cast(list[JsonValue], item.data["states"]))
            for item in alb
        )

        deployments = by_source.get("github.deployments", [])
        deployment_keys = [
            (
                repository_order[str(item.data["repository"])],
                -datetime.fromisoformat(str(item.data["created_at"])).timestamp(),
            )
            for item in deployments
        ]
        assert deployment_keys == sorted(deployment_keys)

        databases = by_source.get("rds.describe_db_instances", [])
        assert [database_order[str(item.data["database"])] for item in databases] == sorted(
            database_order[str(item.data["database"])] for item in databases
        )


def test_tool_rows_follow_production_internal_order(
    representative_fixtures: tuple[EvalFixture, ...],
) -> None:
    for fixture in representative_fixtures:
        for result in fixture.tool_results.values():
            rows = [item.data for item in result.evidence]
            if result.request.tool == "service_log_search":
                service_log_keys = [
                    (
                        cast(int, row["timestamp"]),
                        str(row["message"]),
                        str(row.get("log_stream", "")),
                    )
                    for row in rows
                ]
                assert service_log_keys == sorted(service_log_keys)
            elif result.request.tool == "rds_events":
                rds_event_keys = [(str(row["occurred_at"]), str(row["message"])) for row in rows]
                assert rds_event_keys == sorted(rds_event_keys)
            elif result.request.tool == "secret_rotation_metadata":
                assert all(
                    row["version_stages"]
                    == sorted(str(stage) for stage in cast(list[JsonValue], row["version_stages"]))
                    for row in rows
                )
            elif result.request.tool == "github_changed_files":
                changed_file_keys = [(str(row["path"]), str(row["status"])) for row in rows]
                assert changed_file_keys == sorted(changed_file_keys)
            else:
                assert result.request.tool == "sqs_status"
                assert len(rows) <= 1


def test_tool_evidence_ids_match_production_request_hash_allocator(
    representative_fixtures: tuple[EvalFixture, ...],
) -> None:
    for fixture in representative_fixtures:
        for result in fixture.tool_results.values():
            prefix = TOOL_EVIDENCE_PREFIXES[result.request.tool]
            request_hash = result.request.deduplication_key()[5:21]
            assert [item.evidence_id for item in result.evidence] == [
                f"tool-local-{prefix}-{request_hash}-{index}"
                for index in range(1, len(result.evidence) + 1)
            ]


def test_expected_references_only_model_visible_opaque_evidence_ids(
    representative_fixtures: tuple[EvalFixture, ...],
) -> None:
    for fixture in representative_fixtures:
        evidence_ids = {item.evidence_id for item in _all_evidence(fixture)}
        referenced_ids = set(fixture.expected.required_evidence_ids)
        referenced_ids.update(
            evidence_id for fact in fixture.expected.facts for evidence_id in fact.evidence_ids
        )
        assert referenced_ids <= evidence_ids
        assert all(
            evidence_id.startswith("E-") or evidence_id.startswith("tool-local-")
            for evidence_id in referenced_ids
        )
        model_visible_text = " ".join(
            [
                *(result.request.reason for result in fixture.tool_results.values()),
                *fixture.expected.missing_information,
                *(fact.text for fact in fixture.expected.facts),
            ]
        )
        assert all(label not in model_visible_text for label in SEMANTIC_EVIDENCE_IDS)


def test_tool_request_reasons_cite_snapshot_without_scenario_labels(
    representative_fixtures: tuple[EvalFixture, ...],
) -> None:
    for fixture in representative_fixtures:
        snapshot_ids = {item.evidence_id for item in fixture.snapshot.evidence}
        forbidden_labels = {
            fixture.scenario,
            fixture.expected.classification,
            *fixture.expected.acceptable_direction_labels,
        }
        for result in fixture.tool_results.values():
            reason = result.request.reason
            assert cites_available_evidence(reason, snapshot_ids)
            assert all(label.lower() not in reason.lower() for label in forbidden_labels)


def test_secret_metadata_observation_time_is_tool_execution_time(
    representative_fixtures: tuple[EvalFixture, ...],
) -> None:
    for fixture in representative_fixtures:
        for result in fixture.tool_results.values():
            if result.request.tool != "secret_rotation_metadata":
                continue
            alarm = parse_alarm_event(_eventbridge_payload(fixture.alarm))
            assert result.evidence
            for item in result.evidence:
                assert item.observed_at == alarm.state_timestamp
                assert datetime.fromisoformat(str(item.data["last_rotated_at"])) < item.observed_at
                assert datetime.fromisoformat(str(item.data["last_changed_at"])) < item.observed_at


@pytest.mark.parametrize("tool", sorted(TOOL_NAMES))
def test_tool_evidence_uses_production_normalized_data_contract(
    tool: str,
    representative_fixtures: tuple[EvalFixture, ...],
) -> None:
    summaries = {
        "service_log_search": "service log event",
        "rds_events": "RDS event",
        "secret_rotation_metadata": "secret rotation metadata",
        "sqs_status": "SQS queue status",
        "github_changed_files": "GitHub changed file",
    }
    checked = 0
    for fixture in representative_fixtures:
        for result in fixture.tool_results.values():
            if result.request.tool != tool:
                continue
            for item in result.evidence:
                checked += 1
                assert item.source == tool
                assert item.summary == summaries[tool]
                data = item.data
                if tool == "service_log_search":
                    assert {"log_group", "timestamp", "message"} <= set(data)
                    assert set(data) <= {"log_group", "timestamp", "message", "log_stream"}
                    assert data["log_group"] == result.request.resource_key
                    assert isinstance(data["timestamp"], int) and not isinstance(
                        data["timestamp"], bool
                    )
                    assert isinstance(data["message"], str) and data["message"]
                    if "log_stream" in data:
                        assert isinstance(data["log_stream"], str) and data["log_stream"]
                elif tool == "rds_events":
                    assert set(data) == {"database", "occurred_at", "message"}
                    assert data["database"] == result.request.resource_key
                    assert isinstance(data["occurred_at"], str)
                    assert datetime.fromisoformat(data["occurred_at"]).utcoffset() is not None
                    assert isinstance(data["message"], str) and data["message"]
                elif tool == "secret_rotation_metadata":
                    assert set(data) == {
                        "rotation_enabled",
                        "last_rotated_at",
                        "last_changed_at",
                        "version_stages",
                    }
                    assert isinstance(data["rotation_enabled"], bool)
                    for key in ("last_rotated_at", "last_changed_at"):
                        timestamp = data[key]
                        assert timestamp is None or isinstance(timestamp, str)
                        if isinstance(timestamp, str):
                            assert datetime.fromisoformat(timestamp).utcoffset() is not None
                    assert isinstance(data["version_stages"], list)
                    assert all(isinstance(stage, str) for stage in data["version_stages"])
                elif tool == "sqs_status":
                    assert {"queue", "visible", "not_visible", "delayed"} <= set(data)
                    assert set(data) <= {
                        "queue",
                        "visible",
                        "not_visible",
                        "delayed",
                        "oldest_message_age_seconds",
                    }
                    assert data["queue"] == result.request.resource_key
                    for key in set(data) - {"queue"}:
                        count = data[key]
                        assert isinstance(count, int) and not isinstance(count, bool)
                        assert count >= 0
                else:
                    assert tool == "github_changed_files"
                    assert set(data) == {"repository", "path", "status"}
                    assert data["repository"] == result.request.resource_key
                    assert isinstance(data["path"], str) and data["path"]
                    assert isinstance(data["status"], str) and data["status"]
    assert checked


def test_sqs_status_uses_one_canonical_row_and_oldest_signal_has_realistic_provenance(
    representative_fixtures: tuple[EvalFixture, ...],
) -> None:
    for fixture in representative_fixtures:
        if fixture.scenario != "sqs_backlog":
            continue
        by_tool = {result.request.tool: result for result in fixture.tool_results.values()}
        assert len(by_tool["sqs_status"].evidence) == 1
        queue_status = by_tool["sqs_status"].evidence[0]
        assert queue_status.data == {
            "queue": by_tool["sqs_status"].request.resource_key,
            "visible": 240,
            "not_visible": 12,
            "delayed": 3,
            "oldest_message_age_seconds": 600,
        }
        evidence = {item.evidence_id: item for item in _all_evidence(fixture)}
        expected_source = (
            "service_log_search" if fixture.variant == "partial" else "logs.filter_log_events"
        )
        required = [evidence[evidence_id] for evidence_id in fixture.expected.required_evidence_ids]
        oldest = next(item for item in required if "oldest" in str(item.data.get("message", "")))
        assert oldest.source == expected_source


def _eventbridge_payload(alarm: dict[str, JsonValue]) -> dict[str, JsonValue]:
    return {
        "version": "0",
        "id": alarm["event_id"],
        "detail-type": "CloudWatch Alarm State Change",
        "source": "aws.cloudwatch",
        "account": "000000000000",
        "time": alarm["state_timestamp"],
        "region": "ap-northeast-2",
        "resources": [alarm["alarm_arn"]],
        "detail": alarm["detail"],
    }


def test_alarm_is_runtime_normalized_and_resolves_to_synthetic_service(
    representative_fixtures: tuple[EvalFixture, ...],
) -> None:
    event_ids: set[str] = set()
    for fixture in representative_fixtures:
        assert set(fixture.alarm) == {
            "event_id",
            "alarm_arn",
            "alarm_name",
            "state_timestamp",
            "detail",
        }
        event = parse_alarm_event(_eventbridge_payload(fixture.alarm))
        normalized: dict[str, JsonValue] = {
            "event_id": event.event_id,
            "alarm_arn": event.alarm_arn,
            "alarm_name": event.alarm_name,
            "state_timestamp": event.state_timestamp.isoformat().replace("+00:00", "Z"),
            "detail": event.detail,
        }
        assert fixture.alarm == normalized
        assert event.event_id not in event_ids
        event_ids.add(event.event_id)
        assert event.event_id.startswith("evt-")
        assert event.event_id[4:].isdecimal()
        assert fixture.snapshot.incident_id == incident_id_for(event.event_id)
        assert event.alarm_arn == SYNTHETIC_ALARM_ARN
        assert event.alarm_name == SYNTHETIC_ALARM_NAME
        metric_name, reason = ALARM_SYMPTOMS[fixture.scenario]
        assert event.detail["state"] == {
            "value": "ALARM",
            "reason": reason,
            "timestamp": fixture.alarm["state_timestamp"],
        }
        state_timestamp = fixture.alarm["state_timestamp"]
        assert isinstance(state_timestamp, str)
        previous_timestamp = (
            (datetime.fromisoformat(state_timestamp.replace("Z", "+00:00")) - timedelta(minutes=1))
            .isoformat()
            .replace("+00:00", "Z")
        )
        assert event.detail["previousState"] == {
            "value": "OK",
            "reason": "synthetic metric within threshold",
            "timestamp": previous_timestamp,
        }
        assert event.detail["configuration"] == {
            "metrics": [
                {
                    "id": "m1",
                    "metricStat": {
                        "metric": {
                            "namespace": "PILO/Synthetic",
                            "name": metric_name,
                            "dimensions": {
                                "ClusterName": "pilo-dev-cluster",
                                "ServiceName": "pilo-dev-service-01",
                            },
                        },
                        "period": 60,
                        "stat": "Average",
                    },
                    "returnData": True,
                }
            ]
        }
        alarm_text = json.dumps(fixture.alarm).lower()
        assert "oom" not in alarm_text
        assert "deployment" not in alarm_text
        assert "root cause" not in alarm_text
        resolved_services = fixture.topology.resolve_alarm(event.alarm_arn)
        assert tuple(service.key for service in resolved_services) == ("pilo-dev-service-01",)


def test_all_evidence_uses_bounded_synthetic_time_window(
    representative_fixtures: tuple[EvalFixture, ...],
) -> None:
    for fixture in representative_fixtures:
        evidence = tuple(_all_evidence(fixture))
        assert evidence
        assert all(WINDOW_START <= item.observed_at <= WINDOW_END for item in evidence)


def test_representative_fixtures_use_only_synthetic_account(
    representative_fixtures: tuple[EvalFixture, ...],
) -> None:
    assert {fixture.alarm["alarm_arn"] for fixture in representative_fixtures} == {
        SYNTHETIC_ALARM_ARN
    }


def test_representative_scenario_labels_are_absent_from_runtime_modules() -> None:
    runtime_root = REPO_ROOT / "src" / "pilo_incident_investigator"
    literals: set[str] = set()
    for path in runtime_root.rglob("*.py"):
        if "evaluation" in path.parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        literals.update(
            node.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        )
    assert SCENARIOS.isdisjoint(literals)
