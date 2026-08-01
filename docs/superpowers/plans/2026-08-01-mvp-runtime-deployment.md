# PILO Incident Investigator MVP 런타임·배포 구현 계획

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** PILO dev Alarm 하나를 받아 결정적 Snapshot, 제한된 Bedrock 조사, redaction, private S3 Bundle, private GitHub Issue, Slack 알림까지 안전하게 처리하는 Lambda 기반 세로 흐름을 만든다.

**Architecture:** Python 3.12 Lambda가 EventBridge event를 정규화하고 DynamoDB checkpoint로 멱등성을 확보한다. Collector와 Agent Tool은 `pilo-topology.yaml` 허용 목록을 공유하며, redaction된 Bundle을 S3에 먼저 저장한 뒤 GitHub와 Slack을 순서대로 게시한다. Terraform은 서비스 소유 AWS 자원만 만들고 실제 topology와 두 SSM SecureString 값은 보호된 배포 입력으로 취급한다.

**Tech Stack:** Python 3.12, boto3/botocore, PyYAML, pytest, Ruff, mypy, AWS Bedrock Converse API, AWS Lambda, EventBridge, DynamoDB, S3, CloudWatch Logs, SSM Parameter Store, Terraform 1.8 이상 2.0 미만, GitHub REST API, Slack Incoming Webhook.

## Global Constraints

- 대상은 PILO AWS dev, `ap-northeast-2`, PILO ECS 8개 서비스다.
- 런타임 조사 API는 read-only이며 `GetSecretValue`와 PILO 애플리케이션 Secret 값 조회를 호출하지 않는다.
- Agent는 최대 2 round, round당 최대 3개, 전체 최대 6개 Tool 호출만 허용한다.
- topology 밖 리소스, 중복 Tool 요청, 선택 이유가 없는 Tool 요청은 실행 전에 거부한다.
- 모든 판단은 Evidence ID를 인용하고, 근거 부족·unknown·복합 장애는 `unclassified`로 처리한다.
- redaction 성공과 private S3 저장 성공 전에는 GitHub 또는 Slack으로 발송하지 않는다.
- GitHub token과 Slack Webhook URL은 정확히 두 개의 서비스 전용 SSM SecureString에서만 읽고 어떤 산출물이나 로그에도 남기지 않는다.
- 실제 topology, 실제 장애 로그, 실제 Secret, token, 계정 식별자는 공개 저장소에 커밋하지 않는다.
- Docker와 상시 서버를 추가하지 않는다.

---

## File Map

```text
pyproject.toml                         Python 패키지, Ruff, mypy, pytest 설정
Makefile                               make check/test/eval/terraform-check/verify 계약
src/pilo_incident_investigator/
  domain.py                            Event, Evidence, Snapshot, Investigation, Bundle 타입
  config.py                            환경 변수와 서비스 설정 검증
  topology.py                          YAML schema, Alarm 매핑, 리소스 허용 검사
  event.py                             EventBridge Alarm 파싱과 Incident ID
  state.py                             DynamoDB event lock와 publisher checkpoint
  snapshot.py                          고정 Collector 실행과 partial result 조립
  collectors/aws.py                   ECS, Logs, ALB, RDS 기본 Snapshot 조회
  integrations/github.py              배포·변경 파일 read와 Issue write
  integrations/credentials.py         두 SSM SecureString의 adapter 한정 로딩
  agent/contracts.py                   Tool 요청/응답 schema와 Tool registry
  agent/tools.py                       로그, RDS event, Secret metadata, SQS, GitHub file Tool
  agent/bedrock.py                     Bedrock Converse 호출과 구조화 응답 파싱
  agent/loop.py                        2 round/6 call 제한과 snapshot fallback
  redaction.py                         민감 문자열 제거와 redaction report
  brief.py                             Evidence 인용 검증과 Incident Brief 생성
  bundle.py                            canonical JSON Bundle 직렬화
  publishers.py                        S3→GitHub→Slack 순서와 degraded 처리
  handler.py                           Lambda composition root
tests/                                 각 모듈 단위·통합 테스트와 합성 입력
config/pilo-topology.example.yaml      공개 가능한 익명화 topology 예시
infra/                                 별도 Terraform state용 AWS 자원
.github/workflows/verify.yml           실제 외부 변경 없는 기본 CI
```

### Task 1: Toolchain and immutable domain contracts

**Files:**
- Create: `pyproject.toml`
- Create: `Makefile`
- Create: `src/pilo_incident_investigator/__init__.py`
- Create: `src/pilo_incident_investigator/domain.py`
- Create: `tests/unit/test_domain.py`

**Interfaces:**
- Produces: `AlarmEvent`, `Evidence`, `CollectorFailure`, `Snapshot`, `ToolRequest`, `ToolResult`, `SupportedStatement`, `Investigation`, `IncidentBundle` frozen dataclasses.
- Produces: `JsonValue = None | bool | int | float | str | list[JsonValue] | dict[str, JsonValue]`.

- [ ] **Step 1: Write tests that lock Evidence IDs and JSON-safe dataclasses**

```python
from datetime import UTC, datetime

from pilo_incident_investigator.domain import Evidence, Snapshot


def test_snapshot_rejects_duplicate_evidence_ids() -> None:
    evidence = Evidence(
        evidence_id="E-001",
        source="ecs.describe_services",
        observed_at=datetime(2026, 8, 1, tzinfo=UTC),
        summary="service desired=1 running=0",
        data={"desired": 1, "running": 0},
    )
    with pytest.raises(ValueError, match="duplicate Evidence ID"):
        Snapshot(incident_id="inc-123", evidence=(evidence, evidence), failures=())
```

- [ ] **Step 2: Run the focused test and confirm the package is absent**

Run: `python -m pytest tests/unit/test_domain.py -q`

Expected: FAIL because `pilo_incident_investigator.domain` does not exist.

- [ ] **Step 3: Add the package configuration and exact domain types**

```python
@dataclass(frozen=True, slots=True)
class Evidence:
    evidence_id: str
    source: str
    observed_at: datetime
    summary: str
    data: dict[str, JsonValue]


@dataclass(frozen=True, slots=True)
class SupportedStatement:
    text: str
    evidence_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Snapshot:
    incident_id: str
    evidence: tuple[Evidence, ...]
    failures: tuple[CollectorFailure, ...]

    def __post_init__(self) -> None:
        ids = [item.evidence_id for item in self.evidence]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate Evidence ID")
```

Set `requires-python = ">=3.12,<3.13"`; runtime dependencies are `boto3` and `PyYAML`; development dependencies are `pytest`, `pytest-cov`, `ruff`, `mypy`, `types-PyYAML`, and `boto3-stubs` with ECS, CloudWatch Logs, ELBv2, RDS, Secrets Manager, SQS, S3, DynamoDB, SSM, and Bedrock Runtime extras.

- [ ] **Step 4: Wire the command contract without claiming infrastructure exists**

```make
PYTHON ?= python

check:
	$(PYTHON) -m ruff check src tests
	$(PYTHON) -m ruff format --check src tests
	$(PYTHON) -m mypy src tests

test:
	$(PYTHON) -m pytest tests/unit tests/integration -q

eval:
	$(PYTHON) -m pytest tests/eval -q

terraform-check:
	terraform -chdir=infra fmt -check -recursive
	terraform -chdir=infra init -backend=false
	terraform -chdir=infra validate

verify: check test terraform-check
```

The evaluation plan later adds `eval` to `verify`; until that plan is complete, this runtime plan does not claim the 21-fixture contract is available.

- [ ] **Step 5: Run domain tests and static checks**

Run: `python -m pytest tests/unit/test_domain.py -q && python -m ruff check src tests && python -m mypy src tests`

Expected: PASS with no duplicate-ID or typing failures.

- [ ] **Step 6: Commit the domain contract**

```bash
git add pyproject.toml Makefile src/pilo_incident_investigator tests/unit/test_domain.py
git commit -m "build: establish runtime domain contracts"
```

### Task 2: Fail-closed topology loader and Alarm mapping

**Files:**
- Create: `src/pilo_incident_investigator/topology.py`
- Create: `config/pilo-topology.example.yaml`
- Create: `tests/fixtures/topology/valid.yaml`
- Create: `tests/fixtures/topology/duplicate.yaml`
- Create: `tests/unit/test_topology.py`

**Interfaces:**
- Produces: `Topology.load(text: str) -> Topology`.
- Produces: `Topology.resolve_alarm(alarm_arn: str) -> tuple[ServiceTopology, ...]`.
- Produces: `Topology.require_allowed(resource_type: str, resource_id: str) -> None`.
- Produces: `python -m pilo_incident_investigator.topology validate PATH`; success prints only `valid topology: 8 services`.

- [ ] **Step 1: Write fail-closed topology tests**

```python
def test_unknown_alarm_maps_to_no_service(topology: Topology) -> None:
    assert topology.resolve_alarm("arn:aws:cloudwatch:ap-northeast-2:000000000000:alarm:unknown") == ()


def test_resource_outside_allowlist_is_rejected(topology: Topology) -> None:
    with pytest.raises(TopologyDenied, match="not allowlisted"):
        topology.require_allowed("log_group", "/aws/ecs/not-pilo")
```

Also assert exactly eight unique service keys, `environment == "dev"`, `region == "ap-northeast-2"`, no duplicate resource IDs, and every Alarm mapping references an existing service key.

- [ ] **Step 2: Run topology tests and observe import failure**

Run: `python -m pytest tests/unit/test_topology.py -q`

Expected: FAIL because the loader and `TopologyDenied` are not defined.

- [ ] **Step 3: Implement strict `yaml.safe_load` parsing**

```python
@dataclass(frozen=True, slots=True)
class ServiceTopology:
    key: str
    ecs_cluster: str
    ecs_service: str
    log_groups: tuple[str, ...]
    target_groups: tuple[str, ...]
    rds_instances: tuple[str, ...]
    queues: tuple[str, ...]
    github_repository: str


def require_allowed(self, resource_type: str, resource_id: str) -> None:
    if resource_id not in self.allowed_resources[resource_type]:
        raise TopologyDenied(f"{resource_type} is not allowlisted")
```

The public example uses `000000000000`, `pilo-dev-service-01` through `pilo-dev-service-08`, and synthetic log/target/database/queue names. It contains no real ARN or repository name. The CLI reads the named file, calls the same `Topology.load`, and never prints topology contents.

- [ ] **Step 4: Run valid, duplicate, wrong-region, and unknown-Alarm tests**

Run: `python -m pytest tests/unit/test_topology.py -q`

Expected: PASS; malformed or out-of-scope topology always raises before any AWS client is called.

- [ ] **Step 5: Commit topology enforcement**

```bash
git add src/pilo_incident_investigator/topology.py config tests/fixtures/topology tests/unit/test_topology.py
git commit -m "feat: enforce PILO topology allowlist"
```

### Task 3: Event normalization and DynamoDB idempotency

**Files:**
- Create: `src/pilo_incident_investigator/event.py`
- Create: `src/pilo_incident_investigator/state.py`
- Create: `tests/fixtures/events/alarm.json`
- Create: `tests/unit/test_event.py`
- Create: `tests/unit/test_state.py`

**Interfaces:**
- Produces: `parse_alarm_event(payload: dict[str, JsonValue]) -> AlarmEvent`.
- Produces: `incident_id_for(event_id: str) -> str` formatted as `inc-` plus the first 20 lowercase hex characters of SHA-256.
- Produces: `IncidentStateStore.claim_event`, `mark_snapshot_complete`, `mark_bundle_stored`, `mark_issue_published`, and `mark_slack_attempted`.

- [ ] **Step 1: Write deterministic identity and conditional-lock tests**

```python
def test_incident_id_is_stable() -> None:
    assert incident_id_for("evt-001") == incident_id_for("evt-001")
    assert incident_id_for("evt-001").startswith("inc-")


def test_claim_uses_attribute_not_exists(table) -> None:
    store = DynamoIncidentStateStore(table)
    assert store.claim_event("evt-001", "inc-abc") is True
    assert store.claim_event("evt-001", "inc-abc") is False
```

- [ ] **Step 2: Confirm the focused tests fail**

Run: `python -m pytest tests/unit/test_event.py tests/unit/test_state.py -q`

Expected: FAIL because event parsing and the state adapter are absent.

- [ ] **Step 3: Implement strict EventBridge parsing and checkpoint names**

```python
class Checkpoint(StrEnum):
    CLAIMED = "claimed"
    SNAPSHOT_COMPLETE = "snapshot_complete"
    BUNDLE_STORED = "bundle_stored"
    ISSUE_PUBLISHED = "issue_published"
    SLACK_ATTEMPTED = "slack_attempted"


def incident_id_for(event_id: str) -> str:
    digest = hashlib.sha256(event_id.encode("utf-8")).hexdigest()[:20]
    return f"inc-{digest}"
```

Use a conditional DynamoDB `PutItem` with `attribute_not_exists(event_id)` for the first claim and conditional `UpdateItem` transitions that never move a checkpoint backwards.

- [ ] **Step 4: Run tests with botocore Stubber or an in-memory fake**

Run: `python -m pytest tests/unit/test_event.py tests/unit/test_state.py -q`

Expected: PASS, including duplicate delivery and retry-from-checkpoint cases.

- [ ] **Step 5: Commit idempotency support**

```bash
git add src/pilo_incident_investigator/event.py src/pilo_incident_investigator/state.py tests/fixtures/events tests/unit/test_event.py tests/unit/test_state.py
git commit -m "feat: add incident idempotency checkpoints"
```

### Task 4: Deterministic Snapshot orchestration

**Files:**
- Create: `src/pilo_incident_investigator/snapshot.py`
- Create: `tests/unit/test_snapshot.py`

**Interfaces:**
- Consumes: `AlarmEvent`, `Topology`, `Evidence`, `CollectorFailure`.
- Produces: `Collector.collect(context: CollectionContext) -> tuple[Evidence, ...]` protocol.
- Produces: `SnapshotCollector.collect(event: AlarmEvent, topology: Topology) -> Snapshot`.

- [ ] **Step 1: Test fixed ordering and partial failure preservation**

```python
def test_all_collectors_are_attempted_after_one_failure() -> None:
    calls: list[str] = []
    collectors = (
        FakeCollector("ecs", calls, evidence=(evidence("E-001"),)),
        FailingCollector("logs", calls, code="timeout"),
        FakeCollector("alb", calls, evidence=(evidence("E-002"),)),
    )
    snapshot = SnapshotCollector(collectors).collect(event(), topology())
    assert calls == ["ecs", "logs", "alb"]
    assert [item.evidence_id for item in snapshot.evidence] == ["E-001", "E-002"]
    assert snapshot.failures[0].collector == "logs"
```

- [ ] **Step 2: Run and confirm Snapshot orchestration is missing**

Run: `python -m pytest tests/unit/test_snapshot.py -q`

Expected: FAIL because `SnapshotCollector` is not defined.

- [ ] **Step 3: Implement a fixed collector tuple and stable Evidence allocator**

```python
DEFAULT_COLLECTOR_NAMES = (
    "alarm_target_ecs",
    "stopped_tasks_and_logs",
    "alb_target_health",
    "all_pilo_services",
    "recent_github_deployments",
    "rds_basic_status",
)
```

Catch only expected adapter exceptions, convert each to `CollectorFailure`, continue the remaining fixed collectors, and assign Evidence IDs after deterministic source/order sorting.

- [ ] **Step 4: Verify complete and partial Snapshot cases**

Run: `python -m pytest tests/unit/test_snapshot.py -q`

Expected: PASS with all six collector names attempted in the exact declared order.

- [ ] **Step 5: Commit the Snapshot orchestrator**

```bash
git add src/pilo_incident_investigator/snapshot.py tests/unit/test_snapshot.py
git commit -m "feat: orchestrate deterministic snapshots"
```

### Task 5: AWS and GitHub basic Snapshot collectors

**Files:**
- Create: `src/pilo_incident_investigator/collectors/__init__.py`
- Create: `src/pilo_incident_investigator/collectors/aws.py`
- Create: `src/pilo_incident_investigator/integrations/__init__.py`
- Create: `src/pilo_incident_investigator/integrations/credentials.py`
- Create: `src/pilo_incident_investigator/integrations/github.py`
- Create: `tests/unit/collectors/test_aws.py`
- Create: `tests/unit/integrations/test_credentials.py`
- Create: `tests/unit/integrations/test_github.py`

**Interfaces:**
- Produces: six `Collector` implementations matching `DEFAULT_COLLECTOR_NAMES`.
- Produces: `CredentialProvider.github_token() -> str` and `CredentialProvider.slack_webhook_url() -> str` with no value-bearing logging or repr.
- Produces: `GitHubClient.recent_deployments(repository: str, since: datetime) -> tuple[Deployment, ...]`.

- [ ] **Step 1: Write botocore Stubber tests for bounded API calls**

```python
def test_ecs_collector_rejects_service_outside_topology(ecs_client, topology) -> None:
    collector = EcsServiceCollector(ecs_client)
    with pytest.raises(TopologyDenied):
        collector.collect(context_for(service="not-pilo"), topology)


def test_ssm_secret_values_never_appear_in_repr(ssm_client) -> None:
    provider = SsmCredentialProvider(
        ssm_client,
        "/pilo-incident-investigator/dev/github-token",
        "/pilo-incident-investigator/dev/slack-webhook-url",
    )
    assert "token-value" not in repr(provider)
```

For ECS, assert paginated `ListTasks`/`DescribeTasks` and `DescribeServices`; for logs, assert a bounded start/end time and result limit; for ALB, assert only mapped target groups; for RDS, assert only `DescribeDBInstances`; for all-service health, assert exactly the eight topology services.

- [ ] **Step 2: Run collector and integration tests to observe missing adapters**

Run: `python -m pytest tests/unit/collectors tests/unit/integrations -q`

Expected: FAIL because AWS and GitHub adapters are absent.

- [ ] **Step 3: Implement bounded collectors and credential isolation**

```python
class SsmCredentialProvider:
    __slots__ = ("_client", "_github_name", "_slack_name", "_cache")

    def _load(self, name: str) -> str:
        response = self._client.get_parameter(Name=name, WithDecryption=True)
        return str(response["Parameter"]["Value"])

    def __repr__(self) -> str:
        return "SsmCredentialProvider(redacted=True)"
```

Every collector calls `topology.require_allowed` immediately before an AWS/GitHub request, supplies a finite time window, truncates oversized string fields, and returns normalized Evidence rather than raw SDK responses. `GitHubClient` keeps the bearer token in a private field and sanitizes HTTP exceptions before raising `IntegrationError`.

- [ ] **Step 4: Run all collector tests and assert no forbidden SDK call appears**

Run: `python -m pytest tests/unit/collectors tests/unit/integrations -q`

Expected: PASS; test spies report zero `GetSecretValue`, mutation, and non-allowlisted calls.

- [ ] **Step 5: Commit the basic collectors**

```bash
git add src/pilo_incident_investigator/collectors src/pilo_incident_investigator/integrations tests/unit/collectors tests/unit/integrations
git commit -m "feat: collect bounded PILO snapshot evidence"
```

### Task 6: Additional Tool registry and duplicate guard

**Files:**
- Create: `src/pilo_incident_investigator/agent/__init__.py`
- Create: `src/pilo_incident_investigator/agent/contracts.py`
- Create: `src/pilo_incident_investigator/agent/tools.py`
- Create: `tests/unit/agent/test_registry.py`
- Create: `tests/unit/agent/test_tools.py`

**Interfaces:**
- Produces: exact Tool names `service_log_search`, `rds_events`, `secret_rotation_metadata`, `sqs_status`, `github_changed_files`.
- Produces: `ToolRegistry.execute(request: ToolRequest, topology: Topology, seen: set[str]) -> ToolResult`.
- Produces: `ToolRequest.deduplication_key() -> str` from canonical JSON of Tool name, resource key, and parameters.
- Produces: `AgentProposal(tool_requests, facts, directions, missing, classification)` in `agent/contracts.py`; it imports the canonical `ToolRequest` and `ToolResult` from `domain.py` instead of defining competing types.

- [ ] **Step 1: Write allowlist, reason, and duplicate rejection tests**

```python
def test_request_without_reason_is_rejected(registry, topology) -> None:
    request = ToolRequest(tool="sqs_status", resource_key="queue-1", parameters={}, reason="")
    with pytest.raises(ToolDenied, match="reason is required"):
        registry.execute(request, topology, set())


def test_identical_request_is_not_executed_twice(registry, topology) -> None:
    request = request_for("rds_events", "db-1")
    seen = {request.deduplication_key()}
    with pytest.raises(ToolDenied, match="duplicate"):
        registry.execute(request, topology, seen)
```

- [ ] **Step 2: Run registry tests and observe missing policy**

Run: `python -m pytest tests/unit/agent/test_registry.py tests/unit/agent/test_tools.py -q`

Expected: FAIL because registry and Tool adapters are absent.

- [ ] **Step 3: Implement the closed Tool registry**

```python
TOOL_NAMES = frozenset({
    "service_log_search",
    "rds_events",
    "secret_rotation_metadata",
    "sqs_status",
    "github_changed_files",
})


@dataclass(frozen=True, slots=True)
class AgentProposal:
    tool_requests: tuple[ToolRequest, ...]
    facts: tuple[SupportedStatement, ...]
    directions: tuple[SupportedStatement, ...]
    missing: tuple[str, ...]
    classification: str
```

`secret_rotation_metadata` calls only `DescribeSecret` and records `RotationEnabled`, `LastRotatedDate`, `LastChangedDate`, and version-stage names without version values. SQS records approximate visible/not-visible/delayed counts and oldest-message metrics if present. GitHub returns paths and statuses, not full file contents, unless a later Evidence request names a specific allowlisted path and bounded diff.

Add a botocore Stubber test that registers only `DescribeSecret`; the test fails if the adapter attempts `GetSecretValue` or any unregistered operation.

- [ ] **Step 4: Run policy and Tool tests**

Run: `python -m pytest tests/unit/agent/test_registry.py tests/unit/agent/test_tools.py -q`

Expected: PASS for all five allowed Tools and rejection of a sixth arbitrary Tool.

- [ ] **Step 5: Commit the Tool boundary**

```bash
git add src/pilo_incident_investigator/agent tests/unit/agent
git commit -m "feat: constrain incident investigation tools"
```

### Task 7: Bedrock Agent loop with hard budgets and fallback

**Files:**
- Create: `src/pilo_incident_investigator/agent/bedrock.py`
- Create: `src/pilo_incident_investigator/agent/loop.py`
- Create: `tests/unit/agent/test_bedrock.py`
- Create: `tests/unit/agent/test_loop.py`

**Interfaces:**
- Produces: `BedrockPlanner.propose(snapshot, prior_results, remaining_budget) -> AgentProposal`.
- Produces: `BedrockPlanner.summarize(snapshot, tool_results=()) -> Investigation` for the no-Tool `snapshot_only` path.
- Produces: `InvestigationAgent.run(snapshot, topology) -> Investigation`.
- Produces: a `Planner` protocol containing both `propose` and `summarize`, reused by offline evaluation fakes.
- `AgentProposal` contains zero to three `ToolRequest` values plus `facts`, `directions`, `missing`, `classification`, and `classification_evidence_ids`. `unclassified` 외의 분류는 현재 Evidence 집합의 ID를 하나 이상 인용하고, 해당 인용은 최종 `Investigation`까지 보존한다.
- Hybrid 조사는 Tool 선택 `propose`를 최대 2회 호출한 뒤, 수집된 모든 Tool Evidence를 반영하는 최종 `summarize`를 최대 1회 호출한다. 따라서 모델 호출 상한은 총 3회다. 이 최종 synthesis는 Tool 선택 round에 포함하지 않으며 추가 Tool을 요청할 수 없다.
- `snapshot_only`는 Tool schema 없이 `summarize`를 최대 1회만 호출한다.

- [ ] **Step 1: Write budget, timeout, duplicate, and invalid-citation tests**

```python
def test_agent_never_executes_more_than_six_tools() -> None:
    planner = ScriptedPlanner([three_requests(1), three_requests(2), three_requests(3)])
    result = InvestigationAgent(planner, recording_registry()).run(snapshot(), topology())
    assert len(result.tool_calls) == 6
    assert planner.propose_count == 2
    assert planner.summarize_count == 1


def test_model_timeout_returns_snapshot_only_investigation() -> None:
    result = InvestigationAgent(TimeoutPlanner(), recording_registry()).run(snapshot(), topology())
    assert result.tool_calls == ()
    assert result.classification == "unclassified"


def test_snapshot_only_summary_cannot_request_tools() -> None:
    result = planner().summarize(snapshot(), tool_results=())
    assert result.tool_calls == ()
```

- [ ] **Step 2: Run the Agent tests and confirm failure**

Run: `python -m pytest tests/unit/agent/test_bedrock.py tests/unit/agent/test_loop.py -q`

Expected: FAIL because Bedrock parsing and loop control do not exist.

- [ ] **Step 3: Implement Converse requests and strict proposal decoding**

```python
MAX_ROUNDS = 2
MAX_TOOLS_PER_ROUND = 3
MAX_TOTAL_TOOLS = 6


for round_index in range(MAX_ROUNDS):
    remaining = MAX_TOTAL_TOOLS - len(executed)
    proposal = planner.propose(snapshot, tuple(results), remaining)
    requests = proposal.tool_requests[: min(MAX_TOOLS_PER_ROUND, remaining)]
    for request in requests:
        results.append(registry.execute(request, topology, seen))
        seen.add(request.deduplication_key())

investigation = planner.summarize(snapshot, tuple(results))
```

Send only normalized Snapshot Evidence, previous Tool Evidence, permitted Tool schema, and remaining budget to Bedrock. Reject unknown JSON fields, unknown Tool names, missing reasons, and Evidence citations not present in the current Evidence set. `summarize` omits the Tool schema entirely and cannot request additional Tools. The final synthesis receives all completed Tool results, including the second selection round. Catch Bedrock timeout/throttling/invalid output and return a template `unclassified` Investigation from the Snapshot while preserving already completed Tool results.

- [ ] **Step 4: Run Agent tests including malformed model output**

Run: `python -m pytest tests/unit/agent/test_bedrock.py tests/unit/agent/test_loop.py -q`

Expected: PASS with at most two `propose` calls, one final `summarize` call, three total model calls, and six Tool executions. `snapshot_only` uses only one `summarize` call.

- [ ] **Step 5: Commit the bounded Agent**

```bash
git add src/pilo_incident_investigator/agent/bedrock.py src/pilo_incident_investigator/agent/loop.py tests/unit/agent
git commit -m "feat: add bounded Bedrock investigation loop"
```

### Task 8: Redaction, Evidence validation, Brief, and canonical Bundle

**Files:**
- Create: `src/pilo_incident_investigator/redaction.py`
- Create: `src/pilo_incident_investigator/brief.py`
- Create: `src/pilo_incident_investigator/bundle.py`
- Create: `tests/unit/test_redaction.py`
- Create: `tests/unit/test_brief.py`
- Create: `tests/unit/test_bundle.py`

**Interfaces:**
- Produces: `Redactor.redact_bundle(bundle: IncidentBundle) -> tuple[IncidentBundle, RedactionReport]`.
- Produces: `validate_evidence_citations(investigation, evidence_ids) -> None`.
- Produces: `render_issue_markdown(bundle: IncidentBundle) -> str`.
- Produces: `canonical_bundle_json(bundle: IncidentBundle) -> bytes` with sorted keys and UTC ISO-8601 timestamps.

- [ ] **Step 1: Write leak-prevention and unsupported-claim tests**

```python
@pytest.mark.parametrize("secret", ["xoxb-1234567890-secret", "ghp_abcdefghijklmnopqrstuvwxyz123456", "password=hunter2"])
def test_redactor_removes_secret_like_values(secret: str) -> None:
    redacted, report = Redactor().redact_text(f"request failed: {secret}")
    assert secret not in redacted
    assert report.replacements == 1


def test_brief_rejects_unknown_evidence_id() -> None:
    with pytest.raises(UnsupportedClaim, match="E-999"):
        validate_evidence_citations(investigation(citations=("E-999",)), {"E-001"})
```

- [ ] **Step 2: Run security-focused tests and confirm failure**

Run: `python -m pytest tests/unit/test_redaction.py tests/unit/test_brief.py tests/unit/test_bundle.py -q`

Expected: FAIL because redaction and canonical rendering are absent.

- [ ] **Step 3: Implement recursive redaction and fail-closed rendering**

```python
REDACTION_RULES = (
    (re.compile(r"xox[baprs]-[A-Za-z0-9-]+"), "[REDACTED:SLACK_TOKEN]"),
    (re.compile(r"gh[pousr]_[A-Za-z0-9_]+"), "[REDACTED:GITHUB_TOKEN]"),
    (re.compile(r"(?i)(password|passwd|secret|token)\s*[=:]\s*[^\s,;]+"), r"\1=[REDACTED]"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED:AWS_ACCESS_KEY]"),
)
```

Traverse every string in Evidence data, summaries, failures, Agent text, and publication metadata. If redaction raises or citation validation fails, raise `UnsafeBundleError`; the publisher must not receive bytes. Render four explicit Issue sections: 확인된 사실, 조사 방향, 누락 정보, 분류 상태.

- [ ] **Step 4: Run tests and a credential-pattern scan over rendered output**

Run: `python -m pytest tests/unit/test_redaction.py tests/unit/test_brief.py tests/unit/test_bundle.py -q`

Expected: PASS; canonical serialization is byte-for-byte stable and all injected secret-like values are absent.

- [ ] **Step 5: Commit safe output generation**

```bash
git add src/pilo_incident_investigator/redaction.py src/pilo_incident_investigator/brief.py src/pilo_incident_investigator/bundle.py tests/unit/test_redaction.py tests/unit/test_brief.py tests/unit/test_bundle.py
git commit -m "feat: redact and validate incident bundles"
```

### Task 9: Ordered publishers and degraded behavior

**Files:**
- Create: `src/pilo_incident_investigator/publishers.py`
- Modify: `src/pilo_incident_investigator/integrations/github.py`
- Create: `tests/unit/test_publishers.py`

**Interfaces:**
- Consumes: canonical redacted Bundle bytes, Issue Markdown, Incident ID, `IncidentStateStore`.
- Produces: `PublishResult(bundle_uri: str, issue_url: str | None, slack_status: str)`.
- Enforces: S3 first, GitHub second, Slack third; resume from checkpoints.

- [ ] **Step 1: Write exact call-order and failure-matrix tests**

```python
def test_publish_order_is_s3_then_github_then_slack() -> None:
    calls: list[str] = []
    Publisher(recording_s3(calls), recording_github(calls), recording_slack(calls), state()).publish(bundle())
    assert calls == ["s3", "github", "slack"]


def test_s3_failure_blocks_all_external_publication() -> None:
    calls: list[str] = []
    with pytest.raises(BundleStoreFailed):
        Publisher(failing_s3(calls), recording_github(calls), recording_slack(calls), state()).publish(bundle())
    assert calls == ["s3"]


def test_github_failure_sends_minimal_degraded_slack() -> None:
    result = publisher_with_failed_github().publish(bundle())
    assert result.issue_url is None
    assert sent_slack_body() == {"text": "inc-123 — degraded: issue publication failed"}
```

- [ ] **Step 2: Run publisher tests and observe missing choreography**

Run: `python -m pytest tests/unit/test_publishers.py -q`

Expected: FAIL because `Publisher` and checkpoint resume behavior are absent.

- [ ] **Step 3: Implement idempotent S3, GitHub, and Slack adapters**

```python
bundle_key = f"incidents/{bundle.incident_id}/bundle.json"
s3.put_object(
    Bucket=config.bundle_bucket,
    Key=bundle_key,
    Body=bundle_bytes,
    ContentType="application/json",
    ServerSideEncryption="AES256",
)
```

Extend `GitHubClient` with `find_issue_by_incident_id` and `create_incident_issue`; both sanitize response/error bodies before returning. For Incident ID `inc-123`, GitHub searches open and closed Issues for the exact hidden marker `<!-- incident-id:inc-123 -->` before creating a new Issue. Normal Slack contains only summary and private Issue URL. GitHub failure sends only Incident ID plus degraded state. Slack failure records `slack_attempted=failed`; retry may duplicate and the message always includes Incident ID.

- [ ] **Step 4: Run the full failure matrix**

Run: `python -m pytest tests/unit/test_publishers.py -q`

Expected: PASS for success, partial Collector result, S3 failure, GitHub failure, Slack failure, checkpoint resume, and duplicate Slack cases.

- [ ] **Step 5: Commit ordered publication**

```bash
git add src/pilo_incident_investigator/publishers.py src/pilo_incident_investigator/integrations/github.py tests/unit/test_publishers.py
git commit -m "feat: publish incident records in safe order"
```

### Task 10: Lambda composition root and local end-to-end test

**Files:**
- Create: `src/pilo_incident_investigator/config.py`
- Create: `src/pilo_incident_investigator/handler.py`
- Create: `tests/integration/test_handler.py`
- Create: `tests/fixtures/responses/`

**Interfaces:**
- Produces: `handler.lambda_handler(event: dict[str, JsonValue], context: object) -> dict[str, str]`.
- Configuration keys: `PILO_REGION`, `PILO_TOPOLOGY_BUCKET`, `PILO_TOPOLOGY_KEY`, `PILO_STATE_TABLE`, `PILO_BUNDLE_BUCKET`, `PILO_GITHUB_REPOSITORY`, `PILO_GITHUB_TOKEN_PARAMETER`, `PILO_SLACK_WEBHOOK_PARAMETER`, `PILO_BEDROCK_MODEL_ID`, `PILO_MODE`.
- `PILO_MODE` is exactly `snapshot_only` or `hybrid_agent` and defaults to `snapshot_only`; deployment may select `hybrid_agent` only after the evaluation gate passes.

- [ ] **Step 1: Write an end-to-end test with only fake external clients**

```python
def test_alarm_reaches_slack_with_issue_link(runtime) -> None:
    response = runtime.handle(load_json("tests/fixtures/events/alarm.json"))
    assert response == {"incident_id": "inc-expected", "status": "published"}
    assert runtime.s3.keys == ["incidents/inc-expected/bundle.json"]
    assert runtime.github.created_issue_count == 1
    assert runtime.slack.messages[0]["issue_url"].startswith("https://github.com/")


def test_snapshot_only_mode_never_exposes_tool_schema(runtime) -> None:
    runtime.config = replace(runtime.config, mode="snapshot_only")
    runtime.handle(load_json("tests/fixtures/events/alarm.json"))
    assert runtime.planner.summarize_calls == 1
    assert runtime.tool_registry.calls == []
```

- [ ] **Step 2: Run the integration test and observe missing composition**

Run: `python -m pytest tests/integration/test_handler.py -q`

Expected: FAIL because configuration validation and handler wiring are absent.

- [ ] **Step 3: Implement configuration and dependency construction**

```python
def lambda_handler(event: dict[str, JsonValue], context: object) -> dict[str, str]:
    runtime = build_runtime(RuntimeConfig.from_environment())
    outcome = runtime.handle(event)
    return {"incident_id": outcome.incident_id, "status": outcome.status}
```

`Runtime.handle` calls `planner.summarize(snapshot, tool_results=())` in `snapshot_only` mode and `InvestigationAgent.run(snapshot, topology)` in `hybrid_agent` mode. Load protected topology from `s3://$PILO_TOPOLOGY_BUCKET/$PILO_TOPOLOGY_KEY`, validate it before creating any investigation request, and cache it only for the warm Lambda process. Log structured Incident ID, stage, duration, and failure code; never log raw events, Evidence payloads, model prompts, SSM values, or HTTP authorization headers.

- [ ] **Step 4: Run integration, unit, static, and format checks**

Run: `make check && make test`

Expected: PASS with no live AWS, GitHub, Slack, or Bedrock calls.

- [ ] **Step 5: Commit the runnable Lambda composition**

```bash
git add src/pilo_incident_investigator/config.py src/pilo_incident_investigator/handler.py tests/integration tests/fixtures/responses
git commit -m "feat: compose incident Lambda runtime"
```

### Task 11: Terraform-owned AWS resources and least-privilege IAM

**Files:**
- Create: `infra/versions.tf`
- Create: `infra/variables.tf`
- Create: `infra/main.tf`
- Create: `infra/iam.tf`
- Create: `infra/outputs.tf`
- Create: `infra/tests/runtime.tftest.hcl`
- Create: `scripts/check_iam_policy.py`
- Create: `tests/unit/test_iam_policy.py`

**Interfaces:**
- Consumes: deployment inputs for existing Alarm event pattern, Bedrock model/inference profile ARN, protected topology object key, private incident repository name, and exactly two existing SSM parameter ARNs.
- Produces: Lambda, EventBridge rule/target/permission, private S3 bucket with 7-day lifecycle on `incidents/`, DynamoDB table, IAM role/policies, CloudWatch log group.
- Does not produce: ECS, ALB, RDS, SQS, application Secrets Manager resources, SSM parameter values, GitHub repository, or Slack Webhook.

- [ ] **Step 1: Write Terraform tests for ownership and prohibitions**

```hcl
run "runtime_resources_are_bounded" {
  command = plan

  assert {
    condition     = aws_s3_bucket_lifecycle_configuration.bundle.rule[0].filter[0].prefix == "incidents/"
    error_message = "Only incident bundles may expire after seven days."
  }

  assert {
    condition     = aws_dynamodb_table.state.billing_mode == "PAY_PER_REQUEST"
    error_message = "The event-driven state table must not reserve capacity."
  }
}
```

Add a policy assertion script that rejects `secretsmanager:GetSecretValue`, wildcard `Resource = "*"` on PILO read actions, and every ECS/RDS/ELB/SQS mutation action.

Also assert the Terraform `operating_mode` variable defaults to `snapshot_only` and rejects any value other than `snapshot_only` or `hybrid_agent`.

- [ ] **Step 2: Run Terraform tests before resources exist**

Run: `terraform -chdir=infra init -backend=false && terraform -chdir=infra test`

Expected: FAIL because the Terraform module is absent.

- [ ] **Step 3: Implement exact service-owned resources**

```hcl
resource "aws_s3_bucket_lifecycle_configuration" "bundle" {
  bucket = aws_s3_bucket.bundle.id
  rule {
    id     = "expire-incident-bundles-after-seven-days"
    status = "Enabled"
    filter { prefix = "incidents/" }
    expiration { days = 7 }
  }
}
```

Block all public S3 access, enable SSE-S3 bucket encryption, set DynamoDB partition key `event_id`, set explicit log retention, add Lambda reserved concurrency and timeout, configure bounded EventBridge retries, and scope Bedrock invocation to the supplied ARN. IAM may read the two supplied SSM parameter ARNs and the protected topology object; it may write only the service bundle prefix, state table, and log group. Do not add a service-owned SQS queue in this initial scope.

- [ ] **Step 4: Run Terraform format, validate, tests, and policy scan**

Run: `make terraform-check && terraform -chdir=infra test && python scripts/check_iam_policy.py infra`

Expected: PASS with no forbidden action and no application resource declaration.

- [ ] **Step 5: Commit Terraform ownership boundaries**

```bash
git add infra scripts/check_iam_policy.py tests/unit/test_iam_policy.py
git commit -m "infra: define isolated incident investigator stack"
```

### Task 12: Packaging, CI verification, and deployment runbook

**Files:**
- Create: `scripts/build_lambda.py`
- Create: `tests/unit/test_build_lambda.py`
- Create: `.github/workflows/verify.yml`
- Create: `.gitignore`
- Modify: `README.md`
- Modify: `AGENTS.md`

**Interfaces:**
- Produces: deterministic `dist/pilo-incident-investigator.zip` without Docker.
- CI executes `make check`, `make test`, and `make terraform-check` without AWS write credentials. The evaluation plan upgrades this to the final `make verify` contract.
- Deployment runbook requires explicit opt-in and protected values for live topology plus the two existing SSM SecureStrings.

- [ ] **Step 1: Test deterministic packaging and exclusion rules**

```python
def test_bundle_excludes_operational_data(tmp_path: Path) -> None:
    artifact = build_lambda(tmp_path)
    names = zip_names(artifact)
    assert "config/pilo-topology.yaml" not in names
    assert not any(name.endswith((".env", ".tfstate")) for name in names)
```

- [ ] **Step 2: Run packaging tests before scripts exist**

Run: `python -m pytest tests/unit/test_build_lambda.py tests/unit/test_iam_policy.py -q`

Expected: FAIL because the build and IAM scanners are absent.

- [ ] **Step 3: Implement deterministic zip packaging and no-write CI**

```yaml
jobs:
  verify:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: python -m pip install -e ".[dev]"
      - run: make check
      - run: make test
      - run: make terraform-check
```

Build sorted zip entries with fixed timestamps and include only installed runtime dependencies plus `src/pilo_incident_investigator`. The README runbook must state that live deployment is never part of local verification, requires a separate protected environment approval, and must verify both SSM parameters and the private topology S3 object exist without printing values.

- [ ] **Step 4: Run the complete local contract**

Run: `make check && make test && make terraform-check && python scripts/build_lambda.py && git status --short`

Expected: all checks PASS; artifact is reproducible; the working tree is clean because `dist/` is ignored; no AWS, GitHub, Slack, or Bedrock mutation occurred.

- [ ] **Step 5: Commit packaging and documentation**

```bash
git add scripts/build_lambda.py tests/unit/test_build_lambda.py .github/workflows/verify.yml README.md AGENTS.md .gitignore
git commit -m "build: add reproducible verification and packaging"
```

### Task 13: Isolated live vertical-slice verification

**Files:**
- Modify: `README.md`
- Create: `docs/runbooks/dev-smoke-test.md`
- Create: `tests/fixtures/events/dev-smoke-entry.json`

**Interfaces:**
- Consumes: approved PILO dev deployment, protected topology object, two service-owned SSM SecureStrings, private incident repository, test Slack channel.
- Produces: one synthetic Alarm Incident ID, one redacted S3 Bundle, one private Issue, and one Slack message.

- [ ] **Step 1: Record the preflight checks without reading credential values**

Create `dev-smoke-entry.json` with the synthetic Alarm ARN and account `000000000000`; the detail sets `state.value` to `ALARM`, reason to `synthetic smoke test`, and a fixed test timestamp.

```powershell
aws sts get-caller-identity
aws ssm describe-parameters --parameter-filters Key=Name,Option=Equals,Values=/pilo-incident-investigator/dev/github-token --query 'Parameters[0].Name' --output text
aws ssm describe-parameters --parameter-filters Key=Name,Option=Equals,Values=/pilo-incident-investigator/dev/slack-webhook-url --query 'Parameters[0].Name' --output text
python -m pilo_incident_investigator.topology validate $env:PILO_TOPOLOGY_FILE
terraform -chdir=infra plan -out saved-dev.plan
```

Expected: approved dev account and region; parameter names are present; the protected local topology validates without printing its contents; Terraform plan contains only service-owned resources. The deployment operator provisions the two SecureString values through the approved secret-management workflow before this check, never through a committed file or Terraform variable.

- [ ] **Step 2: Deploy only after explicit protected-environment approval**

Run: `terraform -chdir=infra apply saved-dev.plan`

Expected: Lambda, EventBridge, private S3, DynamoDB, IAM, and log group changes only. Abort if ECS, ALB, RDS, SQS, application Secret, GitHub repository, or Slack configuration changes appear.

Then upload the already validated protected topology and verify only its metadata:

```powershell
$env:PILO_BUNDLE_BUCKET = terraform -chdir=infra output -raw bundle_bucket_name
aws s3 cp $env:PILO_TOPOLOGY_FILE "s3://$env:PILO_BUNDLE_BUCKET/config/pilo-topology.yaml" --sse AES256
aws s3api head-object --bucket $env:PILO_BUNDLE_BUCKET --key config/pilo-topology.yaml --query '{Encryption:ServerSideEncryption,Length:ContentLength}'
```

Expected: the object uses `AES256`; command output contains no topology body.

- [ ] **Step 3: Send one synthetic Alarm event and capture the Incident ID**

Run: `aws events put-events --entries file://tests/fixtures/events/dev-smoke-entry.json`

Expected: one accepted EventBridge entry and one Incident ID in the Lambda structured log.

- [ ] **Step 4: Verify outputs without copying sensitive contents locally**

Check S3 object metadata and encryption, GitHub Issue visibility and Evidence citations, Slack summary/link shape, DynamoDB checkpoints, and the absence of token/Secret patterns in Lambda logs. Trigger the same event again and confirm no second Issue is created; a duplicate Slack delivery is acceptable only with the same Incident ID.

- [ ] **Step 5: Record results and commit runbook corrections only**

```bash
git add README.md docs/runbooks/dev-smoke-test.md tests/fixtures/events/dev-smoke-entry.json
git commit -m "docs: verify PILO dev incident vertical slice"
```

Do not commit live command output, Bundle contents, Issue text, Slack payloads, resource identifiers, or topology.
