# PILO dev 애플리케이션 Alarm 경로 확장 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 기존 26개 PILO dev Alarm 경로를 보존하면서 신규 8개를 추가해 정확히 34개 Alarm만 Incident Investigator로 전달하고, 보호 topology와 배포 상태를 비민감 검증으로 증명한다.

**Architecture:** 런타임 Lambda와 Terraform resource 정의는 변경하지 않는다. 대신 Python 검증기가 baseline/candidate topology, EventBridge event pattern, Terraform plan JSON을 fail-closed 방식으로 비교하고, 한국어 runbook이 보호 파일 생성부터 saved plan 적용과 사후 검증까지 순서를 고정한다. 저장소 변경을 `dev`에 병합한 뒤 보호 topology를 먼저 갱신하고, 전체 Terraform plan의 유일한 실질 변경이 EventBridge rule의 26→34 정확 집합 확장일 때만 같은 saved plan을 적용한다.

**Tech Stack:** Python 3.12, PyYAML, pytest, Ruff, mypy strict, PowerShell, AWS CLI, Terraform `>= 1.10, < 2.0`, GitHub CLI.

## Global Constraints

- 대상은 PILO AWS dev, `ap-northeast-2`, PILO ECS 8개 서비스다.
- 기존 26개 Alarm 경로를 모두 유지하고 신규 8개를 더한 정확히 34개만 허용한다.
- EventBridge pattern은 `aws.cloudwatch`의 `CloudWatch Alarm State Change` 중 `ALARM`만 수신한다.
- 조사 모드는 `snapshot_only`, Lambda 예약 동시성은 2를 유지한다.
- 보호 topology를 먼저 갱신·검증하고 나서 EventBridge 허용 목록을 확장한다.
- 실제 Alarm에 `SetAlarmState`를 호출하거나 ECS, ALB, SQS 등 PILO 애플리케이션 리소스를 변경하지 않는다.
- 실제 ARN, 계정 ID, topology 본문·경로, 운영 로그, token과 Secret은 Git, Issue, PR 또는 채팅에 기록하지 않는다.
- Terraform은 전체 saved plan만 사용한다. EventBridge rule의 정확한 리소스 집합 확장 외 실질 변경이 있으면 적용하지 않는다.
- 자동 rollback하지 않는다. rollback은 별도 saved plan 검토와 사용자 승인을 요구한다.
- `main` 대상 PR은 만들지 않고 기능 PR은 `dev`로만 병합한다.

---

## File Map

```text
scripts/verify_application_alarm_route.py       보호 입력의 topology 전환, EventBridge pattern, Terraform plan을 비민감 검증
tests/unit/test_application_alarm_route.py      26→34 정확 집합, mapping, plan diff와 오류 비노출 단위 테스트
docs/runbooks/application-alarm-route.md        보호 topology 선행 갱신, saved plan 적용, read-only 사후 검증 절차
tests/unit/test_application_alarm_route_runbook.py
                                                runbook의 순서·금지·불변 조건 계약 테스트
```

### Task 1: Fail-closed 애플리케이션 Alarm 경로 검증기

**Files:**
- Create: `scripts/verify_application_alarm_route.py`
- Create: `tests/unit/test_application_alarm_route.py`

**Interfaces:**
- Produces: `RouteContractError(ValueError)`; 실제 식별자를 예외 메시지에 넣지 않는다.
- Produces: `build_candidate_topology(baseline_text: str, additions: object) -> str`.
- Produces: `validate_topology_transition(baseline_text: str, candidate_text: str, additions: object) -> frozenset[str]`.
- Produces: `validate_event_pattern(pattern: object, expected_alarm_arns: frozenset[str]) -> None`.
- Produces: `validate_terraform_plan(plan: object, baseline_alarm_arns: frozenset[str], candidate_alarm_arns: frozenset[str]) -> None`.
- Produces CLI commands `build-candidate`, `validate-transition`, `validate-event-pattern`, `validate-plan`; 성공 시 개수만 출력하고 실패 시 `application Alarm route validation failed`만 stderr에 출력한다.

- [ ] **Step 1: 정확한 topology 전환의 실패 테스트 작성**

`tests/fixtures/topology/valid.yaml`을 읽고 합성 Alarm을 26개 가진 baseline을 만드는 helper를 추가한다. 계정은 `000000000000`, 서비스 key는 기존 합성 key만 사용한다.

```python
def synthetic_alarm(number: int) -> str:
    return (
        "arn:aws:cloudwatch:ap-northeast-2:000000000000:alarm:"
        f"synthetic-{number:02d}"
    )


def additions() -> dict[str, list[str]]:
    return {
        synthetic_alarm(27): ["pilo-dev-service-01"],
        synthetic_alarm(28): ["pilo-dev-service-01"],
        synthetic_alarm(29): ["pilo-dev-service-02"],
        synthetic_alarm(30): ["pilo-dev-service-02"],
        synthetic_alarm(31): ["pilo-dev-service-03"],
        synthetic_alarm(32): ["pilo-dev-service-03"],
        synthetic_alarm(33): ["pilo-dev-service-04"],
        synthetic_alarm(34): ["pilo-dev-service-04"],
    }


def test_candidate_is_exact_baseline_union_eight_additions() -> None:
    baseline = baseline_topology_text()
    candidate = build_candidate_topology(baseline, additions())

    alarm_arns = validate_topology_transition(baseline, candidate, additions())

    assert alarm_arns == frozenset(synthetic_alarm(i) for i in range(1, 35))
```

같은 파일에 다음 변형이 각각 `RouteContractError`를 발생시키는 테스트를 작성한다.

- baseline이 26개가 아님
- 추가 mapping이 8개가 아님
- 4개 서비스에 각 2개씩 연결되지 않음
- 신규 Alarm이 두 서비스에 연결됨
- 신규 Alarm이 baseline과 중복됨
- candidate가 기존 mapping 하나를 제거·변경함
- candidate가 아홉 번째 Alarm을 몰래 추가함
- candidate service resource가 baseline과 달라짐
- 신규 ARN에 `*` 또는 `?`가 있음

- [ ] **Step 2: focused test가 구현 부재로 실패하는지 확인**

Run: `python -m pytest tests/unit/test_application_alarm_route.py -q`

Expected: FAIL with import error for `scripts.verify_application_alarm_route`.

- [ ] **Step 3: candidate 생성과 topology 전환 검증 최소 구현**

`Topology.load`로 baseline과 candidate의 스키마를 모두 검증한다. count 상수와 addition shape를 먼저 검사하고, candidate mapping이 baseline과 additions의 정확한 합집합인지 비교한다.

```python
BASELINE_ALARM_COUNT = 26
ADDED_ALARM_COUNT = 8
FINAL_ALARM_COUNT = 34
ADDED_SERVICE_COUNT = 4
ALARMS_PER_ADDED_SERVICE = 2


class RouteContractError(ValueError):
    """Raised without embedding protected identifiers."""


def _normalize_additions(value: object) -> dict[str, tuple[str, ...]]:
    if not isinstance(value, dict) or len(value) != ADDED_ALARM_COUNT:
        raise RouteContractError("addition count is invalid")
    normalized: dict[str, tuple[str, ...]] = {}
    for alarm_arn, service_keys in value.items():
        if (
            not isinstance(alarm_arn, str)
            or "*" in alarm_arn
            or "?" in alarm_arn
            or not isinstance(service_keys, list)
            or len(service_keys) != 1
            or not isinstance(service_keys[0], str)
        ):
            raise RouteContractError("addition shape is invalid")
        normalized[alarm_arn] = (service_keys[0],)
    counts = Counter(keys[0] for keys in normalized.values())
    if len(counts) != ADDED_SERVICE_COUNT or set(counts.values()) != {
        ALARMS_PER_ADDED_SERVICE
    }:
        raise RouteContractError("addition service distribution is invalid")
    return normalized


def validate_topology_transition(
    baseline_text: str, candidate_text: str, additions: object
) -> frozenset[str]:
    baseline = Topology.load(baseline_text)
    candidate = Topology.load(candidate_text)
    normalized = _normalize_additions(additions)
    baseline_mappings = dict(baseline.alarm_mappings)
    candidate_mappings = dict(candidate.alarm_mappings)
    if len(baseline_mappings) != BASELINE_ALARM_COUNT:
        raise RouteContractError("baseline count is invalid")
    if set(baseline_mappings) & set(normalized):
        raise RouteContractError("addition overlaps baseline")
    if baseline.services != candidate.services:
        raise RouteContractError("service topology changed")
    if candidate_mappings != baseline_mappings | normalized:
        raise RouteContractError("candidate mapping set is invalid")
    if len(candidate_mappings) != FINAL_ALARM_COUNT:
        raise RouteContractError("candidate count is invalid")
    return frozenset(candidate_mappings)
```

`build_candidate_topology`은 baseline을 `yaml.safe_load`한 뒤 검증된 additions를 `alarms`에 합치고 `yaml.safe_dump(sort_keys=False)`로 반환한다. 반환값을 다시 `validate_topology_transition`에 통과시킨 뒤에만 CLI가 `Path.write_text(encoding="utf-8")`를 수행한다.

- [ ] **Step 4: EventBridge exact pattern 실패 테스트와 최소 구현**

```python
def test_event_pattern_accepts_only_exact_candidate_resources() -> None:
    expected = frozenset(synthetic_alarm(i) for i in range(1, 35))
    pattern = {
        "source": ["aws.cloudwatch"],
        "detail-type": ["CloudWatch Alarm State Change"],
        "region": ["ap-northeast-2"],
        "resources": sorted(expected),
        "detail": {"state": {"value": ["ALARM"]}},
    }

    validate_event_pattern(pattern, expected)
```

resource 하나 누락, 하나 초과, 중복 resource, `OK` 상태 추가, pattern key 추가, region 변경이 모두 실패하는 parametrized test를 작성한다. 구현은 입력 dict와 아래 기대 dict의 완전 동등성을 비교한다.

```python
def validate_event_pattern(
    pattern: object, expected_alarm_arns: frozenset[str]
) -> None:
    expected = {
        "source": ["aws.cloudwatch"],
        "detail-type": ["CloudWatch Alarm State Change"],
        "region": ["ap-northeast-2"],
        "resources": sorted(expected_alarm_arns),
        "detail": {"state": {"value": ["ALARM"]}},
    }
    if pattern != expected:
        raise RouteContractError("event pattern is invalid")
```

- [ ] **Step 5: Terraform plan 유일 변경 실패 테스트와 최소 구현**

Terraform `show -json`의 `resource_changes`에는 no-op이 포함될 수 있으므로 actions가 `['no-op']`인 항목은 제외한다. 실질 변경은 `aws_cloudwatch_event_rule.alarm` 하나, actions는 정확히 `['update']`여야 한다. before/after에서 `event_pattern`만 다르고 나머지 속성은 같아야 한다.

```python
def test_plan_allows_only_event_rule_resource_expansion() -> None:
    baseline = frozenset(synthetic_alarm(i) for i in range(1, 27))
    candidate = frozenset(synthetic_alarm(i) for i in range(1, 35))
    plan = terraform_plan(
        before_pattern=event_pattern(baseline),
        after_pattern=event_pattern(candidate),
    )

    validate_terraform_plan(plan, baseline, candidate)
```

Lambda change, IAM change, create/delete, 두 번째 update, 기존 resource 제거, 신규 8개 외 추가, unknown 값이 있는 pattern은 모두 실패해야 한다.

```python
def validate_terraform_plan(
    plan: object,
    baseline_alarm_arns: frozenset[str],
    candidate_alarm_arns: frozenset[str],
) -> None:
    if not isinstance(plan, dict) or plan.get("complete") is not True:
        raise RouteContractError("plan is incomplete")
    changes = [
        item
        for item in plan.get("resource_changes", [])
        if item.get("change", {}).get("actions") != ["no-op"]
    ]
    if len(changes) != 1:
        raise RouteContractError("plan change count is invalid")
    item = changes[0]
    change = item.get("change", {})
    if (
        item.get("address") != "aws_cloudwatch_event_rule.alarm"
        or change.get("actions") != ["update"]
        or change.get("after_unknown") not in ({}, {"arn": True, "id": True})
    ):
        raise RouteContractError("plan target is invalid")
    before = dict(change["before"])
    after = dict(change["after"])
    before_pattern = json.loads(before.pop("event_pattern"))
    after_pattern = json.loads(after.pop("event_pattern"))
    if before != after:
        raise RouteContractError("event rule attributes changed")
    validate_event_pattern(before_pattern, baseline_alarm_arns)
    validate_event_pattern(after_pattern, candidate_alarm_arns)
```

실제 Terraform JSON의 `after_unknown` shape를 fixture로 고정하고, 허용 shape를 넓혀야 한다면 실제 출력에서 필요한 최소 key만 추가한다. `complete`가 없거나 false이면 적용을 금지한다.

- [ ] **Step 6: CLI의 비민감 오류 계약 구현과 검증**

CLI는 JSON/YAML/파일/계약 오류를 한 곳에서 처리하며 원래 예외 문자열을 출력하지 않는다.

```python
try:
    return run_command(args)
except (OSError, UnicodeError, json.JSONDecodeError, yaml.YAMLError, TopologyError, RouteContractError):
    print("application Alarm route validation failed", file=sys.stderr)
    return 2
```

민감 marker를 잘못된 ARN이나 JSON key에 넣은 CLI test에서 stdout+stderr에 marker가 없음을 확인한다.

Run: `python -m pytest tests/unit/test_application_alarm_route.py -q`

Expected: PASS.

- [ ] **Step 7: 정적 검사 후 검증기 커밋**

Run: `python -m ruff check scripts/verify_application_alarm_route.py tests/unit/test_application_alarm_route.py && python -m ruff format --check scripts/verify_application_alarm_route.py tests/unit/test_application_alarm_route.py && python -m mypy scripts/verify_application_alarm_route.py tests/unit/test_application_alarm_route.py`

Expected: PASS.

```bash
git add scripts/verify_application_alarm_route.py tests/unit/test_application_alarm_route.py
git commit -m "feat: validate application Alarm route changes (#28)"
```

### Task 2: 보호된 적용·검증 runbook 계약

**Files:**
- Create: `docs/runbooks/application-alarm-route.md`
- Create: `tests/unit/test_application_alarm_route_runbook.py`

**Interfaces:**
- Consumes protected environment variables: `PILO_DEV_ACCOUNT_ID`, `PILO_BASELINE_TOPOLOGY_FILE`, `PILO_CANDIDATE_TOPOLOGY_FILE`, `PILO_NEW_ALARM_MAPPINGS_FILE`, `PILO_TOPOLOGY_BUCKET`, `PILO_TOPOLOGY_KEY`, `PILO_EVENT_RULE_NAME`, `PILO_LAMBDA_FUNCTION_NAME`, `PILO_DEPLOY_TFVARS_FILE`.
- Produces only protected temporary files outside the repository: candidate topology, `application-route.tfplan`, `application-route-plan.json`, `application-route-event-pattern.json`, and Terraform output logs.
- Never produces repository-tracked actual identifiers or topology data.

- [ ] **Step 1: runbook 안전 계약의 실패 테스트 작성**

```python
from pathlib import Path

RUNBOOK = Path(__file__).parents[2] / "docs" / "runbooks" / "application-alarm-route.md"


def test_runbook_updates_topology_before_event_route() -> None:
    text = RUNBOOK.read_text(encoding="utf-8")
    assert text.index("validate-transition") < text.index("s3api put-object")
    assert text.index("s3api put-object") < text.index("terraform -chdir=infra plan")
    assert text.index("validate-plan") < text.index("terraform -chdir=infra apply")


def test_runbook_never_mutates_application_alarms() -> None:
    text = RUNBOOK.read_text(encoding="utf-8").lower()
    assert "set-alarm-state" not in text
    assert "put-metric-alarm" not in text
    assert "delete-alarms" not in text
    assert "-target" not in text
```

추가 테스트는 `snapshot_only`, 예약 동시성 2, 정확히 26/8/34, checksum 검증, saved plan 재사용, 자동 rollback 금지, `dev` 전용과 `ap-northeast-2`를 요구한다.

- [ ] **Step 2: runbook 부재로 실패하는지 확인**

Run: `python -m pytest tests/unit/test_application_alarm_route_runbook.py -q`

Expected: FAIL because the runbook does not exist.

- [ ] **Step 3: 보호 입력, 저장소 밖 경로, 계정 사전 점검 절차 작성**

runbook은 `Set-StrictMode -Version Latest`와 `$ErrorActionPreference = 'Stop'`으로 시작한다. 모든 보호 변수가 비어 있지 않은지 확인하고, `Resolve-Path`와 `[IO.Path]::GetFullPath`로 baseline, candidate, additions, tfvars와 모든 temporary output parent가 저장소 밖인지 fail-closed로 확인한다. 기존 입력은 존재해야 하며 생성할 output은 저장소 밖의 기존 parent를 가져야 한다. 이후 `aws sts get-caller-identity`의 Account가 `PILO_DEV_ACCOUNT_ID`, region이 `ap-northeast-2`인지 비교한다. 실제 값을 출력하지 않는다.

```powershell
$account = aws sts get-caller-identity --query Account --output text --region ap-northeast-2 2>$null
if ($LASTEXITCODE -ne 0 -or $account -cne $env:PILO_DEV_ACCOUNT_ID) {
  throw "AWS account preflight failed"
}
$region = aws configure get region 2>$null
if ($LASTEXITCODE -ne 0 -or $region -cne "ap-northeast-2") {
  throw "AWS region preflight failed"
}
```

- [ ] **Step 4: topology 선행 갱신과 checksum 절차 작성**

현재 object를 `PILO_BASELINE_TOPOLOGY_FILE`로 내려받고, 보호된 8개 mapping JSON으로 candidate를 만든 뒤 전환을 검증한다. 명령 출력은 버린다.

```powershell
aws s3api get-object --bucket $env:PILO_TOPOLOGY_BUCKET --key $env:PILO_TOPOLOGY_KEY --region ap-northeast-2 $baselineTopologyFile 1>$null 2>$null
if ($LASTEXITCODE -ne 0) { throw "Protected topology download failed" }
python scripts/verify_application_alarm_route.py build-candidate --baseline $baselineTopologyFile --additions $newAlarmMappingsFile --output $candidateTopologyFile *> $null
if ($LASTEXITCODE -ne 0) { throw "Protected topology candidate build failed" }
python scripts/verify_application_alarm_route.py validate-transition --baseline $baselineTopologyFile --candidate $candidateTopologyFile --additions $newAlarmMappingsFile *> $null
if ($LASTEXITCODE -ne 0) { throw "Protected topology transition failed" }
aws s3api put-object --bucket $env:PILO_TOPOLOGY_BUCKET --key $env:PILO_TOPOLOGY_KEY --body $candidateTopologyFile --server-side-encryption AES256 --checksum-algorithm SHA256 --region ap-northeast-2 1>$null 2>$null
if ($LASTEXITCODE -ne 0) { throw "Protected topology upload failed" }
```

로컬 candidate SHA-256을 base64로 계산하고 `head-object --checksum-mode ENABLED`의 `ChecksumSHA256`, `AES256`, 양수 `ContentLength`와 비교한다. 값은 화면에 출력하지 않는다.

- [ ] **Step 5: saved full plan 검증·적용 절차 작성**

Lambda artifact를 재현 빌드하고 로컬 zip SHA-256과 현재 Lambda `CodeSha256`이 다르면 plan 전에 중단한다. 보호 tfvars는 정확한 34개 Alarm, `event_route_enabled=true`, `operating_mode="snapshot_only"`, `lambda_reserved_concurrency=2`를 제공한다.

```powershell
python scripts/build_lambda.py *> $null
if ($LASTEXITCODE -ne 0) { throw "Lambda artifact build failed" }
terraform -chdir=infra plan -input=false -var-file=$deployTfvarsFile -out=$savedPlanFile *> $terraformPlanLog
if ($LASTEXITCODE -ne 0) { throw "Terraform plan failed" }
$planJson = terraform -chdir=infra show -json $savedPlanFile 2>$terraformShowLog
if ($LASTEXITCODE -ne 0) { throw "Terraform plan JSON export failed" }
[IO.File]::WriteAllText($planJsonFile, $planJson, [Text.UTF8Encoding]::new($false))
python scripts/verify_application_alarm_route.py validate-plan --baseline $baselineTopologyFile --candidate $candidateTopologyFile --plan $planJsonFile *> $null
if ($LASTEXITCODE -ne 0) { throw "Terraform plan scope validation failed" }
terraform -chdir=infra apply -input=false $savedPlanFile *> $terraformApplyLog
if ($LASTEXITCODE -ne 0) { throw "Terraform apply failed" }
```

plan과 JSON은 `.gitignore`의 `*.tfplan` 및 별도 임시 경로를 사용하고, 적용에는 검증한 동일 saved plan만 사용한다. 실제 출력에서 EventBridge rule 외 변경이 보이면 검증기 결과와 무관하게 멈춘다.

- [ ] **Step 6: read-only 사후 검증과 수동 rollback 경계 작성**

`aws events describe-rule`의 `EventPattern`을 JSON 파일로 저장하고 candidate topology의 34개와 exact 비교한다. `aws events list-targets-by-rule`은 target 하나, Terraform output의 Lambda ARN과 동일, Input/InputPath/InputTransformer 없음이어야 한다. Lambda configuration의 `PILO_MODE`는 `snapshot_only`, reserved concurrency는 2여야 한다. 후속 `terraform plan -detailed-exitcode`는 0이어야 한다.

자연 발생 이벤트가 없으면 구성 실패로 판단하지 않으며 실제 Alarm 상태를 바꾸지 않는다. 검증 실패 시 자동 rollback하지 않고 기존 26개를 복원하는 별도 saved plan을 만든 후 사용자 승인을 받는다고 명시한다.

- [ ] **Step 7: runbook 계약과 전체 단위 테스트 실행 후 커밋**

Run: `python -m pytest tests/unit/test_application_alarm_route_runbook.py tests/unit/test_application_alarm_route.py -q`

Expected: PASS.

```bash
git add docs/runbooks/application-alarm-route.md tests/unit/test_application_alarm_route_runbook.py
git commit -m "docs: add application Alarm route runbook (#28)"
```

### Task 3: 저장소 전체 검증, PR과 dev 병합

**Files:**
- Verify only; no new file is expected.

**Interfaces:**
- Consumes commits from Tasks 1-2 plus the approved design and this plan.
- Produces one ready PR from `feat/28-application-alarm-route` to `dev`, then a merge commit or squash commit on `dev`.

- [ ] **Step 1: 저장소 전체 검증**

Run: `make verify`

Expected: Ruff, formatting, mypy strict, unit/integration/eval, Lambda packaging, Terraform format/init/validate/native test/IAM ownership checks all PASS. No live AWS, Slack or GitHub Incident mutation occurs.

- [ ] **Step 2: 민감정보와 범위 검토**

Run: `git diff origin/dev...HEAD --check && git diff --stat origin/dev...HEAD && git status --short`

Expected: only the approved design, implementation plan, verifier, tests and application Alarm runbook are changed; working tree is clean.

Run: `rg -n "[0-9]{12}|AKIA|xox[baprs]-|gh[pousr]_" docs scripts tests`

Expected: every 12-digit account value is the synthetic `000000000000`; no protected key, AWS key, Slack token or GitHub token. Synthetic detection patterns in security tests are allowed only after manual context inspection.

- [ ] **Step 3: 브랜치 push와 dev 대상 PR 생성**

```bash
git push -u origin feat/28-application-alarm-route
gh pr create --repo Developer-EJ/pilo-incident-investigator --base dev --head feat/28-application-alarm-route --title "feat: connect application Alarm route" --body "Closes #28"
```

Expected: PR base is exactly `dev`; `main` is not targeted.

- [ ] **Step 4: CI와 review 확인 후 자동 병합**

Run: `gh pr checks <PR_NUMBER> --watch`

Expected: all required checks PASS. 실패하면 `superpowers:systematic-debugging`, review feedback가 있으면 `superpowers:receiving-code-review`를 적용하고 수정 후 다시 검증한다.

Run: `gh pr merge <PR_NUMBER> --squash --delete-branch`

Expected: PR is merged into `dev`; `main` remains unchanged.

### Task 4: 보호 topology 전환

**Files:**
- Protected temporary files only; never add them to Git.

**Interfaces:**
- Consumes the currently deployed topology object and protected eight-Alarm mapping JSON.
- Produces the same protected object key with baseline mappings plus exactly eight mappings, AES256 encryption and SHA-256 checksum.

- [ ] **Step 1: dev 병합 commit과 AWS identity 확인**

Run: `git fetch origin dev && git rev-parse origin/dev && aws sts get-caller-identity --query Account --output text --region ap-northeast-2`

Expected: origin/dev contains the merged PR; AWS account equals the protected approved account. Account value is not copied into logs, Issue, PR or chat.

- [ ] **Step 2: 현재 topology를 보호 임시 파일로 보존**

Run the runbook preflight and `s3api get-object` block.

Expected: baseline validates as exactly 8 services and 26 Alarm mappings. The file remains outside the repository and is retained until post-apply verification completes, so a reviewed rollback candidate can be built if needed.

- [ ] **Step 3: candidate 생성·전환 검증**

Run the runbook `build-candidate` and `validate-transition` commands.

Expected: exactly eight additions across four services, two per service; all existing services/resources and 26 mappings are byte-semantically unchanged.

- [ ] **Step 4: candidate 업로드와 metadata 검증**

Run the runbook `s3api put-object` and checksum block.

Expected: same protected bucket/key, `AES256`, positive content length, remote `ChecksumSHA256` equals local candidate checksum. EventBridge remains at 26 resources, so new mappings are not active yet.

### Task 5: EventBridge 26→34 saved plan 적용

**Files:**
- Ignored `dist/` artifact and protected temporary plan files only.

**Interfaces:**
- Consumes the merged `dev`, protected deployment tfvars, baseline/candidate topology and current Terraform backend state.
- Produces one in-place update to `aws_cloudwatch_event_rule.alarm.event_pattern.resources`.

- [ ] **Step 1: Lambda artifact 무변경 확인**

Build the deterministic artifact, compute base64 SHA-256, and compare it with `aws lambda get-function --query Configuration.CodeSha256`.

Expected: hashes are equal. If different, stop before Terraform plan and report the mismatch; do not accept a Lambda update.

- [ ] **Step 2: 전체 saved plan 생성**

Run the runbook `terraform plan` and `terraform show -json` commands without `-target`.

Expected: complete plan; protected tfvars keep `snapshot_only`, reserved concurrency 2 and exact 34 Alarm ARNs.

- [ ] **Step 3: machine contract와 사람이 plan을 함께 검토**

Run `validate-plan`, then inspect the normal Terraform plan summary without copying identifiers elsewhere.

Expected: exactly one in-place EventBridge rule update; before resources are exact baseline 26, after resources are exact candidate 34; no create/delete and no Lambda, target, permission, IAM, S3, DynamoDB or log group change. Any deviation stops the task.

- [ ] **Step 4: 검증한 동일 saved plan 적용**

Run the runbook saved-plan apply command, which applies `$savedPlanFile` and captures all Terraform streams in the protected `$terraformApplyLog` outside the repository.

Expected: `0 added, 1 changed, 0 destroyed`, with the one change limited to the EventBridge rule.

### Task 6: 적용 후 read-only 검증과 정리

**Files:**
- No repository changes or committed outputs.

**Interfaces:**
- Consumes deployed AWS metadata only.
- Produces a concise non-sensitive completion report with counts and invariant states.

- [ ] **Step 1: EventBridge exact pattern과 target 검증**

Run the runbook `describe-rule`, `validate-event-pattern`, and `list-targets-by-rule` checks.

Expected: enabled rule, exact 34 resources, `ALARM` only, existing Lambda target one, no input transformation.

- [ ] **Step 2: Lambda 불변 조건과 topology metadata 검증**

Run the runbook Lambda configuration/concurrency and S3 `head-object --checksum-mode ENABLED` checks.

Expected: `PILO_MODE=snapshot_only`, reserved concurrency 2, topology AES256 and local candidate와 일치하는 SHA-256 checksum.

- [ ] **Step 3: Terraform 무변경 확인**

Run the runbook post-apply `terraform plan -detailed-exitcode` command, which uses `$deployTfvarsFile` and suppresses Terraform detail output.

Expected: exit code 0 and no changes. Exit code 2 means drift and must be reported; exit code 1 means plan error and must be diagnosed.

- [ ] **Step 4: passive observation과 보호 파일 정리**

실제 Alarm은 조작하지 않는다. 자연 발생 `ALARM` 이벤트가 있으면 Incident ID로 private S3 Bundle, private GitHub Issue, Slack 요약을 확인하되 내용을 공개 위치에 복사하지 않는다. 자연 이벤트가 없으면 구성 검증 완료로 종료한다.

post-apply 검증이 모두 통과한 뒤에만 protected candidate, mapping JSON, plan JSON과 tfplan을 삭제한다. baseline topology 복구본은 사용자 승인에 따라 보호 위치에서 보존하거나 안전하게 삭제한다. Git working tree가 깨끗하고 `main`이 변경되지 않았는지 확인한다.
