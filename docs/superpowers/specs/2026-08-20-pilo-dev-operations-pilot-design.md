# PILO dev 운영 파일럿 설계

## 상태

- 상태: 사용자 승인 설계
- 기준일: 2026-08-20
- 목표: 모니터링 담당자가 자연 발생 PILO dev Alarm의 Slack 알림만으로 대상 서비스, 관측된 이상, 정보 공백, 다음 조사 진입점을 파악하게 한다.

## 1. 문제와 성공 기준

현재 Investigator는 Alarm 이후 bounded Snapshot, private Bundle, private Issue를 만들 수 있지만, 정상 Slack 메시지가 Incident ID, 분류, Issue URL 중심이다. 담당자는 Issue를 열기 전에는 어느 서비스에서 어떤 이상이 관측되었는지 알기 어렵다. 또한 Investigator 자체의 실패·지연·부분 수집 실패를 운영 지표로 확인하는 경로가 없다.

이 파일럿은 원인을 자동 확정하거나 복구하는 서비스가 아니다. 성공은 다음 조건을 만족하는 것이다.

1. 정상 처리된 Alarm은 담당자가 1~2분 안에 Slack에서 대상 서비스, Alarm, 확인된 이상 1~3개, 수집 공백, private Issue 진입점을 읽을 수 있다.
2. Slack의 사실 문장은 Agent 판단이나 원문 로그가 아니라 redaction을 통과한 기본 Snapshot Evidence에서만 유도된다.
3. Alarm·수집·게시 실패와 처리 시간은 Investigator 소유 CloudWatch log group의 Embedded Metric Format(EMF) 지표로 남는다.
4. 기존 안전 경계(허용 목록, read-only 조사, Secret 값 비조회, 사람 승인 없는 복구·배포 금지)를 완화하지 않는다.
5. 보호된 dev에서 synthetic smoke를 먼저 통과하고, 승인된 실제 Alarm 경로에서 자연 발생 사건을 관찰해 메시지 유용성을 검토한다.

## 2. 범위와 비범위

### 범위

- 안전한 Slack Alert Brief renderer와 단위·통합 테스트
- 서비스 소유자, runbook URL, Alarm 우선순위를 protected topology로 제공하고 엄격히 검증하는 계약
- Lambda의 EMF 운영 지표와 이를 확인하는 runbook
- 기존 EventBridge/Lambda/S3/DynamoDB/GitHub/Slack 흐름의 protected dev 파일럿 절차
- 실제 사건 2~5건 또는 동등한 승인된 synthetic smoke 결과에 따른 메시지·수집 범위 검토

### 비범위

- PILO 애플리케이션의 빌드·배포·재시작·롤백·자동 복구
- CloudWatch, APM, PagerDuty 등의 범용 대체
- 허용 목록 밖 리소스 탐색, Secret 값 조회, 원문 로그의 Slack 복사
- Agent의 원인 가설을 Slack의 확인된 사실로 게시
- 실제 사건을 공개 fixture, 문서, 테스트 출력에 저장
- 초기 파일럿에서의 Alarm grouping, flapping suppression, Issue comment/update 자동화

반복 Alarm의 상관관계 처리와 Issue 타임라인 갱신은 실제 dev 관찰에서 Alert noise가 확인된 뒤 별도 설계한다. 현재의 EventBridge event ID 기반 정확 중복 방지는 유지한다.

## 3. 사용자 흐름

```text
CloudWatch Alarm
  -> EventBridge (명시된 Alarm ARN만)
  -> Lambda
  -> topology 허용 목록 검증
  -> 결정적 Snapshot 수집
  -> redaction
  -> private S3 Bundle
  -> private GitHub Issue
  -> Slack Alert Brief
  -> 모니터링 담당자의 Issue/Runbook 조사 및 사람이 승인한 조치
```

`snapshot_only`는 파일럿 기본값이다. `hybrid_agent`는 이 파일럿의 성공 기준이 아니며, 별도 평가와 승인 전에는 활성화하지 않는다.

정상 Slack Alert Brief의 형태는 다음과 같다.

```text
[PILO][P1][ALARM] pilo-api
Alarm: api-error-rate-high
확인: running 1/2; stopped task 2건; unhealthy target 1개
정보: 로그 수집 실패 1건
담당: API 운영
Runbook: <private HTTPS URL>
상세: <private GitHub Issue URL>
```

표현은 예시이며 실제 서비스 key, Alarm name, owner, URL은 protected topology에만 존재한다. Slack에는 최대 세 개의 확인된 사실만 표시한다. 해당 Evidence가 없으면 추정 문장으로 대체하지 않고 `확인 가능한 기본 상태가 없습니다`로 표시한다.

## 4. topology 계약 확장

기존 version 1의 서비스와 Alarm mapping은 유지한다. 파일럿에서는 새 최상위 선택 항목 `operations`를 지원한다.

```yaml
operations:
  services:
    pilo-api:
      owner: API 운영
      runbook_url: https://private.example.invalid/runbooks/pilo-api
  alarms:
    arn:aws:cloudwatch:ap-northeast-2:000000000000:alarm:api-error-rate-high:
      priority: P1
```

검증 규칙은 다음과 같다.

- `operations.services`의 key는 기존 `services[].key`와 정확히 일치해야 하며, 모든 운영 대상 서비스에 하나씩 존재한다.
- `owner`는 1~80자의 평문 label이고 credential 형태나 제어 문자를 포함할 수 없다.
- `runbook_url`은 HTTPS URL이며 query/fragment가 없고, credential을 포함할 수 없다. 이 URL은 private 운영 문서만 가리킨다.
- `operations.alarms`의 key는 기존 `alarms` key와 정확히 일치한다.
- `priority`는 `P1`, `P2`, `P3` 중 하나다.
- version 1 topology를 계속 읽을 수 있어야 한다. version 1에서는 priority를 `P2`, owner/runbook을 `미등록`으로 렌더링하고, 시작을 실패시키지 않는다.
- protected production-like topology가 운영 metadata를 도입하는 시점에는 version 2로 명시 승격할 수 있지만, 이 파일럿에서는 호환 가능한 확장만 사용한다.

topology는 계속 private S3 object에서만 읽으며, 저장소의 example은 익명 값만 사용한다.

## 5. Alert Brief renderer

새 renderer는 `redacted IncidentBundle`과 topology의 운영 metadata만 입력으로 받는다. raw event, raw AWS response, Agent 출력, credential provider에는 접근하지 않는다.

### 확인된 사실 선택 순서

대상 service별 Snapshot Evidence에서 아래 순서로 최대 세 문장을 선택한다.

1. `ecs.describe_services` 또는 `ecs.describe_services.all_pilo`의 `running/desired/pending`
2. `ecs.describe_tasks`의 stopped task 수
3. `elbv2.describe_target_health`의 non-healthy target 수
4. `rds.describe_db_instances`의 non-available 상태
5. `github.deployments`의 최근 배포 존재

각 문장은 하나 이상의 Evidence ID를 내부적으로 보유한다. Slack 본문에는 Evidence ID를 강제하지 않지만, Issue의 동일 문장 또는 상세 증거로 역추적 가능해야 한다. Evidence가 서로 충돌하거나 데이터 shape가 불완전하면 그 사실은 생략한다.

로그 원문, task ARN, account ID, Secret name/metadata, SQS queue URL, Git revision 전문은 Slack Brief에 넣지 않는다. Agent가 제안한 분류·원인 가설은 `Issue의 조사 방향`에만 남기며 Slack의 `확인` 행에 넣지 않는다.

Snapshot failure는 collector 이름이나 내부 예외를 노출하지 않고 `로그 수집 실패 1건`처럼 범주·건수로 표시한다. Alert Brief 전체는 기존 Slack payload size 제한과 Redactor 검증을 통과해야 하며, 검증에 실패하면 기존의 안전한 degraded publication 경로를 사용한다.

GitHub Issue 게시 실패 시에는 현재 계약을 유지한다. Slack에는 Incident ID와 `degraded: issue publication failed`만 보낸다. private Issue 없는 상세 정보를 Slack에 새로 복사하지 않는다.

## 6. Investigator 자체 모니터링

Lambda는 CloudWatch EMF를 log group에 기록한다. 새 AWS 쓰기 API 권한을 추가하지 않는다. 각 log event에는 safe structural Incident ID만 상관관계 키로 사용하고 Alarm ARN, account ID, log text, token은 넣지 않는다.

필수 metric은 다음과 같다.

| Metric | Unit | Dimension | 의미 |
| --- | --- | --- | --- |
| `EventsReceived` | Count | `Mode` | handler가 유효 Alarm event를 수신 |
| `IncidentsPublished` | Count | `Mode` | S3, Issue, Slack이 모두 완료 |
| `IncidentsDegraded` | Count | `Stage` | Issue 또는 Slack 게시가 미완료 |
| `IncidentsFailed` | Count | `Stage` | parse, topology, snapshot, render, publish 중 실패 |
| `CollectorFailures` | Count | `Collector` | bounded collector의 부분 실패 |
| `ProcessingDuration` | Milliseconds | `Outcome` | 수신부터 최종 상태까지 시간 |

`Stage`, `Collector`, `Mode`, `Outcome`은 작은 closed enum만 허용한다. service key·Alarm name·Incident ID는 metric dimension에 넣지 않아 cardinality와 민감정보 노출을 막는다.

초기 파일럿은 지표와 CloudWatch dashboard/query 검증까지만 포함한다. `IncidentsFailed` 등에 대한 실제 paging Alarm과 수신 채널은 팀의 기존 운영 경로·승인을 확인한 뒤 서비스 소유 CloudWatch Alarm으로 별도 설계한다. Investigator Alarm을 자기 EventBridge 입력으로 연결해서 재귀 호출해서는 안 된다.

## 7. 실패 처리

- topology extension이 누락된 version 1 파일은 normal renderer로 계속 처리한다.
- extension이 존재하지만 schema가 잘못되면 topology 전체를 fail-closed로 거부한다.
- Brief 렌더링 실패는 redacted Bundle과 Issue가 안전하게 만들어진 경우 기존 degraded publication 절차로 전환하고 EMF `IncidentsFailed{Stage=render}`를 남긴다.
- Collector 부분 실패는 Bundle·Issue·Slack의 정보 공백으로 남기고 처리를 중단하지 않는다.
- Agent timeout/model failure는 파일럿 모드에서 영향이 없다. mode는 `snapshot_only`로 고정한다.
- S3 Bundle 실패 시 GitHub와 Slack은 보내지 않는다. Issue 실패 시 기존의 최소 degraded Slack만 보낸다.

## 8. 테스트와 검증

### 자동 검증

- topology: 정상 extension, metadata 누락 호환, unknown service/alarm, URL/priority/credential-shape 거부
- renderer: 대상 서비스, max 3 facts, Evidence 기반 selection, failure summary, no-evidence fallback, byte limit
- security: raw log·ARN·account ID·Secret/credential shape가 Slack text에 들어가지 않음
- handler integration: normal publish, Issue failure degraded path, Snapshot partial failure, snapshot-only가 Agent schema를 노출하지 않는 경로
- EMF: metric name/unit/dimension enum, failure/outcome/duration 기록
- 기존 `make verify` 계약(정적 검사, unit/integration/eval, package, Terraform 검증)을 유지

### protected dev 검증

1. synthetic smoke route에서 snapshot-only로 deploy한다.
2. Slack test channel과 private Issue의 Alert Brief가 topology의 anonymized expected shape를 만족하는지 담당자가 확인한다.
3. Bundle encryption, DynamoDB final checkpoint, secret-pattern 없는 Lambda log를 기존 runbook으로 확인한다.
4. application Alarm route는 별도 approved saved plan으로 활성화한다.
5. 자연 Alarm 2~5건을 수동으로 검토해 `대상 식별`, `첫 조사 방향`, `정보 공백 표시`를 기록한다. 실제 내용은 공개 저장소에 저장하지 않는다.

## 9. 단계별 실행과 견적

| 단계 | 산출물 | 추정 구현 기간 |
| --- | --- | --- |
| A | topology extension, Alert Brief renderer, test fixture | 3~5일 |
| B | EMF operational metrics, tests, dashboard/query runbook | 3~5일 |
| C | README/runbook 갱신, full local/CI verification | 1~2일 |
| D | protected dev deployment, synthetic smoke, application route approval | 구현 2~4일 + 외부 승인/관찰 1~2주 |
| E | 자연 사건 review와 첫 조정 | 1~2주 |

개발 집중 기준 A~C는 약 2주, D~E를 포함한 파일럿은 약 3~5주다. D와 E는 AWS dev 권한, SSM parameter, private GitHub repository, Slack channel, 운영자 참여 여부에 크게 좌우된다.

## 10. 출시 기준

다음을 모두 만족해야 실제 application Alarm route를 운영 대상으로 취급한다.

1. `make verify`가 clean working tree에서 성공한다.
2. 보호된 synthetic smoke가 Bundle, private Issue, Slack Alert Brief, EMF 지표를 모두 검증한다.
3. 운영자가 Slack 메시지만 보고 대상 서비스·Alarm·확인 사실·정보 공백·Issue 링크를 식별할 수 있다고 확인한다.
4. 최소 두 건의 자연 Alarm 또는 별도로 승인된 대표 smoke case를 검토하고, 원문·Secret·실제 식별자를 Git에 남기지 않는다.
5. Investigator 실패 지표를 확인하는 담당자와 runbook이 정해져 있다.

자동 복구, `hybrid_agent` 활성화, Alert grouping은 이 출시 기준 이후에도 별도 승인과 설계를 요구한다.
