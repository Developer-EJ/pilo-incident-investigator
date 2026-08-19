# PILO dev 운영 파일럿 구현 계획

## 목표

모니터링 담당자가 Slack Alert Brief만으로 PILO dev Alarm의 대상, 관측된 이상, 정보 공백, 담당·runbook·private Issue 진입점을 판단하게 하고, Investigator 자체의 처리 상태를 CloudWatch EMF로 관측한다.

## 설계 요약

Protected topology의 선택적 `operations` metadata는 service owner/runbook과 Alarm priority를 제공하며 version 1 topology는 안전한 기본값으로 계속 읽는다. Handler는 redacted `IncidentBundle`과 validated `Topology`로부터 결정적 Alert Brief를 만든 뒤 기존 Publisher를 통해 private Issue URL과 함께 전송한다. Handler의 closed stage/outcome은 새 EMF renderer로 log group에 기록하여 추가 AWS 쓰기 권한 없이 Investigator의 성공·degraded·실패·지연을 관찰한다.

상세 설계: `docs/superpowers/specs/2026-08-20-pilo-dev-operations-pilot-design.md`

## 공통 안전 경계

- 대상은 PILO AWS dev, 리전은 `ap-northeast-2`, topology는 정확히 8개 서비스를 유지한다.
- runtime은 topology 허용 목록의 read-only 조사만 수행하며 `GetSecretValue`와 PILO 리소스 변경 API를 호출하지 않는다.
- Alert Brief는 redacted Snapshot Evidence와 validated topology metadata만 사용한다. Agent 가설, 원문 로그, ARN/account ID, Secret metadata, SQS URL, Git revision은 Slack에 넣지 않는다.
- `snapshot_only`가 파일럿 기본이고, `hybrid_agent`는 이 작업에서 활성화하거나 확장하지 않는다.
- GitHub Issue 실패 시 기존의 최소 degraded Slack 계약을 유지한다.
- EMF dimension은 `Mode`, `Stage`, `Collector`, `Outcome`의 closed enum만 사용한다. service key, Alarm name, Incident ID는 dimension에 넣지 않는다.
- 실제 topology, account ID, token/webhook, Bundle, Issue, 실제 Incident 출력은 저장소에 넣지 않는다.
- `make verify` 계약을 바꾸지 않는다. 외부 AWS·GitHub·Slack 호출은 기본 테스트에 넣지 않는다.

## PR 단위와 순서

각 PR은 `dev`에서 분기해 `dev`로 병합한다. PR 생성 전에 관련 테스트를 먼저 실패시키고(TDD), GitHub Actions `verify` 통과 후에만 병합한다. 문제가 생기면 해당 PR의 merge commit을 되돌려 기능 단위로 복구한다.

| 순서 | PR 경계 | 주요 파일 | 완료 조건 |
| --- | --- | --- | --- |
| 1 | topology 운영 metadata 계약 | `topology.py`, topology 단위 테스트, 익명 topology 예시 | 선택적 metadata의 strict validation 및 호환성 테스트 통과 |
| 2 | 결정적 Slack Alert Brief | `alert_brief.py`, `handler.py`, 단위·통합 테스트 | snapshot evidence만 사용하고 500자 안전 경계 테스트 통과 |
| 3 | Investigator EMF 지표 | `observability.py`, `handler.py`, 단위·통합 테스트 | closed dimension EMF와 정상·degraded·실패 경로 테스트 통과 |
| 4 | 운영 Runbook | 운영 문서, 문서 계약 테스트 | 수신·지표·실패·안전 경계가 한국어로 문서화됨 |

## PR 1 — Topology 운영 metadata 계약

**변경:** `Topology`에 `ServiceOperations(owner, runbook_url)`와 `AlarmOperations(priority)`를 추가한다. `operations`가 없으면 `owner/runbook=None`, priority=`P2`로 fallback한다.

**검증 먼저:** `tests/unit/test_topology.py`에 유효 metadata, 없는 metadata fallback, unknown/missing service·Alarm, `P0`, HTTP URL, query·fragment·user-info URL, 개행 또는 credential-shaped owner 거부 테스트를 추가한다.

**구현:** 기존 top-level 허용 목록에만 `operations`를 선택적으로 추가한다. block이 존재하면 service·Alarm 키 집합이 정확히 topology와 일치해야 한다. URL은 1–512자 HTTPS/netloc만 허용하고 query·fragment·자격 증명을 거부한다. owner는 1–80자 printable/control-free이며 Redactor 결과가 원문과 같아야 한다. priority는 `P1/P2/P3`만 허용한다. 공개 topology 예시에는 합성 metadata만 추가한다.

**완료:** `python -m pytest tests/unit/test_topology.py -q`, `git diff --check` 및 GitHub `verify`가 통과한다.

## PR 2 — 결정적 evidence-only Slack Alert Brief

**변경:** `render_slack_alert_brief(bundle, topology)`를 만들고 `handler.py`의 정상 Slack summary에 연결한다.

**검증 먼저:** ECS running/desired, stopped task count, ALB unhealthy target, RDS status, collector 실패, metadata 부재, evidence 부재, 500자 제한과 raw log/task ARN/account/queue/Secret/git revision/Agent direction 미노출을 단위 테스트로 고정한다. GitHub Issue 실패의 기존 degraded Slack 계약도 통합 테스트로 보존한다.

**구현:** Alarm으로 service를 resolve한 뒤 해당 service Snapshot Evidence의 정확한 source/data shape만 해석한다. 우선순위는 ECS, stopped task, ALB, RDS이며 최대 3개 사실만 고른다. 실패는 collector 이름의 closed mapping으로만 요약한다. Alarm·owner·runbook은 one-line normalize 및 Redactor equality 검증 뒤 closed multiline template에 넣고, 줄 경계에서만 500자로 자른다. invalid input은 외부 publish 전에 `UnsafeBundleError`를 낸다.

**완료:** `python -m pytest tests/unit/test_alert_brief.py tests/integration/test_handler.py -q`, `git diff --check` 및 GitHub `verify`가 통과한다.

## PR 3 — Investigator operational EMF metrics

**변경:** `emit_metric` renderer와 Handler의 수신·collector failure·published·degraded·failed duration 지표를 추가한다.

**검증 먼저:** fake logger로 valid JSON EMF, metric별 정확한 dimension, closed enum 위반, negative/non-integer, service/error/Incident ID 등 고카디널리티 입력 거부를 테스트한다. integration test에서는 normal, partial Snapshot, GitHub degraded 경로가 민감값 없이 필요한 지표를 남기는지 확인한다.

**구현:** metric은 `EventsReceived`, `IncidentsPublished`, `IncidentsDegraded`, `IncidentsFailed`, `CollectorFailures`, `ProcessingDuration`만 허용한다. dimension 계약은 각각 `Mode`, `Mode`, `Stage`, `Stage`, `Collector`, `Outcome`으로 고정한다. stage는 `parse_event`, `load_topology`, `claim_event`, `snapshot`, `investigation`, `render`, `publish`; outcome은 `published`, `degraded`, `failed`; collector는 결정적 여섯 collector만 허용한다. `ProcessingDuration`만 `Milliseconds`를 사용한다.

**완료:** `python -m pytest tests/unit/test_observability.py tests/integration/test_handler.py -q`, `git diff --check` 및 GitHub `verify`가 통과한다.

## PR 4 — Operator Runbook과 문서 계약

**변경:** `docs/runbooks/investigator-operations.md`와 관련 문서 계약 테스트를 추가하고 dev smoke runbook을 Alert Brief 수동 확인 절차로 보완한다.

**검증 먼저:** 문서에 `PILO/IncidentInvestigator`, `IncidentsFailed`, `IncidentsDegraded`, `snapshot_only`, `자동 복구`, `GetSecretValue`, `Evidence`가 포함되는지 테스트한다. smoke runbook은 service, Alarm, facts, information gap, Issue link의 수동 확인을 요구하되 원문 payload를 출력·저장하지 않는지 확인한다.

**구현:** Alert Brief 읽기, 지표 확인, 실패 대응, 안전 경계의 네 섹션으로 작성한다. Agent output은 가설임을 명시하고, GitHub 실패 시 degraded Slack만 전송되는 점, Slack 실패 시 Issue가 source of record인 점, 재전달은 EventBridge retry/idempotency로 처리되는 점을 다룬다. `README.md`는 사용자 작업 트리에 별도 변경이 있으므로 수정하지 않는다.

**완료:** 관련 문서 테스트, `python -m ruff check src tests scripts`, `git diff --check` 및 GitHub `verify`가 통과한다.

## 보호된 dev 배포 인계

모든 기능 PR이 병합돼도 이 계획은 `terraform apply`, topology 업로드, Alarm 상태 변경, 실제 Slack/GitHub publication을 실행하지 않는다. 기존 2단계 plan/apply와 synthetic smoke는 protected environment 승인 후 별도로 수행한다.
