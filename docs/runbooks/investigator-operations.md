# Incident Investigator 운영 절차

이 문서는 PILO dev의 모니터링 담당자가 Alert Brief와 CloudWatch 지표로 초기 조사 상태를 판단하는 절차다. Investigator는 CloudWatch Alarm을 대체하거나 원인을 확정하는 시스템이 아니다. 기본 모드는 `snapshot_only`이며, 조사 결과는 사람의 후속 확인을 위한 입력이다.

## Alert Brief 읽기

Alert Brief는 Alarm 하나에 대한 redacted Snapshot Evidence와 보호된 topology metadata만으로 구성된다. 아래 순서로 읽는다.

1. 제목의 우선순위, Alarm, 서비스로 어떤 운영 범위의 알림인지 확인한다.
2. `확인:` 행의 running 수, stopped task 수, unhealthy target 수, RDS 상태처럼 실제로 수집된 사실을 읽는다. 이 값은 원인 확정이 아니다.
3. `수집 실패` 또는 `확인 가능한 기본 상태가 없습니다`가 있으면 정보 공백으로 기록하고, 해당 범위는 private Issue에서 Evidence ID를 따라 추가 조사한다.
4. 담당과 Runbook이 있으면 해당 서비스의 소유자와 절차로 연결한다. private Issue 링크는 상세 redacted Bundle과 조사 기록의 진입점이다.

Brief에는 원문 로그, ARN, 계정 번호, Secret metadata, SQS URL, Git revision, Agent의 방향 제안이 들어가지 않는다. `hybrid_agent`가 별도로 승인되어 사용되더라도 Agent 출력은 가설이며 Evidence ID로 확인되지 않은 내용을 사실이나 원인으로 취급하지 않는다.

## 지표 확인

CloudWatch Logs의 Investigator Lambda log group에서 `PILO/IncidentInvestigator` EMF 지표를 확인한다. dimension은 Mode, Stage, Collector, Outcome의 고정 enum뿐이며 서비스명·Alarm명·Incident ID로 지표를 분할하지 않는다.

| 지표 | 의미 | 담당자 조치 |
| --- | --- | --- |
| `EventsReceived` | 유효한 Alarm event를 수신함 | Mode별 유입량이 예상과 맞는지 확인하고, Alert Brief 또는 EventBridge delivery와 대조한다. |
| `IncidentsPublished` | Bundle, private Issue, Slack 게시까지 완료됨 | Alert Brief의 Issue 링크로 들어가 Evidence와 정보 공백을 검토한다. |
| `IncidentsDegraded` | publish 단계가 부분 완료됨 | `Stage=publish`를 확인하고 degraded Slack만 받았는지, private Issue가 source of record인지 확인한다. |
| `IncidentsFailed` | parse_event, load_topology, claim_event, snapshot, investigation, render, publish 중 처리 실패 또는 안전한 Brief 축소 | Stage와 같은 시각의 Lambda 로그를 확인하되, 민감한 원문을 외부 채널에 복사하지 않는다. `render`는 안전 검증 때문에 간략 Brief로 전환된 경우도 포함한다. |
| `CollectorFailures` | 기본 Snapshot collector가 일부 실패함 | Collector를 정보 공백으로 보고 Alert Brief/Issue의 누락 정보를 우선 조사한다. 단일 collector 실패만으로 장애 원인을 확정하지 않는다. |
| `ProcessingDuration` | 한 event의 처리 시간 | Outcome별 추세를 보고 지연이 반복되면 동시성, EventBridge 재시도, downstream 게시 상태를 운영 절차에 따라 확인한다. |

지표는 조사 도구 자체의 상태를 알리는 용도다. `IncidentsFailed`나 `IncidentsDegraded`에 대한 paging Alarm, 수신 채널, 임계값은 기존 팀 운영 경로와 별도 승인으로 정한다. Investigator Alarm을 자기 EventBridge 입력으로 연결해 재귀 호출하지 않는다.

## 실패 대응

- GitHub 게시가 실패하면 Slack에는 정상 Brief 대신 degraded Slack만 전송될 수 있다. EventBridge retry와 idempotency가 같은 event의 게시 상태를 이어서 처리하므로, 동일 알림을 수동으로 재발행하지 말고 private Issue와 DynamoDB 처리 상태를 승인된 운영 경로에서 확인한다.
- Slack 전송이 실패해도 private Issue가 source of record다. Issue 중복 생성을 피하기 위해 retry가 끝나기 전 수동 재게시나 상태 변경을 하지 않는다.
- Alert Brief가 안전 검증을 통과하지 못하면 `degraded: alert brief unavailable`로 축소된다. 이는 민감 정보 노출을 막기 위한 경계이며 Bundle과 Issue가 안전하게 생성되었다면 조사 자체를 중단했다는 뜻은 아니다.
- 반복 실패나 지연은 `Stage`/`Outcome`과 접근이 허용된 Lambda 로그를 근거로 운영 담당자에게 전달한다. 리소스 변경, 재시작, 롤백, 배포는 이 도구나 이 절차에서 수행하지 않는다.

## 안전 경계

- Investigator는 topology 허용 목록 안에서만 read-only 조사한다. `GetSecretValue`와 Secret 값 조회는 금지되며, Secret·token·webhook·실제 운영 식별자·원문 로그를 Alert Brief, 지표, 티켓, 채팅에 복사하지 않는다.
- Evidence가 부족하거나 collector가 실패하면 `unclassified` 또는 누락 정보로 남긴다. 근거 없는 원인 확정이나 자동 복구는 하지 않는다.
- 이 runbook은 자동 복구, 재시작, 롤백, 배포, Alarm 상태 변경을 지시하거나 실행하지 않는다. 운영 변경은 별도의 승인된 절차와 서비스 소유자 판단이 필요하다.
- 실제 Bundle과 Incident Issue는 private 저장소에만 두며, 공개 문서와 테스트에는 익명화된 예시만 사용한다.
