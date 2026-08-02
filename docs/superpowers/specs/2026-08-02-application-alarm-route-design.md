# PILO dev 애플리케이션 Alarm 경로 확장 설계

## 1. 배경과 목표

PILO dev에는 ECS 실행 상태, ALB healthy target, SQS DLQ backlog를 관찰하는 애플리케이션 Alarm 8개가 새로 추가되어 있다. 이 Alarm들은 현재 알림 동작을 직접 실행하지 않으며, Incident Investigator의 EventBridge 허용 목록에도 아직 포함되지 않는다.

이번 변경의 목표는 기존 26개 Alarm 경로를 그대로 유지하면서 신규 8개 Alarm을 추가하여, Incident Investigator가 정확히 34개의 명시적 Alarm만 수신하도록 연결하는 것이다. 연결 이후에도 조사 모드는 `snapshot_only`, Lambda 예약 동시성은 2로 유지한다.

이 변경은 Alarm을 새로 만들거나 상태를 바꾸는 작업이 아니다. 이미 존재하는 Alarm이 자연스럽게 `ALARM` 상태로 전환될 때 Incident Investigator의 기존 세로 흐름으로 전달되도록 허용 목록을 확장하는 작업이다.

## 2. 범위

### 포함

- 현재 배포된 보호 topology에 다음 네 서비스의 신규 Alarm 관계를 추가한다.
  - 애플리케이션 서버: ECS running 상태, ALB healthy target 상태
  - 실시간 서버: ECS running 상태, ALB healthy target 상태
  - AI worker: ECS running 상태, AI 작업 DLQ backlog
  - workspace indexer worker: ECS running 상태, indexing DLQ backlog
- EventBridge rule의 정확한 Alarm 리소스 허용 목록을 26개에서 34개로 확장한다.
- 신규 경로를 검증할 익명화된 계약 테스트와 운영 runbook을 추가한다.
- 저장된 전체 Terraform plan을 검토한 뒤 허용된 변경만 적용한다.
- 적용 후 EventBridge, Lambda와 보호 topology의 metadata를 검증하고 실제 Alarm은 수동적으로 관찰한다.

### 제외

- CloudWatch Alarm 생성·수정·삭제 또는 상태 조작
- PILO ECS, ALB, SQS와 기타 애플리케이션 리소스 변경
- `hybrid_agent` 활성화 또는 Agent 조사 범위 변경
- 실제 장애 발생 유도와 운영 부하 주입
- 자동 재시작, 롤백, 배포 또는 복구
- 와일드카드 기반 Alarm 수신과 topology 외 임의 리소스 조회
- 실제 계정 식별자, ARN, 보호 topology 본문·경로 또는 운영 로그의 Git 저장

## 3. 안전 원칙

1. EventBridge는 신규 8개를 포함한 정확한 34개 Alarm ARN만 허용한다. 이름 접두사, 태그 또는 와일드카드로 범위를 넓히지 않는다.
2. 신규 Alarm 경로를 열기 전에 보호 topology를 먼저 갱신하고 검증한다. topology에 없는 Alarm 이벤트가 먼저 Lambda에 도착하는 순서를 허용하지 않는다.
3. 기존 26개 Alarm과 그 topology 관계는 제거하거나 변경하지 않는다.
4. 보호 topology는 로컬 보호 임시 파일에서만 다룬다. 본문을 표준 출력, 애플리케이션 로그, Git, Issue 또는 PR에 기록하지 않는다.
5. Terraform은 저장된 전체 plan을 사용한다. plan에 EventBridge rule의 리소스 집합 확장 외 변경이 나타나면 적용하지 않고 중단한다.
6. 실제 애플리케이션 Alarm에 `SetAlarmState`를 호출하지 않는다. 기존 합성 smoke 경로가 세로 흐름을 검증하고, 신규 경로는 구성과 자연 발생 이벤트를 수동적으로 검증한다.
7. 적용 후 문제가 보여도 자동 rollback하지 않는다. 원인을 확인하고 별도의 저장된 rollback plan과 사용자 승인을 거친다.

## 4. 변경 흐름

### 4.1 저장소 계약 추가

기능 브랜치에서 다음을 추가한다.

- 애플리케이션 Alarm 경로의 정확한 집합 검증
- 기존 26개 보존과 신규 8개 포함 검증
- topology 선행 갱신 조건
- 허용되는 Terraform plan 변경 범위
- 실제 Alarm 상태를 조작하지 않는 적용·검증 runbook

테스트와 문서는 합성 식별자를 사용한다. 실제 ARN, 계정 ID, 버킷 이름, topology object key는 저장소에 넣지 않는다.

### 4.2 보호 topology 갱신

현재 Lambda가 참조하는 보호 topology object를 보호 임시 위치로 내려받고, 본문을 출력하지 않은 채 현재 스키마와 서비스 수를 검증한다. 그 복사본에 네 서비스와 신규 8개 Alarm의 명시적 관계만 추가한다.

업로드 전 검증 조건은 다음과 같다.

- PILO ECS 서비스가 정확히 8개다.
- 기존 26개 Alarm 관계가 모두 보존된다.
- 신규 8개 Alarm이 지정된 네 서비스에 정확히 한 번씩 연결된다.
- topology 허용 목록 밖 리소스가 추가되지 않는다.
- 중복 Alarm ARN과 와일드카드가 없다.

검증된 복사본은 현재 Lambda가 참조하는 동일한 보호 object에 서버 측 암호화와 SHA-256 checksum을 지정하여 업로드한다. 업로드 후에는 본문이 아니라 암호화, checksum과 object metadata만 확인한다. 이 시점에는 EventBridge 허용 목록이 아직 26개이므로 신규 관계는 비활성 상태다.

### 4.3 Terraform plan과 적용

배포 입력은 다음 불변 조건을 가진다.

- Alarm ARN 집합: 기존 26개와 신규 8개를 합친 정확한 34개
- EventBridge route: 활성화
- 조사 모드: `snapshot_only`
- Lambda 예약 동시성: 2

backend와 현재 state를 사용하여 전체 저장 plan을 만든다. 적용 허용 조건은 EventBridge rule의 event pattern 안 `resources` 집합이 26개에서 34개로 늘어나는 변경 하나뿐이다. 다음 중 하나라도 나타나면 즉시 중단한다.

- Lambda 코드, 설정, 권한 또는 동시성 변경
- EventBridge target 또는 Lambda invoke permission 변경
- IAM, S3, DynamoDB, log group 변경
- 리소스 생성 또는 삭제
- 기존 26개 Alarm 제거
- 신규 8개 외 Alarm 추가
- 계획되지 않은 drift 또는 provider 교체

허용 조건을 만족한 동일한 saved plan만 적용한다. 검토 후 새 plan을 다시 만들거나 `-target`으로 예상 밖 변경을 우회하지 않는다.

### 4.4 적용 후 검증

적용 직후 read-only 조회로 다음을 확인한다.

- EventBridge rule이 활성 상태다.
- event pattern이 `aws.cloudwatch`의 `CloudWatch Alarm State Change` 중 `ALARM` 상태만 수신한다.
- 리소스 집합이 정확히 34개이며 기존 26개와 신규 8개가 모두 포함된다.
- EventBridge target은 기존 Investigator Lambda 하나이며 입력 변환이 추가되지 않았다.
- Lambda 조사 모드는 `snapshot_only`다.
- Lambda 예약 동시성은 2다.
- 보호 topology object에 서버 측 암호화와 SHA-256 checksum metadata가 있다.
- Terraform 후속 plan에 변경이 없다.

실제 Alarm은 상태를 조작하지 않고 자연 발생 이벤트를 관찰한다. 신규 Alarm에서 이벤트가 발생하면 기존 Incident Bundle, 비공개 GitHub Issue와 Slack 전달 경로가 정상 동작하는지 Incident ID로 확인한다. 자연 발생 이벤트가 없다는 사실은 구성 실패로 간주하지 않는다.

## 5. 실패 처리와 rollback

- topology 다운로드, 파싱, 스키마 또는 관계 검증이 실패하면 업로드와 Terraform 작업을 수행하지 않는다.
- topology 업로드나 metadata 검증이 실패하면 EventBridge 허용 목록을 확장하지 않는다.
- Terraform plan이 허용 범위를 벗어나면 적용하지 않고 사용자에게 실제 diff를 보고한다.
- saved plan 적용이 실패하면 추가 변경을 시도하지 않고 Terraform state와 AWS read-only 상태를 진단한다.
- 적용 후 구성 검증이 실패하면 실제 Alarm을 조작하거나 자동 rollback하지 않는다.
- rollback이 필요하면 EventBridge 허용 목록을 검증된 기존 26개로 되돌리는 별도 saved plan을 만든다. 그 plan이 EventBridge rule의 리소스 집합 축소만 포함하는지 검토하고 사용자 승인을 받은 뒤 적용한다.
- topology rollback이 함께 필요하면 이전 object의 검증된 복구 가능성을 먼저 확인한다. 복구본이 확인되지 않은 상태에서 topology를 덮어쓰지 않는다.

## 6. 테스트와 완료 기준

저장소 검증은 실제 AWS, Slack 또는 GitHub Issue를 변경하지 않고 다음 계약을 확인한다.

- 정확한 Alarm 집합 비교가 누락, 초과와 중복을 실패로 처리한다.
- 기존 경로가 하나라도 빠지면 실패한다.
- 신규 경로가 지정된 서비스와 일치하지 않으면 실패한다.
- 와일드카드와 익명화되지 않은 운영 식별자가 fixture에 들어가면 실패한다.
- 운영 runbook이 topology 선행, saved full plan 검토, 비조작 검증과 수동 rollback 승인을 요구한다.

완료 조건은 다음과 같다.

1. 기능 변경이 `dev` 대상 PR로 검토되고 모든 검증이 통과한다.
2. PR이 `dev`에 병합된다. `main` 대상 PR은 만들지 않는다.
3. 보호 topology가 신규 8개 관계를 포함하고 metadata 검증을 통과한다.
4. 승인 범위와 정확히 일치하는 saved plan만 적용된다.
5. 적용 후 EventBridge 34개 허용 목록, 기존 단일 Lambda target, `snapshot_only`, 예약 동시성 2가 확인된다.
6. 실제 Alarm, PILO 서비스와 외부 연계에 변경을 가하지 않는다.

## 7. 작업 단위

이 변경은 하나의 작은 기능 PR로 처리한다. 저장소 변경은 계약 검증과 runbook에 한정하고, 보호 topology 및 Terraform 적용은 PR 병합 후 같은 승인 작업에서 수행한다. 저장소 검증이나 AWS 사전 조건에서 예상 밖 문제가 발견되면 PR 또는 배포 단계를 억지로 쪼개 진행하지 않고 중단하여 보고한다.
