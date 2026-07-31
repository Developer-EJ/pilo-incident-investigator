# PILO Incident Investigator 설계

- 상태: 사용자 승인 완료, 구현 계획 작성 중
- 문서 기준일: 2026-08-01
- 저장소: `pilo-incident-investigator`

## 1. 개요

PILO Incident Investigator는 AWS 장애 Alarm이 발생하면 PILO의 ECS, CloudWatch, RDS, Secrets Manager metadata, SQS, ALB, GitHub 배포 이력을 자동 수집하고, 근거 기반 Incident Brief를 만들어 Slack으로 전달하는 **PILO 전용 초기 장애 조사 서비스**다.

목적은 CloudWatch를 대체하거나 모든 장애 원인을 자동 진단하는 것이 아니다. Alarm 이후 운영자가 여러 콘솔에서 반복하던 초기 컨텍스트 수집을 자동화하고, 비공개 GitHub Issue URL 하나로 Codex의 후속 조사와 사람이 승인하는 복구 작업을 빠르게 시작하게 하는 것이 목적이다.

## 2. 목표와 비목표

### 목표

- Alarm과 직접 관련된 기본 운영 근거를 항상 같은 수집 규칙으로 확보한다.
- 기본 Snapshot을 바탕으로 제한된 추가 조회만 수행해 조사에 필요한 컨텍스트를 보강한다.
- 확인된 사실, 조사 방향, 누락 정보를 명확히 구분하고 모든 판단을 Evidence ID에 연결한다.
- 일부 조회나 LLM이 실패해도 확보한 근거를 잃지 않고 유용한 최소 Incident Brief를 남긴다.
- 실제 증거는 private S3에, 운영자가 보는 사건 기록은 private GitHub Issue에 보관하고 Slack은 진입점 역할만 한다.
- Incident Brief를 받은 Codex가 raw Alarm만 받았을 때보다 더 적은 추가 조회로 안전하고 올바른 첫 조사 방향을 선택하게 한다.

### 비목표

- CloudWatch Alarm, APM 또는 관측 플랫폼 대체
- 모든 AWS 계정·환경·리전 또는 모든 장애 유형을 지원하는 범용 조사 플랫폼
- 장애 원인의 무조건적인 자동 확정
- PILO 애플리케이션 및 조사 대상 AWS 리소스 변경, 자동 재시작, 자동 롤백, 자동 복구 또는 배포
- Secret 값 조회 또는 실제 운영 데이터의 공개 저장
- PILO 애플리케이션 인프라의 생성·소유·수정

## 3. 적용 범위와 소유권

운영 범위는 PILO AWS **dev 환경**, **ap-northeast-2**, **PILO ECS 8개 서비스**로 한정한다. 런타임은 `pilo-topology.yaml`에 등록된 리소스만 조회할 수 있다. 공개 저장소에는 schema와 익명화 예시만 두며, 실제 계정·리소스 식별자를 포함한 운영 topology는 배포 환경에서 보호된 구성으로 주입한다.

이 프로젝트는 PILO 애플리케이션 저장소와 분리하며 다음 항목을 독립적으로 소유한다.

- 별도 저장소와 CI/CD
- 별도 Terraform state
- 서비스 전용 IAM 역할과 정책
- EventBridge 연동, Lambda, private S3, DynamoDB, 전용 CloudWatch log group

기존 PILO ECS, ALB, RDS, SQS, CloudWatch 및 관련 애플리케이션 리소스는 **조회 대상**이며 이 프로젝트의 Terraform 소유 대상이 아니다. GitHub 배포 이력과 변경 파일도 read-only로 조회한다. Slack Incoming Webhook과 private incident 저장소는 결과 게시 대상이지 애플리케이션 인프라 소유 범위가 아니다.

private GitHub 게시 token과 Slack Incoming Webhook URL은 이 서비스만 읽을 수 있는 SSM SecureString으로 보관한다. 프로젝트 배포 운영자가 정확히 두 값을 운영 환경에 주입하며, 실제 값은 공개 저장소와 Terraform state에 넣지 않는다. Terraform은 값이나 parameter resource를 소유하지 않고, 입력받은 정확한 두 parameter ARN에 대한 `ssm:GetParameter` 권한만 Lambda 역할에 부여한다.

PILO 저장소에 잘못 커밋된 이전 설계 문서의 제거는 이 설계를 새 저장소에 안전하게 커밋하고 사용자가 검토한 뒤 수행할 별도 작업이다. 이 저장소의 설계 작업에는 그 삭제가 포함되지 않는다.

### `pilo-topology.yaml` 계약

운영 topology는 Alarm과 PILO 서비스 사이의 관계를 명시하고, 각 서비스에 허용된 ECS cluster/service, CloudWatch log group, ALB target group, 관련 RDS·SQS, GitHub 저장소 식별자를 연결한다. 이 파일은 PILO ECS 8개 서비스와 조사에 허용된 리소스의 폐쇄형 허용 목록이다.

런타임은 시작 시 topology의 schema와 중복·누락·리전·환경을 검증한다. Alarm을 topology에 매핑할 수 없거나 요청 대상이 허용 목록에 없으면 임의 탐색으로 보완하지 않는다. 대신 매핑 실패를 누락 정보로 남기고 가능한 고정 범위 Snapshot만 수집한 뒤 `unclassified`로 전달한다. 공개 저장소에는 같은 schema의 익명화 예시만 두고 실제 운영 파일은 보호된 배포 구성으로 관리한다.

## 4. 전체 아키텍처와 데이터 흐름

정상 처리 흐름은 다음과 같다.

```text
CloudWatch Alarm
  -> EventBridge
  -> Lambda
  -> 결정적 기본 Snapshot
  -> 제한된 Agent 추가 조사
  -> redaction
  -> private S3 Incident Bundle
  -> private GitHub Issue
  -> Slack Incoming Webhook
  -> Codex handoff
```

1. EventBridge가 CloudWatch Alarm 이벤트를 Lambda로 전달한다.
2. Lambda가 Incident ID를 정하고 DynamoDB에서 이벤트 처리 상태를 확인하거나 선점한다.
3. 결정적 Collector들이 정의된 기본 Snapshot을 수집한다. Collector 일부가 실패해도 성공한 결과와 실패 정보를 함께 유지한다.
4. AWS Bedrock 기반의 제한된 Agent가 기본 Snapshot을 보고 허용된 추가 read-only Tool 중 필요한 것만 선택한다. Agent를 호출할 수 없거나 제한 시간 안에 끝나지 않으면 기본 Snapshot만 사용한다. Bedrock model 또는 inference profile ID는 배포 입력으로 받고 IAM으로 호출 대상을 제한한다.
5. 수집 결과와 Agent 산출물을 redaction하여 민감 정보가 영속 저장소나 게시 채널로 나가지 않게 한다.
6. redacted Incident Bundle을 private S3에 먼저 저장한다. 이 저장이 성공해야 외부 게시를 진행한다.
7. Bundle을 바탕으로 private incident 저장소에 GitHub Issue를 생성하거나 기존 Incident ID의 게시를 재개한다.
8. 정상 시 Slack에는 짧은 요약과 private Issue 링크만 보낸다.
9. 운영자 또는 Codex는 Issue를 기준으로 추가 조사와 사람이 승인하는 복구를 이어간다.

## 5. Incident 식별과 멱등성

EventBridge event ID를 원본 멱등성 키로 사용하고, Incident ID는 이 event ID에서 결정적으로 파생한다. 같은 EventBridge event의 재전달은 같은 Incident ID로 수렴하며, 서로 다른 Alarm 전이는 별도 사건으로 취급한다.

DynamoDB는 두 종류의 상태를 관리한다.

- **Event 처리 상태**: 동일 EventBridge event를 중복 수집하지 않도록 선점, 진행, 완료 또는 재시도 가능 실패를 기록한다.
- **Publisher checkpoint**: S3 저장, GitHub Issue 게시, Slack 전송 시도 등 단계별 완료 지점을 기록해 재시도 시 이미 완료된 부작용을 가능한 한 반복하지 않는다.

Incident ID는 모든 Bundle, Issue, Slack 메시지 및 로그에서 동일한 상관관계 키로 사용한다. GitHub Issue 생성은 Incident ID를 기준으로 기존 게시 여부를 확인한다. Slack Incoming Webhook의 exactly-once 전달은 보장하지 않으므로 중복 메시지가 발생할 수 있으며, 수신자는 Incident ID로 같은 사건임을 식별한다.

## 6. 결정적 기본 Snapshot

기본 Snapshot은 Agent의 판단과 무관하게 Alarm마다 시도하는 고정된 수집 집합이다. 여기서 결정적이라는 말은 운영 상태 값이 매번 같다는 뜻이 아니라, 같은 입력과 topology에 대해 **어떤 수집기를 실행하고 어떤 필드를 기록할지 Agent가 바꾸지 않는다**는 뜻이다.

필수 수집 대상은 다음과 같다.

1. Alarm 대상 ECS 서비스 상태와 관련 중지 Task
2. Alarm 및 중지 Task와 연관된 CloudWatch 로그
3. 해당 ALB target health
4. PILO ECS 8개 서비스 전체의 running 상태
5. 최근 GitHub 배포 이력
6. RDS 기본 상태

각 Collector는 조회 구간, 대상, 성공 여부, 수집 시각, 원본 출처, 정규화 결과를 남긴다. Collector 실패는 전체 실패로 숨기지 않고 별도 누락 정보로 기록한다. 수집 범위는 사건 전후의 제한된 시간 창과 topology 허용 목록으로 제한하며, 무제한 로그 덤프를 만들지 않는다.

## 7. 제한된 Agent 추가 조사

Agent는 기본 Snapshot을 대체하지 않고, Snapshot에 드러난 단서에 따라 필요한 추가 증거만 보강한다.

### 호출 제한

- 최대 2 round
- round당 최대 3개 Tool
- 전체 최대 6개 Tool 호출
- 모든 Tool 선택에 조사 이유 기록
- 동일 대상·동일 조건의 중복 조회 금지
- `pilo-topology.yaml`에 등록되지 않은 리소스 조회 금지
- read-only Tool만 허용

Agent가 선택할 수 있는 추가 Tool은 다음 다섯 범주로 제한한다.

- 특정 PILO 서비스 로그 검색
- RDS 이벤트 조회
- Secrets Manager Secret 회전 **metadata** 조회
- SQS 상태 조회
- GitHub 변경 파일 조회

Tool registry는 호출 전에 리소스, 작업 종류, 시간 범위를 검증한다. `GetSecretValue`는 registry와 IAM 양쪽에서 금지한다. Agent는 AWS 변경 API를 호출할 수 없으며, 임의 ARN·서비스·저장소를 새로 발견해 조회 범위를 넓힐 수 없다.

Agent timeout, 모델 실패, 잘못된 Tool 요청 또는 호출 예산 소진 시 추가 조사를 중단하고 이미 확보한 기본 Snapshot으로 결과를 만든다. 여섯 대표 장애 유형은 Agent나 런타임의 하드코딩된 분류 목록이 아니며, unknown 또는 복합 장애와 근거 부족 사례는 `unclassified`로 전달한다.

## 8. Evidence와 LLM 출력 계약

수집된 각 관찰에는 Bundle 안에서 고유하고 안정적인 Evidence ID를 부여한다. Issue에 포함되는 모든 사실과 조사 판단은 하나 이상의 Evidence ID를 인용해야 한다. 인용할 근거가 없으면 사실이나 원인으로 표현하지 않는다.

Incident Brief는 다음 영역을 분리한다.

- **확인된 사실**: 수집 결과로 직접 확인할 수 있는 상태와 변화. Evidence ID 필수.
- **조사 방향**: 가능한 다음 확인 지점과 그 이유. 판단의 근거가 된 Evidence ID 필수이며 확정 원인처럼 표현하지 않는다.
- **누락 정보**: 실패한 Collector, 접근 불가, 시간 범위 밖, timeout 등 판단에 필요한데 확보하지 못한 정보.
- **분류 상태**: 충분한 근거가 있을 때의 제한적 분류 또는 `unclassified`.

LLM은 증거 원문을 바꾸지 않으며 요약과 조사 방향만 생성한다. unsupported claim은 eval 실패로 간주한다. LLM 실패 시 템플릿 기반 기본 Snapshot Issue와 Slack 전달 경로를 유지한다.

## 9. Incident Bundle, redaction, 보관

Incident Bundle은 최소한 다음 논리 구조를 가진다.

- Incident ID, Alarm 식별 정보, 수집 시간 범위와 처리 상태
- 기본 Snapshot과 Collector별 성공·실패 결과
- 추가 Tool 선택 이유, 호출 기록, 반환 Evidence
- Evidence ID가 부여된 정규화 증거
- 확인된 사실, 조사 방향, 누락 정보, 분류 상태
- redaction 적용 내역과 publisher checkpoint 참조

redaction은 S3 저장과 GitHub·Slack 게시 전에 실행한다. 자격 증명, 토큰, Secret 값으로 보이는 문자열, 불필요한 개인·계정 식별 정보 및 공개 불가 운영 값을 제거하거나 일관된 익명 식별자로 치환한다. Secret 회전 조사는 버전 값이나 Secret 본문이 아닌 회전 상태, 변경 시각 같은 metadata만 사용한다.

redacted 실제 Bundle은 private S3에서 **7일** 보관한다. 버킷은 public access를 차단하고 서비스 전용 최소 권한만 허용한다. 운영자가 보는 사건의 기록 원본은 private GitHub Issue이며, S3 Bundle은 Issue가 인용하는 상세 증거 묶음이다. 공개 저장소에는 합성 또는 충분히 익명화된 fixture와 예시만 저장한다.

## 10. 게시 계약과 오류 처리

정상 Slack 메시지는 짧은 사건 요약과 private GitHub Issue 링크만 포함한다. 상세 증거와 조사 이력은 Slack에 복제하지 않고 Issue에서 확인한다.

오류별 동작은 다음과 같다.

| 오류 | 동작 |
| --- | --- |
| 일부 Collector 실패 | 성공한 결과로 부분 Bundle을 만들고 실패를 누락 정보에 기록한다. |
| Agent timeout 또는 모델 실패 | 기본 Snapshot으로 Incident Brief를 만들고 게시를 계속한다. |
| redaction 실패 | 민감 정보 유출 가능성이 있으므로 Bundle을 게시하지 않고 안전하게 실패 처리 후 재시도한다. |
| S3 저장 실패 | GitHub와 Slack으로 발송하지 않고 checkpoint에서 재시도한다. |
| GitHub Issue 게시 실패 | S3 Bundle을 유지하고 Slack에는 Incident ID와 `degraded: issue publication failed` 상태만 알린다. Brief나 상세 증거는 보내지 않는다. |
| Slack 전송 실패 | GitHub Issue를 기록 원본으로 유지하고 checkpoint에 실패를 기록해 재시도한다. |
| Slack 중복 전송 | exactly-once를 주장하지 않으며 Incident ID로 중복을 식별한다. |

GitHub 실패 시의 degraded Slack 알림은 정상 Slack 형식의 예외다. private Issue URL이 아직 없으므로 링크나 상세 내용을 대신 노출하지 않고, 운영자가 게시 장애를 인지할 수 있는 최소 상태만 제공한다.

## 11. 보안과 권한 경계

### 절대 금지

- Secrets Manager `GetSecretValue`와 PILO 애플리케이션 Secret 값 조회
- PILO 애플리케이션 및 조사 대상 AWS 리소스를 변경하는 API. 서비스 소유 private S3의 Bundle 저장, DynamoDB 상태 기록, 전용 로그 기록은 여기에 해당하지 않으며 별도의 최소 쓰기 권한으로 제한한다.
- 자동 재시작, 롤백, 복구 또는 배포
- topology 허용 목록 밖 임의 리소스 조회
- 실제 장애 로그나 Secret을 공개 저장소에 저장
- 실제 Bundle의 공개 S3 저장 또는 실제 Incident의 공개 Issue 생성

IAM은 조회 대상별 최소 read-only 권한과 서비스 소유 자원에 대한 쓰기 권한을 분리한다. Lambda는 필요한 PILO 상태 조회, 전용 private S3 쓰기, DynamoDB checkpoint, 전용 로그 기록, 승인된 게시 연동 외 권한을 갖지 않는다. redaction 이전 데이터는 처리 중 메모리와 서비스 신뢰 경계를 벗어나 영속화하지 않는다. 로그에도 원문 증거 전체나 민감 값을 남기지 않는다.

GitHub·Slack 연동 adapter만 서비스 전용 GitHub token과 Slack Webhook URL을 SSM `GetParameter`의 복호화 옵션으로 읽을 수 있다. GitHub adapter는 배포·변경 파일 read와 private Issue write에 token을 사용하고, Slack adapter는 Webhook 전송에만 URL을 사용한다. 두 자격 증명은 조사 Evidence나 Agent 입력에 노출하지 않고 해당 adapter 메모리 안에서 요청을 만드는 데만 사용한다. SSM parameter 이름·ARN은 비밀이 아니지만 값은 로그, 오류, Bundle, Issue, Slack, 테스트 fixture, Terraform plan/state에 포함하지 않는다. Agent는 AWS Bedrock을 IAM 인증으로 호출하므로 별도 모델 API key를 사용하지 않는다.

## 12. 배포와 운영 형태

Terraform은 다음 서비스 소유 자원만 관리한다.

- Lambda
- EventBridge 연동
- private S3와 7일 lifecycle
- DynamoDB 상태·checkpoint 테이블
- 최소 권한 IAM
- 전용 CloudWatch log group

PILO의 ECS, ALB, RDS, SQS 등 애플리케이션 자원은 data source 또는 입력 식별자로만 참조하고 생성·변경하지 않는다. SSM SecureString의 실제 값과 parameter resource는 Terraform state에 넣지 않으며, Terraform에는 정확한 두 parameter ARN만 입력한다. 서비스는 Alarm 시 실행되는 Lambda 기반이며 Docker와 상시 서버를 사용하지 않는다. 이 저장소는 PILO와 별도의 Terraform state, IAM, CI/CD를 유지한다.

## 13. 평가 설계

### Fixture 구성

대표 장애 6종은 다음과 같다.

1. RDS Secret rotation 이후 인증 실패
2. ECS OOM
3. ALB health check 실패
4. 배포 regression
5. SQS backlog
6. 외부 API rate limit

각 장애는 `complete`, `noisy`, `partial` 세 변형으로 구성해 18개 fixture를 만든다. 여기에 unknown·복합 장애 fixture 3개를 더해 총 **21개**를 사용한다. fixture는 실제 PILO 장애를 공개하지 않도록 합성하거나 충분히 익명화한다. 특히 실제 RDS 장애에서 파생한 fixture는 식별자, 값, 시간, 로그 문구를 안전하게 변형한다.

### 비교 실험

동일 fixture에 대해 다음 두 경로를 비교한다.

- `snapshot_only`: 결정적 기본 Snapshot만 사용
- `hybrid_agent`: 기본 Snapshot 이후 제한된 Agent 추가 조사 사용

측정 항목은 다음과 같다.

- 필수 Evidence recall
- 올바른 조사 방향 선택
- 불필요 Tool 호출 비율
- unsupported claim 수
- 적절한 `unclassified` 판단
- latency, token, cost

Hybrid가 Snapshot-only보다 의미 있게 개선되지 않거나 안전성·비용이 악화되면 운영 기본 경로를 `snapshot_only`로 되돌린다. 평가 결과는 6개 장애 이름을 런타임 분기문으로 구현하는 근거로 사용하지 않는다.

### Codex handoff A/B

동일 사건에 대해 raw Alarm만 받은 Agent와 Incident Brief를 받은 Agent를 비교한다.

- 후속 추가 Tool 호출 수
- 올바른 첫 조사 방향 선택률
- 사용자에게 요구한 추가 설명 수
- 금지 작업 제안, unsupported claim 등 안전성

Incident Brief의 가치는 예쁜 요약이 아니라 후속 조사량을 줄이면서 첫 방향과 안전성을 개선하는지로 판단한다.

## 14. 구현 우선순위

첫 주말 구현은 다음 순서에 집중한다.

1. 실제 PILO 세로 흐름: EventBridge -> Lambda -> S3 -> private Issue -> Slack
2. redaction
3. 실제 RDS 장애에서 안전하게 익명화한 fixture
4. unknown fixture
5. `snapshot_only`와 `hybrid_agent` 비교
6. 처음부터 실행 가능한 README

범용 플랫폼화, 추가 장애 유형 확대, 자동 복구, UI, Docker 기반 상시 서비스는 이 우선순위와 초기 범위에 포함하지 않는다.

## 15. 설계 수용 기준

이 문서는 2026-08-01에 사용자 승인을 받았다. 이후 구현은 최소한 다음 조건을 증명해야 한다.

- 허용 목록 밖 조회와 모든 변경 API가 코드 및 IAM 양쪽에서 차단된다.
- `GetSecretValue`를 호출하지 않고 실제 Secret 값이 Bundle·Issue·Slack·로그에 남지 않는다.
- 기본 Snapshot은 Agent나 모델 실패와 무관하게 생성 가능하다.
- Tool 호출 예산, 선택 이유, 중복 금지, topology 제한이 검증된다.
- S3 선저장과 publisher checkpoint를 통해 재시도 순서가 유지된다.
- 부분 실패와 게시 실패가 정의된 degraded 동작을 따른다.
- 21개 익명화 fixture로 snapshot/hybrid 및 handoff A/B 지표를 재현할 수 있다.
- 공개 저장소에는 실제 장애 로그, Secret, 자격 증명, 실제 운영 topology가 없다.

구현 계획이 별도 사용자 검토를 통과하기 전에는 코드, Terraform, CI/CD 또는 dependency scaffold를 만들지 않는다.
