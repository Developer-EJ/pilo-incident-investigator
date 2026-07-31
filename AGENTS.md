# AGENTS.md

## 목적

이 저장소는 **PILO Incident Investigator**를 위한 독립 저장소다. 이 서비스는 PILO AWS dev 환경에서 CloudWatch Alarm이 발생한 뒤 사람이 여러 콘솔에서 수행하던 초기 컨텍스트 수집을 자동화하고, 근거 기반 Incident Brief와 비공개 GitHub Issue URL을 만들어 Codex의 후속 조사와 복구를 빠르게 시작하도록 돕는다.

CloudWatch를 대체하거나 모든 장애의 원인을 진단하는 범용 플랫폼이 아니다. 지원하지 않거나 근거가 부족한 장애와 복합 장애는 억지로 분류하지 않고 `unclassified`로 전달한다.

## 현재 단계

- 현재는 **Planning phase**다. 설계는 2026-08-01에 사용자 승인을 받았다.
- 사용자 구현 계획 승인 전에는 애플리케이션 코드, Terraform 리소스, CI workflow, dependency scaffold를 추가하지 않는다.
- 설계의 기준 문서는 `docs/design.md`다.

## 보안 및 안전 금지사항

다음 항목은 어떤 구현에서도 절대 허용하지 않는다.

- AWS Secrets Manager `GetSecretValue` 호출 또는 PILO 애플리케이션 Secret 값 수집·출력·저장
- PILO 애플리케이션 및 조사 대상 AWS 리소스를 생성·변경·삭제하는 런타임 API 호출. 단, 서비스가 소유하는 private S3에 Bundle을 쓰고 DynamoDB에 처리 상태를 기록하며 전용 로그를 남기는 동작은 설계된 저장 책임이다.
- 자동 재시작, 롤백, 배포, 복구 또는 기타 운영 변경
- `pilo-topology.yaml`의 운영 허용 목록 밖 리소스 조회
- 실제 장애 로그, 계정 식별자, Secret, 토큰, 자격 증명 또는 민감 운영 데이터를 공개 저장소의 fixture·문서·테스트 결과에 저장
- 근거 없는 원인 확정, Evidence ID 없는 LLM 판단, 근거가 부족한 장애의 강제 분류
- Incident Bundle 또는 실제 Incident Issue의 공개 게시

런타임 권한은 PILO 조회에 필요한 최소 read-only 권한과 이 서비스가 소유하는 private S3·DynamoDB·로그 기록 및 게시 연동에 필요한 최소 쓰기 권한으로 분리한다. PILO 애플리케이션 리소스는 관찰 대상일 뿐 이 저장소의 Terraform 소유 대상이 아니다.

GitHub 게시 token과 Slack Incoming Webhook URL은 서비스 전용 SSM SecureString으로만 제공한다. 두 값은 조사 Evidence가 아니며 Bundle·Issue·Slack 본문·애플리케이션 로그·Git·Terraform state에 기록하지 않는다. Agent 모델은 AWS Bedrock을 사용하고 IAM으로 호출을 제한한다.

## 구현 범위

구현이 승인된 뒤에도 다음 경계를 지킨다.

- 대상은 PILO AWS **dev**, 리전 **ap-northeast-2**, PILO ECS **8개 서비스**다.
- 처리 흐름은 `CloudWatch Alarm -> EventBridge -> Lambda -> 결정적 기본 Snapshot -> 제한된 Agent 추가 조사 -> redaction -> private S3 Incident Bundle -> private GitHub Issue -> Slack Incoming Webhook -> Codex handoff`다.
- 기본 Snapshot 수집기는 Alarm 대상 ECS 상태와 중지 Task, 관련 로그, ALB target health, PILO ECS 8개 서비스의 running 상태, 최근 GitHub 배포, RDS 기본 상태를 다룬다.
- Agent는 최대 2 round, round당 최대 3개, 총 최대 6개의 추가 read-only Tool만 호출할 수 있다. 각 선택에는 이유가 필요하고 중복 조회는 금지한다.
- 추가 Tool 범위는 특정 PILO 서비스 로그 검색, RDS 이벤트, Secret 회전 metadata, SQS 상태, GitHub 변경 파일이다.
- 실제 Bundle은 private S3에 7일 보관하고, 실제 Incident Issue는 private incident 저장소에만 생성한다.
- 배포 구성은 이 저장소의 별도 Terraform state, IAM, CI/CD를 사용한다. Docker와 상시 서버는 사용하지 않는다.
- 6개 대표 장애는 하드코딩할 런타임 분류 목록이 아니라 eval 회귀 사례다.

## 문서 및 데이터 규칙

- 문서와 사용자 대상 설명은 한국어를 기본으로 한다.
- 공개 저장소에는 합성 또는 익명화 fixture와 예시만 둔다.
- LLM 출력은 `확인된 사실`, `조사 방향`, `누락 정보`를 분리하고 모든 판단에 Evidence ID를 인용한다.
- Collector 일부 실패는 숨기지 말고 누락 정보와 실패 상태로 보존한다.
- 실제 리소스 식별자나 민감한 topology는 커밋하지 않는다. 공개 저장소에는 익명화된 topology 예시만 둘 수 있다.

## 테스트·검증 명령의 예정 계약

아래 명령은 **구현 완료 시 제공할 계약**이다. 현재 저장소에는 실행 파일, Makefile, 테스트 또는 Terraform 구성이 없으므로 **지금 실행 가능한 명령이 아니다**.

- `make check`: 포맷, 정적 분석, 문서 및 보안 규칙 검사를 실행한다.
- `make test`: 단위·통합 테스트를 실행하며 기본적으로 실제 AWS, Slack, GitHub를 변경하지 않는다.
- `make eval`: 익명화된 21개 fixture로 `snapshot_only`와 `hybrid_agent`를 비교한다.
- `make terraform-check`: Terraform 포맷과 정적 검증을 실행하되 apply는 수행하지 않는다.
- `make verify`: 위 검증을 한 번에 실행하는 최종 로컬/CI 진입점이다.

구현 시 이 계약을 실제 명령으로 제공하거나, 사용자 승인을 받아 이 문서와 함께 명시적으로 변경해야 한다. 외부 연동 테스트는 별도의 명시적 opt-in과 격리된 테스트 대상을 요구하며 기본 검증 경로에 포함하지 않는다.
