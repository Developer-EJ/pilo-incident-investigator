# PILO Incident Investigator

AWS 장애 Alarm 이후 PILO의 운영 근거를 자동 수집해 Incident Brief를 만들고, 비공개 GitHub Issue와 Slack을 통해 Codex 후속 조사로 연결하는 PILO 전용 초기 장애 조사 서비스입니다. CloudWatch를 대체하거나 모든 장애의 원인을 자동 확정하는 범용 진단기는 아닙니다.

> **현재 상태: Implementation phase** — 승인된 계획을 기능별 `dev` 대상 PR로 구현하고 있습니다. 전체 구현과 검증이 끝나기 전에는 `main`으로 병합하지 않습니다.

기준 설계는 [`docs/design.md`](docs/design.md), 실행 계획은 [`MVP 런타임·배포`](docs/superpowers/plans/2026-08-01-mvp-runtime-deployment.md)와 [`평가·handoff`](docs/superpowers/plans/2026-08-01-evaluation-handoff.md)에서 확인할 수 있습니다.

## 안전 경계

- 대상은 PILO AWS dev, `ap-northeast-2`, 등록된 ECS 8개 서비스입니다.
- 런타임은 `pilo-topology.yaml` 허용 목록 안의 리소스만 읽습니다.
- Secret 값 조회(`GetSecretValue`), 앱 리소스 변경, 자동 복구·재시작·롤백을 하지 않습니다.
- 실제 Bundle은 private S3, 실제 Issue는 private incident 저장소에만 기록합니다.
- 로컬 검증과 CI는 AWS, GitHub Issue, Slack, Bedrock에 쓰기 요청을 보내지 않습니다.

## 로컬 개발

필수 도구는 Python 3.12와 Terraform `>= 1.10, < 2.0`입니다. `make` 명령을 사용할 환경에서는 다음과 같이 준비합니다.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
make check
make test
make terraform-check
```

PowerShell에서는 먼저 `.\.venv\Scripts\Activate.ps1`로 환경을 활성화합니다. GNU Make가 없다면 같은 검증을 직접 실행할 수 있습니다.

```powershell
python -m ruff check src tests scripts
python -m ruff format --check src tests scripts
python -m mypy src tests scripts
python -m pytest tests/unit tests/integration -q
python scripts/build_lambda.py
terraform -chdir=infra fmt -check -recursive
terraform -chdir=infra init -backend=false -input=false -lockfile=readonly
terraform -chdir=infra validate
terraform -chdir=infra test
python scripts/check_iam_policy.py infra
```

`terraform-check`는 먼저 Lambda artifact를 만든 뒤 format, validate, native test, IAM·소유권 정책 검사를 실행하지만 `plan`이나 `apply`는 실행하지 않습니다.

## Lambda 패키지

개발 의존성을 설치한 Python 3.12 환경에서 다음 명령을 실행합니다.

```bash
python scripts/build_lambda.py
```

결과는 `dist/pilo-incident-investigator.zip`에 생성됩니다. 빌더는 애플리케이션 패키지와 설치된 런타임 import만 포함하고, 정렬된 entry·고정 timestamp·고정 권한을 사용합니다. topology, `.env`, Terraform state, bytecode, OS별 native extension은 포함하지 않습니다. 따라서 Windows에서 만든 artifact에도 Windows용 PyYAML 바이너리가 들어가지 않으며 PyYAML의 순수 Python 구현을 사용합니다.

동일한 소스와 설치된 의존성에서 재실행하면 동일한 SHA-256 artifact가 생성됩니다. 의존성 버전을 바꾼 뒤에는 새 환경에서 검증하고 artifact hash 변경을 의도적으로 검토해야 합니다.

## CI

`.github/workflows/verify.yml`은 `dev` 대상 PR과 `dev` push에서 다음 작업을 수행합니다.

1. Python 정적 검사와 전체 단위·통합 테스트
2. Lambda artifact 빌드
3. Terraform format, validate, native test와 IAM 정책 검사

workflow 권한은 `contents: read`뿐이며 AWS write credential을 요구하지 않습니다. 실제 배포는 CI 검증 경로에 포함하지 않습니다.

## 보호된 dev 배포 준비

실제 배포는 별도 보호 환경의 명시적 승인 후에만 수행합니다. 로컬 또는 PR CI의 성공은 배포 승인이 아닙니다. 배포 전 다음 항목을 값 본문을 출력하지 않는 방식으로 확인합니다.

```powershell
$region = $env:AWS_REGION
if (-not $region) { $region = $env:AWS_DEFAULT_REGION }
if (-not $region) { $region = aws configure get region }
if (-not $region -or $region.Trim() -ne "ap-northeast-2") { throw "AWS region must be ap-northeast-2" }
if (-not $env:PILO_GITHUB_TOKEN_PARAMETER -or -not $env:PILO_SLACK_WEBHOOK_PARAMETER) { throw "SSM parameter names are required" }
if ($env:PILO_GITHUB_TOKEN_PARAMETER -eq $env:PILO_SLACK_WEBHOOK_PARAMETER) { throw "SSM parameters must be distinct" }

aws sts get-caller-identity --query Account --output text --region ap-northeast-2
$githubType = aws ssm describe-parameters --parameter-filters "Key=Name,Option=Equals,Values=$env:PILO_GITHUB_TOKEN_PARAMETER" --query "Parameters[0].Type" --output text --region ap-northeast-2
if ($LASTEXITCODE -ne 0 -or $githubType.Trim() -ne "SecureString") { throw "GitHub token parameter must exist as SecureString" }
$slackType = aws ssm describe-parameters --parameter-filters "Key=Name,Option=Equals,Values=$env:PILO_SLACK_WEBHOOK_PARAMETER" --query "Parameters[0].Type" --output text --region ap-northeast-2
if ($LASTEXITCODE -ne 0 -or $slackType.Trim() -ne "SecureString") { throw "Slack Webhook parameter must exist as SecureString" }
python -m pilo_incident_investigator.topology validate $env:PILO_TOPOLOGY_FILE
aws s3api head-object --bucket $env:PILO_TOPOLOGY_BUCKET --key $env:PILO_TOPOLOGY_KEY --query "{Encryption:ServerSideEncryption,Length:ContentLength}" --region ap-northeast-2
gh repo view $env:PILO_INCIDENT_REPOSITORY --json nameWithOwner,visibility
```

- 두 SSM parameter는 미리 승인된 별개의 SecureString이어야 하며 Terraform으로 값이나 parameter를 만들지 않습니다.
- topology는 공개 저장소 밖의 보호 파일이어야 하며 검증 명령은 본문을 출력하지 않습니다.
- incident 저장소는 private이어야 합니다.
- 실제 식별자와 `*.tfvars`는 커밋하지 않습니다.
- 저장된 Terraform plan을 사람이 검토해 Lambda, EventBridge, private S3, DynamoDB, IAM, 전용 log group 외 리소스 변경이 없음을 확인하기 전에는 apply하지 않습니다.

실제 apply와 합성 Alarm smoke test는 별도의 보호 환경 작업에서 수행합니다.
