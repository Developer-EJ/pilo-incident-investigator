# 보호된 dev 합성 Alarm 스모크 테스트

## 목적과 범위

이 절차는 이미 승인·배포된 PILO Incident Investigator의 **보호된 dev vertical slice**를 한 번 확인하기 위한 운영 runbook이다. 이 저장소의 로컬 검증이나 PR CI를 대체하지 않으며, 별도 보호 환경 승인 없이는 시작하지 않는다. 실행 결과, 실제 값·출력·Incident Bundle·Issue 본문·Slack payload·topology 본문·리소스 식별자를 Git이나 이 문서에 남기지 않는다.

CloudWatch가 생성한 실제 상태 변경만 EventBridge rule을 검증할 수 있다. 고객이 `aws.`로 시작하는 source의 EventBridge event를 `PutEvents`로 넣을 수 없으므로, `aws events put-events`와 `dev-smoke-entry.json`은 live 실행에 사용하지 않는다. fixture는 handler가 받는 익명화된 오프라인 EventBridge envelope 계약이다.

대상은 별도 소유·승인된 전용 synthetic **metric** alarm 하나뿐이다. PILO 애플리케이션 Alarm, composite alarm, ECS·ALB·RDS·SQS·Secret과 그 외 애플리케이션 리소스는 변경하거나 시험 대상으로 사용하지 않는다.

## 1. 변경 없는 사전 점검

보호 환경 작업자는 명시적 승인을 기록하고, 아래 환경 변수 이름만 안전한 실행 환경에 설정한다. 값·ARN·topology 본문을 터미널 기록, 티켓, Git 또는 채팅에 복사하지 않는다.

```powershell
$region = $env:AWS_REGION
if (-not $region) { $region = $env:AWS_DEFAULT_REGION }
if (-not $region) { $region = aws configure get region }
if (-not $region -or $region.Trim() -ne "ap-northeast-2") { throw "AWS region must be ap-northeast-2" }
if (-not $env:PILO_SYNTHETIC_ALARM_NAME -or -not $env:PILO_SYNTHETIC_ALARM_ARN) { throw "Synthetic alarm name and ARN are required" }
if (-not $env:PILO_GITHUB_TOKEN_PARAMETER -or -not $env:PILO_SLACK_WEBHOOK_PARAMETER) { throw "SSM parameter names are required" }
if ($env:PILO_GITHUB_TOKEN_PARAMETER -eq $env:PILO_SLACK_WEBHOOK_PARAMETER) { throw "SSM parameters must be distinct" }
if (-not $env:PILO_TOPOLOGY_BUCKET -or -not $env:PILO_TOPOLOGY_KEY) { throw "Protected topology location is required" }

aws sts get-caller-identity --region ap-northeast-2

$githubType = aws ssm describe-parameters --parameter-filters "Key=Name,Option=Equals,Values=$env:PILO_GITHUB_TOKEN_PARAMETER" --query "Parameters[0].Type" --output text --region ap-northeast-2
if ($LASTEXITCODE -ne 0 -or $githubType.Trim() -ne "SecureString") { throw "GitHub token parameter must exist as SecureString" }
$slackType = aws ssm describe-parameters --parameter-filters "Key=Name,Option=Equals,Values=$env:PILO_SLACK_WEBHOOK_PARAMETER" --query "Parameters[0].Type" --output text --region ap-northeast-2
if ($LASTEXITCODE -ne 0 -or $slackType.Trim() -ne "SecureString") { throw "Slack webhook parameter must exist as SecureString" }

aws s3api head-object --bucket $env:PILO_TOPOLOGY_BUCKET --key $env:PILO_TOPOLOGY_KEY --query "{Encryption:ServerSideEncryption,Length:ContentLength}" --region ap-northeast-2
```

SSM은 `describe-parameters`만 사용한다. `GetParameter --with-decryption`, `GetSecretValue` 또는 webhook/token 값 출력은 금지한다. protected topology는 Terraform의 기존 `topology_bucket_arn` 및 `topology_object_key`가 가리키는 object이며, 위 `head-object`는 metadata만 확인한다. topology를 Bundle bucket에 업로드·복사하거나 본문을 읽지 않는다.

승인된 보호 입력을 다룰 권한이 있는 작업자는 값이나 ARN을 공개하지 않는 방식으로 다음을 확인하고, 하나라도 불일치하면 중단한다.

- 전용 synthetic alarm ARN이 Terraform `alarm_arns`에 포함되고, 보호된 topology allowlist에도 포함되어 있다.
- 그 alarm은 PILO 애플리케이션 Alarm이 아닌 전용 synthetic **metric** alarm이다. composite alarm은 허용하지 않는다.
- 현재 상태는 `OK`이며, `ActionsEnabled`는 `false`이고 `AlarmActions`, `OKActions`, `InsufficientDataActions`가 모두 빈 배열이다.

다음 확인은 alarm의 현재 상태와 action 구성을 검사한다. 출력은 보호된 작업 기록에서만 검토하고 커밋하지 않는다.

```powershell
$alarmResponse = aws cloudwatch describe-alarms --alarm-names $env:PILO_SYNTHETIC_ALARM_NAME --region ap-northeast-2 --output json | ConvertFrom-Json
if ($alarmResponse.MetricAlarms.Count -ne 1 -or $alarmResponse.CompositeAlarms.Count -ne 0) { throw "Exactly one dedicated metric alarm is required; composite alarms are forbidden" }
$alarm = $alarmResponse.MetricAlarms[0]
if ($alarm.AlarmArn -ne $env:PILO_SYNTHETIC_ALARM_ARN) { throw "Synthetic alarm ARN does not match the approved target" }
if ($alarm.StateValue -ne "OK") { throw "Synthetic alarm must start in OK" }
if ($alarm.ActionsEnabled -ne $false) { throw "Synthetic alarm actions must be disabled" }
if ($alarm.AlarmActions.Count -ne 0 -or $alarm.OKActions.Count -ne 0 -or $alarm.InsufficientDataActions.Count -ne 0) { throw "Synthetic alarm must have no configured actions" }
$originalState = $alarm.StateValue
```

`set-alarm-state`는 상태 변경 때 alarm action을 실행할 수 있으므로 위 조건은 필수 중단 조건이다. metric alarm은 실제 metric 평가에 따라 수 초 안에 상태가 돌아갈 수 있지만, 자동 복귀를 보장으로 취급하지 않는다.

마지막으로 artifact를 만든 뒤 저장된 plan만 생성하고, 사람이 내용 전체를 검토한다. 이 단계에서 `apply`하지 않는다.

```powershell
& "C:\path\to\python.exe" scripts/build_lambda.py
terraform -chdir=infra plan -out saved-dev.plan
```

plan에는 Lambda, EventBridge, private S3, DynamoDB, IAM, 전용 log group 및 이 서비스가 소유한 변경만 있어야 한다. application resource, application Secret, GitHub repository 또는 Slack configuration 변경이 있으면 중단한다.

## 2. 명시 승인 뒤 배포

보호 환경 승인자와 plan 검토자가 `saved-dev.plan`을 승인한 경우에만 실행한다. 이번 저장소 작업은 이 명령을 실행하지 않는다.

```powershell
terraform -chdir=infra apply saved-dev.plan
```

apply 뒤 topology object는 다시 `head-object`로 metadata만 확인한다. Bundle bucket에 topology를 업로드하는 절차는 없다.

```powershell
aws s3api head-object --bucket $env:PILO_TOPOLOGY_BUCKET --key $env:PILO_TOPOLOGY_KEY --query "{Encryption:ServerSideEncryption,Length:ContentLength}" --region ap-northeast-2
```

## 3. 전용 synthetic Alarm 전환

사전 점검과 승인 범위가 여전히 유효한지 확인한 뒤, 전용 metric alarm 하나만 `ALARM`으로 전환한다. 이는 CloudWatch가 EventBridge event를 생성하게 하는 유일한 live trigger다.

```powershell
aws cloudwatch set-alarm-state --alarm-name $env:PILO_SYNTHETIC_ALARM_NAME --state-value ALARM --state-reason "synthetic smoke test" --region ap-northeast-2
```

이 명령은 상태 변경이므로 보호 승인 범위에 포함된다. 실행 시간, 승인 참조, `$originalState`만 보호된 운영 기록에 남기며 실제 event ID나 리소스 식별자는 공개 저장소에 기록하지 않는다.

## 4. 결과 확인과 알려진 멱등성 범위

CloudWatch/Lambda의 구조화 로그에서 생성된 Incident ID를 보호된 운영 기록에서 확인한다. 그 ID를 이용해 다음을 확인하되 Bundle·Issue·payload 본문을 로컬 파일이나 Git에 복사하지 않는다.

- Bundle object의 S3 metadata와 SSE-S3 암호화, DynamoDB의 처리 checkpoint가 존재한다.
- private incident repository에 Issue가 하나 생성되었고 Evidence ID 인용이 있다.
- Slack Incoming Webhook에는 read API가 없다. 따라서 test channel에서 사람이 요약과 private Issue link 형식을 수동으로 확인한다.
- Lambda 로그와 게시 결과에 token, Secret 값 또는 topology 본문이 포함되지 않는다.

동일한 `set-alarm-state`를 다시 실행하면 EventBridge event ID가 달라진다. 따라서 그것은 같은 event ID 재처리나 exactly-once live 검증이 아니며, 이 smoke의 필수 범위에서 제외한다. 같은 event ID 멱등성은 기존 자동화 테스트로 검증한다. live 검증이 필요하면 구조화 로그에서 얻은 실제 event ID를 포함한 보호된 임시 envelope로 Lambda를 한 번 재호출하는 별도 승인 절차를 마련해야 하며, 이 runbook의 명령으로 수행하지 않는다.

## 5. 안전한 정리와 상태 복구

metric alarm이 실제 평가로 돌아갔다는 가정을 하지 말고, `describe-alarms`로 상태를 확인한다.

```powershell
$finalAlarm = aws cloudwatch describe-alarms --alarm-names $env:PILO_SYNTHETIC_ALARM_NAME --region ap-northeast-2 --output json | ConvertFrom-Json
if ($finalAlarm.MetricAlarms.Count -ne 1 -or $finalAlarm.CompositeAlarms.Count -ne 0) { throw "Synthetic metric alarm no longer matches the approved target" }
if ($finalAlarm.MetricAlarms[0].StateValue -ne $originalState) { throw "Alarm state did not return to its recorded original value" }
```

상태가 원래 값으로 돌아오지 않으면 중단하고 보호 승인자에게 보고한다. 원래 값으로의 추가 `set-alarm-state` 복구도 별도 상태 변경이므로 같은 보호 승인 범위와 action-free 조건을 다시 확인한 뒤에만 수행한다. Bundle, Issue, DynamoDB checkpoint를 수동 삭제하지 않는다. 서비스의 7일 Bundle lifecycle과 incident 운영 절차에 따라 보존·정리한다.
