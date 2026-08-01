# 보호된 dev 합성 Alarm 스모크 테스트

## 목적과 절대 경계

이 절차는 승인된 release candidate를 보호된 PILO dev에 배포한 뒤 vertical slice를 검증한다. 로컬 검증과 PR CI를 대체하지 않으며, 명시적 보호 환경 승인 없이는 시작하지 않는다. 실제 값·출력·Incident Bundle·Issue 본문·Slack payload·topology 본문·리소스 식별자를 Git, 티켓 또는 채팅에 기록하지 않는다.

live trigger는 CloudWatch가 생성한 상태 변경만 사용한다. 고객은 `aws.` source의 EventBridge event를 `PutEvents`로 생성할 수 없으므로, `aws events put-events`와 `tests/fixtures/events/dev-smoke-entry.json`은 live 실행에 쓰지 않는다. fixture는 handler가 받는 익명화된 오프라인 CloudWatch Alarm State Change EventBridge envelope 계약이다.

대상은 별도 소유·승인된 전용 synthetic **metric** alarm 하나뿐이다. composite alarm, PILO 애플리케이션 Alarm, ECS·ALB·RDS·SQS·Secret 및 다른 애플리케이션 리소스는 변경하거나 시험 대상으로 사용하지 않는다.

## 1. 변경 없는 사전 점검

승인된 보호 실행 환경에 아래 입력을 설정한다. 실제 값을 출력하지 않는다. 모든 명령은 실패하면 일반 오류로 즉시 중단하며, CLI stderr와 민감 본문을 표시하지 않는다.

```powershell
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

foreach ($name in @(
  "PILO_DEV_ACCOUNT_ID", "PILO_SYNTHETIC_ALARM_NAME", "PILO_SYNTHETIC_ALARM_ARN",
  "PILO_GITHUB_TOKEN_PARAMETER", "PILO_SLACK_WEBHOOK_PARAMETER",
  "PILO_INCIDENT_REPOSITORY", "PILO_TOPOLOGY_FILE", "PILO_TOPOLOGY_BUCKET", "PILO_TOPOLOGY_KEY"
)) {
  $protectedValue = [Environment]::GetEnvironmentVariable($name)
  if ([string]::IsNullOrWhiteSpace($protectedValue)) { throw "A required protected input is missing" }
}
if ($env:PILO_GITHUB_TOKEN_PARAMETER -eq $env:PILO_SLACK_WEBHOOK_PARAMETER) { throw "SSM parameters must be distinct" }

$region = $env:AWS_REGION
if (-not $region) { $region = $env:AWS_DEFAULT_REGION }
if (-not $region) {
  $region = aws configure get region 2>$null
  if ($LASTEXITCODE -ne 0) { throw "AWS region lookup failed" }
}
if ([string]::IsNullOrWhiteSpace([string]$region) -or ([string]$region).Trim() -ne "ap-northeast-2") { throw "AWS region must be ap-northeast-2" }

function Get-AwsText([string[]]$Arguments, [string]$FailureMessage) {
  $value = & aws @Arguments 2>$null
  $text = ($value | Out-String).Trim()
  if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($text)) { throw $FailureMessage }
  return $text
}

function Get-AwsJson([string[]]$Arguments, [string]$FailureMessage) {
  $raw = Get-AwsText $Arguments $FailureMessage
  try { return $raw | ConvertFrom-Json -ErrorAction Stop } catch { throw $FailureMessage }
}

function Get-GhText([string[]]$Arguments, [string]$FailureMessage) {
  $value = & gh @Arguments 2>$null
  $text = ($value | Out-String).Trim()
  if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($text)) { throw $FailureMessage }
  return $text
}

function Get-GhJson([string[]]$Arguments, [string]$FailureMessage) {
  $raw = Get-GhText $Arguments $FailureMessage
  try { return $raw | ConvertFrom-Json -ErrorAction Stop } catch { throw $FailureMessage }
}

function Get-TerraformOutput([string]$Name) {
  $value = & terraform "-chdir=infra" output -raw $Name 2>$null
  if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace([string]$value)) { throw "Required Terraform output is unavailable" }
  return ([string]$value).Trim()
}

function Assert-ApprovedAccount {
  $account = Get-AwsText @("sts", "get-caller-identity", "--query", "Account", "--output", "text", "--region", "ap-northeast-2") "AWS account identity check failed"
  if ($account -ne $env:PILO_DEV_ACCOUNT_ID) { throw "AWS account is not the approved dev account" }
}

function Assert-PrivateIncidentRepository {
  $visibility = Get-GhText @("repo", "view", $env:PILO_INCIDENT_REPOSITORY, "--json", "visibility", "--jq", ".visibility") "Incident repository visibility check failed"
  if ($visibility -ne "PRIVATE") { throw "Incident repository must be private" }
}

function Test-EmptyAlarmActionArray([object]$Actions) {
  return $null -eq $Actions -or @($Actions).Count -eq 0
}

function Get-ApprovedSyntheticMetricAlarm {
  param([switch]$RequireOkState)

  $response = Get-AwsJson @("cloudwatch", "describe-alarms", "--alarm-names", $env:PILO_SYNTHETIC_ALARM_NAME, "--region", "ap-northeast-2", "--output", "json") "Synthetic alarm inspection failed"
  $metricAlarms = if ($null -eq $response.MetricAlarms) { @() } else { @($response.MetricAlarms) }
  $compositeAlarms = if ($null -eq $response.CompositeAlarms) { @() } else { @($response.CompositeAlarms) }
  if ($metricAlarms.Count -ne 1 -or $compositeAlarms.Count -ne 0) { throw "Exactly one dedicated metric alarm is required" }
  $alarm = $metricAlarms[0]
  if ($alarm.AlarmArn -ne $env:PILO_SYNTHETIC_ALARM_ARN) { throw "Synthetic alarm identity does not match the approved target" }
  if ($alarm.ActionsEnabled -ne $false) { throw "Synthetic alarm actions must be disabled" }
  if (-not (Test-EmptyAlarmActionArray $alarm.AlarmActions) -or -not (Test-EmptyAlarmActionArray $alarm.OKActions) -or -not (Test-EmptyAlarmActionArray $alarm.InsufficientDataActions)) { throw "Synthetic alarm must have no configured actions" }
  if ($RequireOkState -and $alarm.StateValue -ne "OK") { throw "Synthetic alarm must start in OK" }
  return $alarm
}

$pythonVersion = & python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>$null
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace([string]$pythonVersion) -or ([string]$pythonVersion).Trim() -ne "3.12") { throw "Python 3.12 is required" }
& python -m pilo_incident_investigator.topology validate $env:PILO_TOPOLOGY_FILE *> $null
if ($LASTEXITCODE -ne 0) { throw "Protected topology validation failed" }

Assert-ApprovedAccount
Assert-PrivateIncidentRepository
$githubType = Get-AwsText @("ssm", "describe-parameters", "--parameter-filters", "Key=Name,Option=Equals,Values=$env:PILO_GITHUB_TOKEN_PARAMETER", "--query", "Parameters[0].Type", "--output", "text", "--region", "ap-northeast-2") "GitHub credential parameter check failed"
if ($githubType -ne "SecureString") { throw "GitHub credential parameter must be SecureString" }
$slackType = Get-AwsText @("ssm", "describe-parameters", "--parameter-filters", "Key=Name,Option=Equals,Values=$env:PILO_SLACK_WEBHOOK_PARAMETER", "--query", "Parameters[0].Type", "--output", "text", "--region", "ap-northeast-2") "Slack credential parameter check failed"
if ($slackType -ne "SecureString") { throw "Slack credential parameter must be SecureString" }
$topologyHead = Get-AwsJson @("s3api", "head-object", "--bucket", $env:PILO_TOPOLOGY_BUCKET, "--key", $env:PILO_TOPOLOGY_KEY, "--region", "ap-northeast-2", "--output", "json") "Protected topology metadata check failed"
if ($topologyHead.ServerSideEncryption -ne "AES256" -or [int64]$topologyHead.ContentLength -lt 1) { throw "Protected topology metadata is invalid" }
$originalAlarm = Get-ApprovedSyntheticMetricAlarm -RequireOkState
$originalState = $originalAlarm.StateValue
```

`PILO_TOPOLOGY_FILE`은 보호된 schema 검증 입력이고, S3 object는 Terraform의 기존 `topology_bucket_arn`/`topology_object_key`가 가리키는 metadata만 확인한다. topology를 Bundle bucket에 업로드·복사하거나 본문을 읽지 않는다. 보호 입력을 다룰 권한이 있는 작업자는 synthetic alarm ARN이 Terraform `alarm_arns`와 protected topology allowlist 모두에 포함되어 있음을 값 공개 없이 확인한다.

`set-alarm-state`는 action을 실행할 수 있으므로 action-free 검사 실패는 필수 중단 조건이다. metric alarm은 실제 metric 평가로 수 초 안에 복귀할 수 있지만 자동 복귀를 보장으로 취급하지 않는다.

artifact를 만들고 저장된 plan을 생성한다. plan 본문은 승인된 보호 콘솔에서만 사람이 검토하며, service-owned Lambda, EventBridge, private S3, DynamoDB, IAM, 전용 log group 외 변경이 있으면 중단한다.

```powershell
python scripts/build_lambda.py
if ($LASTEXITCODE -ne 0) { throw "Lambda artifact build failed" }
Assert-ApprovedAccount
terraform -chdir=infra plan -out saved-dev.plan
if ($LASTEXITCODE -ne 0) { throw "Terraform plan failed" }
```

## 2. 명시 승인 뒤 배포 및 배포값 확인

보호 승인자와 plan 검토자가 저장된 plan을 승인한 경우에만 실행한다. apply 직전 계정을 재확인한다. 이번 저장소 변경에서는 이 명령을 실행하지 않는다.

```powershell
Assert-ApprovedAccount
Assert-PrivateIncidentRepository
terraform -chdir=infra apply saved-dev.plan
if ($LASTEXITCODE -ne 0) { throw "Terraform apply failed" }

$bundleBucket = Get-TerraformOutput "bundle_bucket_name"
$stateTable = Get-TerraformOutput "state_table_name"
$lambdaFunction = Get-TerraformOutput "lambda_function_name"
$eventRule = Get-TerraformOutput "event_rule_name"
$runtimeRepository = Get-AwsText @("lambda", "get-function-configuration", "--function-name", $lambdaFunction, "--query", "Environment.Variables.PILO_GITHUB_REPOSITORY", "--output", "text", "--region", "ap-northeast-2") "Lambda repository configuration check failed"
if ($runtimeRepository -ne $env:PILO_INCIDENT_REPOSITORY) { throw "Lambda incident repository does not match the approved input" }
Assert-PrivateIncidentRepository
$eventRuleDescription = Get-AwsJson @("events", "describe-rule", "--name", $eventRule, "--region", "ap-northeast-2", "--output", "json") "EventBridge rule inspection failed"
try { $eventPattern = $eventRuleDescription.EventPattern | ConvertFrom-Json -ErrorAction Stop } catch { throw "EventBridge rule pattern is invalid" }
if (@($eventPattern.resources) -notcontains $env:PILO_SYNTHETIC_ALARM_ARN) { throw "EventBridge rule does not include the approved synthetic alarm" }
```

apply 뒤에도 protected topology는 계속 metadata-only로 확인한다. Bundle bucket에 topology를 업로드하는 절차는 없다.

```powershell
$topologyHead = Get-AwsJson @("s3api", "head-object", "--bucket", $env:PILO_TOPOLOGY_BUCKET, "--key", $env:PILO_TOPOLOGY_KEY, "--region", "ap-northeast-2", "--output", "json") "Protected topology metadata check failed"
if ($topologyHead.ServerSideEncryption -ne "AES256" -or [int64]$topologyHead.ContentLength -lt 1) { throw "Protected topology metadata is invalid" }
```

## 3. 전용 synthetic Alarm 전환

상태 변경 직전에 계정, private repository, alarm identity/action-free/`OK` 상태를 재검사한다. 이후 timestamp를 UTC로 보관하고 CloudWatch가 EventBridge event를 생성하도록 전용 metric alarm 하나만 `ALARM`으로 전환한다.

```powershell
Assert-ApprovedAccount
Assert-PrivateIncidentRepository
$triggerAlarm = Get-ApprovedSyntheticMetricAlarm -RequireOkState
$originalState = $triggerAlarm.StateValue
$smokeStartedAt = [DateTime]::UtcNow
& aws cloudwatch set-alarm-state --alarm-name $env:PILO_SYNTHETIC_ALARM_NAME --state-value ALARM --state-reason "synthetic smoke test" --region ap-northeast-2 1>$null 2>$null
if ($LASTEXITCODE -ne 0) { throw "Synthetic alarm state change failed" }
```

이는 보호 승인 범위의 상태 변경이다. 실행 시각과 승인 참조는 보호된 운영 기록에만 보관한다.

## 4. 실행 가능한 결과 확인

CloudWatch/Lambda가 완료할 시간을 보호된 운영 절차에 따라 기다린 뒤, `$smokeStartedAt` 이후의 service-owned Bundle metadata를 확인한다. key나 payload를 출력하지 않는다.

```powershell
$bundleList = Get-AwsJson @("s3api", "list-objects-v2", "--bucket", $bundleBucket, "--prefix", "incidents/", "--region", "ap-northeast-2", "--output", "json") "Bundle listing failed"
$recentBundles = @($bundleList.Contents | Where-Object { $null -ne $_ -and ([datetime]$_.LastModified).ToUniversalTime() -ge $smokeStartedAt })
if ($recentBundles.Count -ne 1) { throw "Expected exactly one new Incident Bundle" }
$bundleKey = [string]$recentBundles[0].Key
$bundleKeyMatch = [regex]::Match($bundleKey, '^incidents/(inc-[0-9a-f]{20})/bundle\.json$')
if (-not $bundleKeyMatch.Success) { throw "Incident Bundle key shape is invalid" }
$incidentId = $bundleKeyMatch.Groups[1].Value
$bundleHead = Get-AwsJson @("s3api", "head-object", "--bucket", $bundleBucket, "--key", $bundleKey, "--region", "ap-northeast-2", "--output", "json") "Incident Bundle metadata check failed"
if ($bundleHead.ServerSideEncryption -ne "AES256" -or [int64]$bundleHead.ContentLength -lt 1) { throw "Incident Bundle metadata is invalid" }

$dynamoValues = @{ ":incident_id" = @{ "S" = $incidentId } } | ConvertTo-Json -Compress
$stateResult = Get-AwsJson @("dynamodb", "scan", "--table-name", $stateTable, "--filter-expression", "incident_id = :incident_id", "--projection-expression", "event_id, incident_id, bundle_stored, issue_published, slack_status, processing_status", "--expression-attribute-values", $dynamoValues, "--region", "ap-northeast-2", "--output", "json") "DynamoDB incident state check failed"
$stateItems = if ($null -eq $stateResult.Items) { @() } else { @($stateResult.Items) }
if ($stateItems.Count -ne 1) { throw "Expected exactly one DynamoDB state item" }
$stateItem = $stateItems[0]
if ($stateItem.incident_id.S -ne $incidentId -or $stateItem.bundle_stored.BOOL -ne $true -or $stateItem.issue_published.BOOL -ne $true -or $stateItem.slack_status.S -ne "sent" -or $stateItem.processing_status.S -ne "complete") { throw "DynamoDB incident state is incomplete" }

Assert-PrivateIncidentRepository
$issueProof = Get-GhJson @("issue", "list", "--repo", $env:PILO_INCIDENT_REPOSITORY, "--state", "all", "--search", "incident-id:$incidentId in:body", "--json", "number,body", "--jq", '{count: length, evidence: (length == 1 and (.[0].body | test("Evidence ID|evidence[-_ ]id|근거:"; "i")))}') "Private Incident Issue check failed"
if ($issueProof.count -ne 1 -or $issueProof.evidence -ne $true) { throw "Private Incident Issue is missing or lacks an Evidence ID citation" }

$logStartMilliseconds = ([DateTimeOffset]$smokeStartedAt).ToUnixTimeMilliseconds()
$lambdaLogGroup = "/aws/lambda/$lambdaFunction"
foreach ($filterPattern in @('"GetSecretValue"', '"AWS_SECRET_ACCESS_KEY"', '"xoxb-"', '"hooks.slack.com"', '"ghp_"', '"github_pat_"')) {
  $matchCount = Get-AwsText @("logs", "filter-log-events", "--log-group-name", $lambdaLogGroup, "--start-time", "$logStartMilliseconds", "--filter-pattern", $filterPattern, "--query", "length(events)", "--output", "text", "--region", "ap-northeast-2") "Lambda log sensitive-pattern check failed"
  if ($matchCount -notmatch "^\d+$" -or [int]$matchCount -ne 0) { throw "Lambda logs contain a forbidden sensitive pattern" }
}
```

GitHub Issue body는 위 `gh --jq`가 Evidence ID citation의 boolean만 반환해 변수로 보관하며 출력하지 않는다. Slack Incoming Webhook에는 read API가 없으므로 test channel에서 사람이 요약과 private Issue link 형식을 수동 확인한다.

동일한 `set-alarm-state` 재실행은 다른 EventBridge event ID를 만들므로 같은 event ID 재처리나 exactly-once live 검증이 아니다. 이 smoke의 필수 범위에서 제외하며, 같은 event ID 멱등성은 기존 자동화 테스트로 검증한다. live 재검증이 필요하면 실제 event ID를 포함한 보호된 임시 envelope로 Lambda를 한 번 재호출하는 별도 승인이 필요하고, 이 runbook의 명령으로 수행하지 않는다.

## 5. 안전한 정리와 상태 복구

자동 복귀를 신뢰하지 않는다. 상태 복구 전 target identity와 action-free 조건을 다시 검사하되, 이 함수 호출에서는 `OK` 상태를 요구하지 않는다. 그 뒤 기록된 원래 상태와 비교한다.

```powershell
Assert-ApprovedAccount
$finalAlarm = Get-ApprovedSyntheticMetricAlarm
if ($finalAlarm.StateValue -ne $originalState) { throw "Alarm state did not return to its recorded original value" }
```

상태가 원래 값으로 돌아오지 않으면 중단하고 보호 승인자에게 보고한다. 원래 값으로의 추가 `set-alarm-state` 복구도 별도 상태 변경이므로 action-free 조건을 다시 확인하고 명시적 보호 승인 범위 안에서만 수행한다. Bundle, Issue, DynamoDB checkpoint는 수동 삭제하지 않으며, 서비스의 7일 Bundle lifecycle과 incident 운영 절차를 따른다.
