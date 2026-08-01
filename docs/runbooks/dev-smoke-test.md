# 보호된 dev 전용 synthetic Alarm 스모크 테스트

## 목적과 절대 경계

이 절차는 승인된 release candidate를 보호된 PILO dev에 배포한 뒤, 전용 synthetic alarm 하나로 Incident Investigator의 vertical slice를 확인한다. 로컬 검증과 PR CI를 대체하지 않으며 명시적 보호 환경 승인 없이는 시작하지 않는다. 실제 값·출력·Incident Bundle·Issue 본문·Slack payload·topology 본문·리소스 식별자를 Git, 티켓 또는 채팅에 기록하지 않는다.

live trigger는 CloudWatch가 만든 상태 변경만 사용한다. 고객은 aws. source의 EventBridge event를 생성할 수 없으므로 offline fixture는 handler 입력 계약일 뿐 live 실행에 사용하지 않는다. 대상은 아래 exact identity를 가진 별도 synthetic metric alarm 하나뿐이다.

- Alarm name: pilo-incident-investigator-dev-smoke
- Namespace: PILO/IncidentInvestigator/Smoke
- Metric name: Trigger
- Dimensions: 빈 배열
- 필수 tags: pilo:owner=pilo-incident-investigator, pilo:purpose=dev-smoke

composite alarm, PILO 애플리케이션 alarm 및 ECS·ALB·RDS·SQS·Secret 등 애플리케이션 리소스는 시험 대상으로 사용하거나 변경하지 않는다.

모든 아래 block은 동일한 보호된 PowerShell session에서 순서대로 실행한다. 값 또는 resource identifier를 출력하지 않으며, 외부 CLI 오류는 일반화된 오류로 즉시 중단한다.

## 1. 변경 없는 사전 점검과 공통 함수

승인된 보호 실행 환경에는 PILO_DEV_ACCOUNT_ID, PILO_SYNTHETIC_ALARM_ARN, PILO_GITHUB_TOKEN_PARAMETER_ARN, PILO_SLACK_WEBHOOK_PARAMETER_ARN, PILO_BEDROCK_MODEL_ARN, PILO_INCIDENT_REPOSITORY, PILO_TOPOLOGY_FILE, PILO_TOPOLOGY_BUCKET, PILO_TOPOLOGY_KEY를 설정한다. 두 SSM input은 parameter ARN이며 token/webhook 값이나 parameter name input이 아니다. Bedrock input은 ap-northeast-2의 foundation model ARN 또는 승인된 dev account의 inference/application inference profile ARN이어야 한다.

~~~powershell
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$SyntheticAlarmName = "pilo-incident-investigator-dev-smoke"
$SyntheticMetricNamespace = "PILO/IncidentInvestigator/Smoke"
$SyntheticMetricName = "Trigger"

foreach ($name in @(
  "PILO_DEV_ACCOUNT_ID", "PILO_SYNTHETIC_ALARM_ARN",
  "PILO_GITHUB_TOKEN_PARAMETER_ARN", "PILO_SLACK_WEBHOOK_PARAMETER_ARN", "PILO_BEDROCK_MODEL_ARN",
  "PILO_INCIDENT_REPOSITORY", "PILO_TOPOLOGY_FILE", "PILO_TOPOLOGY_BUCKET", "PILO_TOPOLOGY_KEY"
)) {
  $protectedValue = [Environment]::GetEnvironmentVariable($name)
  if ([string]::IsNullOrWhiteSpace($protectedValue)) { throw "A required protected input is missing" }
}
if ($env:PILO_DEV_ACCOUNT_ID -notmatch "^[0-9]{12}$") { throw "Approved dev account ID is invalid" }
if ($env:PILO_SYNTHETIC_ALARM_ARN -notmatch "^arn:aws:cloudwatch:ap-northeast-2:$([regex]::Escape($env:PILO_DEV_ACCOUNT_ID)):alarm:pilo-incident-investigator-dev-smoke$") { throw "Synthetic alarm ARN is outside the approved account, region, or name" }
if ($env:PILO_GITHUB_TOKEN_PARAMETER_ARN -eq $env:PILO_SLACK_WEBHOOK_PARAMETER_ARN) { throw "SSM parameter ARNs must be distinct" }
if ($env:PILO_BEDROCK_MODEL_ARN -notmatch "^arn:aws:bedrock:ap-northeast-2::foundation-model/[^\s*?]+$" -and $env:PILO_BEDROCK_MODEL_ARN -notmatch "^arn:aws:bedrock:ap-northeast-2:$([regex]::Escape($env:PILO_DEV_ACCOUNT_ID)):(inference-profile|application-inference-profile)/[^\s*?]+$") { throw "Bedrock model ARN is outside the approved account or region" }

$region = $env:AWS_REGION
if (-not $region) { $region = $env:AWS_DEFAULT_REGION }
if (-not $region) {
  $region = aws configure get region 2>$null
  if ($LASTEXITCODE -ne 0) { throw "AWS region lookup failed" }
}
if ([string]::IsNullOrWhiteSpace([string]$region) -or ([string]$region).Trim() -ne "ap-northeast-2") { throw "AWS region must be ap-northeast-2" }

function Get-AwsText([string[]]$Arguments, [string]$FailureMessage) {
  $value = & aws @Arguments 2>$null
  $exitCode = $LASTEXITCODE
  $text = ($value | Out-String).Trim()
  if ($exitCode -ne 0 -or [string]::IsNullOrWhiteSpace($text)) { throw $FailureMessage }
  return $text
}

function Get-AwsJson([string[]]$Arguments, [string]$FailureMessage) {
  $raw = Get-AwsText $Arguments $FailureMessage
  try { return $raw | ConvertFrom-Json -ErrorAction Stop } catch { throw $FailureMessage }
}

function Get-GhText([string[]]$Arguments, [string]$FailureMessage) {
  $value = & gh @Arguments 2>$null
  $exitCode = $LASTEXITCODE
  $text = ($value | Out-String).Trim()
  if ($exitCode -ne 0 -or [string]::IsNullOrWhiteSpace($text)) { throw $FailureMessage }
  return $text
}

function Get-GhJson([string[]]$Arguments, [string]$FailureMessage) {
  $raw = Get-GhText $Arguments $FailureMessage
  try { return $raw | ConvertFrom-Json -ErrorAction Stop } catch { throw $FailureMessage }
}

function Get-TerraformOutput([string]$Name) {
  $value = & terraform "-chdir=infra" output -raw $Name 2>$null
  $exitCode = $LASTEXITCODE
  $text = ($value | Out-String).Trim()
  if ($exitCode -ne 0 -or [string]::IsNullOrWhiteSpace($text)) { throw "Required Terraform output is unavailable" }
  return $text
}

function Assert-ExactSingleton([object]$Values, [string]$Expected, [string]$FailureMessage) {
  $items = @($Values | Where-Object { $null -ne $_ })
  if ($items.Count -ne 1 -or [string]$items[0] -cne $Expected) { throw $FailureMessage }
}

function Assert-ExactObjectKeys([object]$Object, [string[]]$ExpectedKeys, [string]$FailureMessage) {
  if ($null -eq $Object) { throw $FailureMessage }
  $actualKeys = @($Object.PSObject.Properties | ForEach-Object { $_.Name })
  $unexpectedKeys = @($actualKeys | Where-Object { $ExpectedKeys -cnotcontains $_ })
  $missingKeys = @($ExpectedKeys | Where-Object { $actualKeys -cnotcontains $_ })
  if ($actualKeys.Count -ne $ExpectedKeys.Count -or $unexpectedKeys.Count -ne 0 -or $missingKeys.Count -ne 0) { throw $FailureMessage }
}

function Get-RequiredDynamoAttributeValue([object]$Item, [string]$Name, [string]$Type) {
  $attributeProperty = $Item.PSObject.Properties[$Name]
  if ($null -eq $attributeProperty) { throw "DynamoDB incident state attribute is missing" }
  $attribute = $attributeProperty.Value
  Assert-ExactObjectKeys $attribute @($Type) "DynamoDB incident state attribute type is invalid"
  return $attribute.PSObject.Properties[$Type].Value
}

function Assert-DynamoIncidentState([object]$Item, [string]$ExpectedIncidentId) {
  Assert-ExactObjectKeys $Item @("incident_id", "checkpoint", "checkpoint_rank", "bundle_stored", "issue_published", "slack_status", "processing_status") "DynamoDB incident state shape is invalid"
  $incidentId = Get-RequiredDynamoAttributeValue $Item "incident_id" "S"
  $checkpoint = Get-RequiredDynamoAttributeValue $Item "checkpoint" "S"
  $checkpointRank = Get-RequiredDynamoAttributeValue $Item "checkpoint_rank" "N"
  $bundleStored = Get-RequiredDynamoAttributeValue $Item "bundle_stored" "BOOL"
  $issuePublished = Get-RequiredDynamoAttributeValue $Item "issue_published" "BOOL"
  $slackStatus = Get-RequiredDynamoAttributeValue $Item "slack_status" "S"
  $processingStatus = Get-RequiredDynamoAttributeValue $Item "processing_status" "S"
  if ($incidentId -isnot [string] -or $incidentId -cne $ExpectedIncidentId -or $checkpoint -isnot [string] -or $checkpointRank -isnot [string] -or $bundleStored -isnot [bool] -or $issuePublished -isnot [bool] -or $slackStatus -isnot [string] -or $processingStatus -isnot [string]) { throw "DynamoDB incident state value type is invalid" }
  $checkpointRanks = @{ "claimed" = 0; "snapshot_complete" = 1; "bundle_stored" = 2; "issue_published" = 3; "slack_attempted" = 4 }
  if ($checkpoint -cnotin @("claimed", "snapshot_complete", "bundle_stored", "issue_published", "slack_attempted") -or $checkpointRank -notmatch "^[0-4]$" -or [int]$checkpointRank -ne $checkpointRanks[$checkpoint]) { throw "DynamoDB checkpoint is invalid" }
  if ($processingStatus -cnotin @("processing", "retryable", "complete") -or $slackStatus -cnotin @("not_attempted", "failed", "sent")) { throw "DynamoDB incident state enum is invalid" }
  if (($issuePublished -eq $true -and $bundleStored -ne $true) -or ($slackStatus -cne "not_attempted" -and $bundleStored -ne $true)) { throw "DynamoDB incident state has impossible publisher outcomes" }
  if ($processingStatus -ceq "complete" -and ($bundleStored -ne $true -or $issuePublished -ne $true -or $slackStatus -cne "sent" -or $checkpoint -cne "slack_attempted" -or $checkpointRank -ne "4")) { throw "DynamoDB complete incident state is invalid" }
  return [pscustomobject]@{ IsComplete = $processingStatus -ceq "complete" }
}

function Assert-ApprovedAccount {
  $account = Get-AwsText @("sts", "get-caller-identity", "--query", "Account", "--output", "text", "--region", "ap-northeast-2") "AWS account identity check failed"
  if ($account -ne $env:PILO_DEV_ACCOUNT_ID) { throw "AWS account is not the approved dev account" }
}

function Assert-PrivateIncidentRepository {
  $visibility = Get-GhText @("repo", "view", $env:PILO_INCIDENT_REPOSITORY, "--json", "visibility", "--jq", ".visibility") "Incident repository visibility check failed"
  if ($visibility -ne "PRIVATE") { throw "Incident repository must be private" }
}

function Get-ApprovedSsmParameterName([string]$ParameterArn, [string]$ExpectedName) {
  $expectedPath = $ExpectedName.TrimStart("/")
  $pattern = "^arn:aws:ssm:ap-northeast-2:$([regex]::Escape($env:PILO_DEV_ACCOUNT_ID)):parameter/$([regex]::Escape($expectedPath))$"
  $match = [regex]::Match($ParameterArn, $pattern)
  if (-not $match.Success) { throw "SSM parameter ARN is outside the approved account, region, or role" }
  return $ExpectedName
}

function Assert-ApprovedSsmParameter([string]$ParameterArn, [string]$ExpectedName) {
  $parameterName = Get-ApprovedSsmParameterName $ParameterArn $ExpectedName
  $parameterType = Get-AwsText @("ssm", "describe-parameters", "--parameter-filters", "Key=Name,Option=Equals,Values=$parameterName", "--query", "Parameters[0].Type", "--output", "text", "--region", "ap-northeast-2") "SSM parameter metadata check failed"
  if ($parameterType -ne "SecureString") { throw "SSM parameter must be SecureString" }
}

function Test-EmptyAlarmActionArray([object]$Actions) {
  return @($Actions | Where-Object { $null -ne $_ }).Count -eq 0
}

function Assert-ApprovedSyntheticAlarmMetadata([object]$Alarm, [object]$Tags, [switch]$RequireOkState) {
  if ($Alarm.AlarmName -ne $SyntheticAlarmName -or $Alarm.AlarmArn -ne $env:PILO_SYNTHETIC_ALARM_ARN) { throw "Synthetic alarm identity does not match the approved target" }
  if ($Alarm.Namespace -ne $SyntheticMetricNamespace -or $Alarm.MetricName -ne $SyntheticMetricName -or @($Alarm.Dimensions | Where-Object { $null -ne $_ }).Count -ne 0) { throw "Synthetic alarm metric identity is invalid" }
  if ($Alarm.ActionsEnabled -ne $false) { throw "Synthetic alarm actions must be disabled" }
  if (-not (Test-EmptyAlarmActionArray $Alarm.AlarmActions) -or -not (Test-EmptyAlarmActionArray $Alarm.OKActions) -or -not (Test-EmptyAlarmActionArray $Alarm.InsufficientDataActions)) { throw "Synthetic alarm must have no configured actions" }
  if ($RequireOkState -and $Alarm.StateValue -ne "OK") { throw "Synthetic alarm must start in OK" }
  $ownerTags = @($Tags | Where-Object { $_.Key -eq "pilo:owner" })
  $purposeTags = @($Tags | Where-Object { $_.Key -eq "pilo:purpose" })
  if ($ownerTags.Count -ne 1 -or $ownerTags[0].Value -ne "pilo-incident-investigator" -or $purposeTags.Count -ne 1 -or $purposeTags[0].Value -ne "dev-smoke") { throw "Synthetic alarm ownership tags are invalid" }
}

function Get-ApprovedSyntheticMetricAlarm {
  param([switch]$RequireOkState)
  $response = Get-AwsJson @("cloudwatch", "describe-alarms", "--alarm-names", $SyntheticAlarmName, "--region", "ap-northeast-2", "--output", "json") "Synthetic alarm inspection failed"
  $metricAlarms = @($response.MetricAlarms | Where-Object { $null -ne $_ })
  $compositeAlarms = @($response.CompositeAlarms | Where-Object { $null -ne $_ })
  if ($metricAlarms.Count -ne 1 -or $compositeAlarms.Count -ne 0) { throw "Exactly one dedicated metric alarm is required" }
  $alarm = $metricAlarms[0]
  $tagResponse = Get-AwsJson @("cloudwatch", "list-tags-for-resource", "--resource-arn", $env:PILO_SYNTHETIC_ALARM_ARN, "--region", "ap-northeast-2", "--output", "json") "Synthetic alarm tag inspection failed"
  Assert-ApprovedSyntheticAlarmMetadata $alarm $tagResponse.Tags -RequireOkState:$RequireOkState
  return $alarm
}

function Assert-ProtectedTopologyBinding {
  & python -m pilo_incident_investigator.topology validate $env:PILO_TOPOLOGY_FILE *> $null
  if ($LASTEXITCODE -ne 0) { throw "Protected topology validation failed" }
  $topologyMappingCheck = @'
import os
from pathlib import Path
from pilo_incident_investigator.topology import Topology
topology = Topology.load(Path(os.environ["PILO_TOPOLOGY_FILE"]).read_text(encoding="utf-8"))
raise SystemExit(0 if topology.resolve_alarm(os.environ["PILO_SYNTHETIC_ALARM_ARN"]) else 1)
'@
  & python -c $topologyMappingCheck *> $null
  if ($LASTEXITCODE -ne 0) { throw "Protected topology does not map the synthetic alarm" }
  $topologyHead = Get-AwsJson @("s3api", "head-object", "--bucket", $env:PILO_TOPOLOGY_BUCKET, "--key", $env:PILO_TOPOLOGY_KEY, "--checksum-mode", "ENABLED", "--region", "ap-northeast-2", "--output", "json") "Protected topology metadata check failed"
  $sha256 = [Security.Cryptography.SHA256]::Create()
  try { $localTopologyChecksum = [Convert]::ToBase64String($sha256.ComputeHash([IO.File]::ReadAllBytes($env:PILO_TOPOLOGY_FILE))) } finally { $sha256.Dispose() }
  if ($topologyHead.ServerSideEncryption -ne "AES256" -or [int64]$topologyHead.ContentLength -lt 1 -or [string]::IsNullOrWhiteSpace($topologyHead.ChecksumSHA256) -or $topologyHead.ChecksumSHA256 -ne $localTopologyChecksum) { throw "Protected topology object does not match the validated local input" }
}

function Assert-RuntimeBinding {
  Assert-ApprovedSsmParameter $env:PILO_GITHUB_TOKEN_PARAMETER_ARN "/pilo-incident-investigator/dev/github-token"
  Assert-ApprovedSsmParameter $env:PILO_SLACK_WEBHOOK_PARAMETER_ARN "/pilo-incident-investigator/dev/slack-webhook-url"
  Assert-ProtectedTopologyBinding
  $configuration = Get-AwsJson @("lambda", "get-function-configuration", "--function-name", $lambdaFunction, "--region", "ap-northeast-2", "--output", "json") "Lambda configuration check failed"
  $variables = $configuration.Environment.Variables
  if ($null -eq $variables -or $configuration.FunctionArn -ne $lambdaFunctionArn) { throw "Lambda configuration is invalid" }
  $expectedVariables = @{
    "PILO_REGION" = "ap-northeast-2"
    "PILO_TOPOLOGY_BUCKET" = $env:PILO_TOPOLOGY_BUCKET
    "PILO_TOPOLOGY_KEY" = $env:PILO_TOPOLOGY_KEY
    "PILO_STATE_TABLE" = $stateTable
    "PILO_BUNDLE_BUCKET" = $bundleBucket
    "PILO_GITHUB_REPOSITORY" = $env:PILO_INCIDENT_REPOSITORY
    "PILO_GITHUB_TOKEN_PARAMETER" = $env:PILO_GITHUB_TOKEN_PARAMETER_ARN
    "PILO_SLACK_WEBHOOK_PARAMETER" = $env:PILO_SLACK_WEBHOOK_PARAMETER_ARN
    "PILO_BEDROCK_MODEL_ID" = $env:PILO_BEDROCK_MODEL_ARN
    "PILO_MODE" = "snapshot_only"
  }
  Assert-ExactObjectKeys $variables @("PILO_REGION", "PILO_TOPOLOGY_BUCKET", "PILO_TOPOLOGY_KEY", "PILO_STATE_TABLE", "PILO_BUNDLE_BUCKET", "PILO_GITHUB_REPOSITORY", "PILO_GITHUB_TOKEN_PARAMETER", "PILO_SLACK_WEBHOOK_PARAMETER", "PILO_BEDROCK_MODEL_ID", "PILO_MODE") "Lambda environment binding keys are invalid"
  foreach ($key in $expectedVariables.Keys) {
    if ([string]$variables.($key) -cne [string]$expectedVariables[$key]) { throw "Lambda runtime binding does not match the approved input" }
  }
  Assert-PrivateIncidentRepository
  $rule = Get-AwsJson @("events", "describe-rule", "--name", $eventRule, "--region", "ap-northeast-2", "--output", "json") "EventBridge rule inspection failed"
  if ($rule.State -ne "ENABLED") { throw "EventBridge rule must be enabled" }
  try { $pattern = $rule.EventPattern | ConvertFrom-Json -ErrorAction Stop } catch { throw "EventBridge rule pattern is invalid" }
  Assert-ExactObjectKeys $pattern @("source", "detail-type", "region", "resources", "detail") "EventBridge event pattern keys are invalid"
  Assert-ExactObjectKeys $pattern.detail @("state") "EventBridge detail keys are invalid"
  Assert-ExactObjectKeys $pattern.detail.state @("value") "EventBridge state keys are invalid"
  Assert-ExactSingleton $pattern.source "aws.cloudwatch" "EventBridge source must be the synthetic CloudWatch route"
  Assert-ExactSingleton $pattern."detail-type" "CloudWatch Alarm State Change" "EventBridge detail type is invalid"
  Assert-ExactSingleton $pattern.region "ap-northeast-2" "EventBridge region is invalid"
  Assert-ExactSingleton $pattern.resources $env:PILO_SYNTHETIC_ALARM_ARN "EventBridge must route only the approved synthetic alarm"
  Assert-ExactSingleton $pattern.detail.state.value "ALARM" "EventBridge alarm state is invalid"
  $targets = Get-AwsJson @("events", "list-targets-by-rule", "--rule", $eventRule, "--region", "ap-northeast-2", "--output", "json") "EventBridge target inspection failed"
  $targetItems = @($targets.Targets | Where-Object { $null -ne $_ })
  if ($targetItems.Count -ne 1 -or $targetItems[0].Arn -ne $lambdaFunctionArn) { throw "EventBridge target must bind exactly one Lambda" }
  foreach ($field in @("Input", "InputPath", "InputTransformer")) {
    if ($null -ne $targetItems[0].PSObject.Properties[$field]) { throw "EventBridge target must bind the unmodified event to exactly one Lambda" }
  }
}

function Wait-ForPublishedIncident {
  param([datetime]$StartedAt)
  $deadline = [DateTime]::UtcNow.AddSeconds(360)
  while ($true) {
    $bundleList = Get-AwsJson @("s3api", "list-objects-v2", "--bucket", $bundleBucket, "--prefix", "incidents/", "--region", "ap-northeast-2", "--output", "json") "Bundle listing failed"
    $contentsProperty = $bundleList.PSObject.Properties["Contents"]
    $bundleContents = if ($null -eq $contentsProperty) { @() } else { @($contentsProperty.Value) }
    $recentBundles = @($bundleContents | Where-Object { $null -ne $_ -and ([datetime]$_.LastModified).ToUniversalTime() -ge $StartedAt })
    if ($recentBundles.Count -gt 1) { throw "More than one isolated synthetic Incident Bundle was found" }
    if ($recentBundles.Count -eq 1) {
      $bundleKey = [string]$recentBundles[0].Key
      $bundleKeyMatch = [regex]::Match($bundleKey, '^incidents/(inc-[0-9a-f]{20})/bundle\.json$')
      if (-not $bundleKeyMatch.Success) { throw "Incident Bundle key shape is invalid" }
      $incidentId = $bundleKeyMatch.Groups[1].Value
      $bundleHead = Get-AwsJson @("s3api", "head-object", "--bucket", $bundleBucket, "--key", $bundleKey, "--region", "ap-northeast-2", "--output", "json") "Incident Bundle metadata check failed"
      if ($bundleHead.ServerSideEncryption -ne "AES256" -or [int64]$bundleHead.ContentLength -lt 1) { throw "Incident Bundle metadata is invalid" }
      $dynamoValues = @{ ":incident_id" = @{ "S" = $incidentId } } | ConvertTo-Json -Compress
      $stateResult = Get-AwsJson @("dynamodb", "scan", "--table-name", $stateTable, "--filter-expression", "incident_id = :incident_id", "--projection-expression", "incident_id, checkpoint, checkpoint_rank, bundle_stored, issue_published, slack_status, processing_status", "--expression-attribute-values", $dynamoValues, "--region", "ap-northeast-2", "--output", "json") "DynamoDB incident state check failed"
      $stateItems = @($stateResult.Items | Where-Object { $null -ne $_ })
      if ($stateItems.Count -gt 1) { throw "More than one DynamoDB state item was found" }
      if ($stateItems.Count -eq 1) {
        $stateItem = $stateItems[0]
        $validatedState = Assert-DynamoIncidentState $stateItem $incidentId
        if ($validatedState.IsComplete) {
          Assert-PrivateIncidentRepository
          $issues = @(Get-GhJson @("issue", "list", "--repo", $env:PILO_INCIDENT_REPOSITORY, "--state", "all", "--search", "incident-id:$incidentId in:body", "--json", "number,body") "Private Incident Issue check failed")
          $markerPattern = "(?m)^<!-- incident-id:$([regex]::Escape($incidentId)) -->\r?$"
          $matchingIssues = @($issues | Where-Object {
            $bodyProperty = $_.PSObject.Properties["body"]
            $null -ne $bodyProperty -and $bodyProperty.Value -is [string] -and $bodyProperty.Value -cmatch $markerPattern
          })
          if ($matchingIssues.Count -gt 1) { throw "More than one private Incident Issue has the canonical incident marker" }
          if ($matchingIssues.Count -eq 1) {
            $body = [string]$matchingIssues[0].PSObject.Properties["body"].Value
            if ($body -cnotmatch "\(근거: E-[0-9]{3}(?:, E-[0-9]{3})*\)") { throw "Private Incident Issue lacks a canonical Evidence ID citation" }
            return $incidentId
          }
        }
      }
    }
    if ([DateTime]::UtcNow -ge $deadline) { throw "Timed out waiting for complete synthetic incident publication" }
    Start-Sleep -Seconds 10
  }
}

$pythonVersion = & python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>$null
$pythonExitCode = $LASTEXITCODE
if ($pythonExitCode -ne 0 -or [string]::IsNullOrWhiteSpace([string]$pythonVersion) -or ([string]$pythonVersion).Trim() -ne "3.12") { throw "Python 3.12 is required" }

Assert-ApprovedAccount
Assert-PrivateIncidentRepository
Assert-ApprovedSsmParameter $env:PILO_GITHUB_TOKEN_PARAMETER_ARN "/pilo-incident-investigator/dev/github-token"
Assert-ApprovedSsmParameter $env:PILO_SLACK_WEBHOOK_PARAMETER_ARN "/pilo-incident-investigator/dev/slack-webhook-url"
Assert-ProtectedTopologyBinding
$originalAlarm = Get-ApprovedSyntheticMetricAlarm -RequireOkState
$originalState = $originalAlarm.StateValue
~~~

위 S3 확인은 head-object checksum-mode ENABLED metadata만 사용한다. Bundle bucket에 topology를 업로드·복사하거나 topology 본문을 출력하지 않는다.

set-alarm-state는 action을 실행할 수 있으므로 alarm ownership, action-free, OK gate 중 하나라도 실패하면 중단한다. metric alarm은 실제 metric 평가로 상태가 돌아갈 수 있지만 자동 복귀를 보장으로 취급하지 않는다.

저장된 plan은 Git ignore 대상이어야 한다. 생성 전 ignore를 확인하고, plan 본문은 승인된 보호 콘솔에서만 검토한다. service-owned Lambda, EventBridge, private S3, DynamoDB, IAM, 전용 log group 외 변경이 있으면 중단한다.

~~~powershell
git check-ignore -q infra/saved-dev.tfplan
if ($LASTEXITCODE -ne 0) { throw "Saved Terraform plan path must be ignored" }
python scripts/build_lambda.py
if ($LASTEXITCODE -ne 0) { throw "Lambda artifact build failed" }
Assert-ApprovedAccount
terraform -chdir=infra plan -out saved-dev.tfplan
if ($LASTEXITCODE -ne 0) { throw "Terraform plan failed" }
~~~

## 2. 명시 승인 뒤 배포와 runtime binding 확인

보호 승인자와 plan 검토자가 infra/saved-dev.tfplan을 승인한 경우에만 실행한다. apply 직전 account를 재확인한다. 이 runbook 작성 작업에서는 이 명령을 실행하지 않는다.

~~~powershell
Assert-ApprovedAccount
Assert-PrivateIncidentRepository
terraform -chdir=infra apply saved-dev.tfplan
if ($LASTEXITCODE -ne 0) { throw "Terraform apply failed" }

$bundleBucket = Get-TerraformOutput "bundle_bucket_name"
$stateTable = Get-TerraformOutput "state_table_name"
$lambdaFunction = Get-TerraformOutput "lambda_function_name"
$eventRule = Get-TerraformOutput "event_rule_name"
$lambdaConfiguration = Get-AwsJson @("lambda", "get-function-configuration", "--function-name", $lambdaFunction, "--region", "ap-northeast-2", "--output", "json") "Lambda configuration bootstrap check failed"
$lambdaFunctionArn = $lambdaConfiguration.FunctionArn
if ([string]::IsNullOrWhiteSpace([string]$lambdaFunctionArn)) { throw "Lambda function ARN is unavailable" }
Assert-RuntimeBinding
~~~

Assert-RuntimeBinding은 Lambda environment, EventBridge event pattern, EventBridge target을 정확한 singleton 값으로 검사한다. 따라서 이 smoke deployment의 rule은 전용 synthetic ARN만 route해야 하며 application alarm을 동시에 route하면 안 된다. 실제 PILO alarm route 활성화는 smoke 성공 뒤 별도 승인된 Terraform plan/apply로 전환하는 후속 단계다. 이 runbook은 application alarm route를 자동 적용하거나 복구하지 않는다.

## 3. trigger·결과·항상 실행되는 cleanup 확인

아래 try/catch/finally 전체를 같은 session에서 실행한다. result gate가 실패해도 finally가 account, alarm identity/ownership/action-free, 원래 상태 복귀를 검사한다. 추가 set-alarm-state 복구는 별도 상태 변경이므로 이 절차로 자동 실행하지 않는다.

~~~powershell
$smokeFailed = $false
try {
  Assert-ApprovedAccount
  Assert-RuntimeBinding
  $triggerAlarm = Get-ApprovedSyntheticMetricAlarm -RequireOkState
  $originalState = $triggerAlarm.StateValue
  $smokeStartedAt = [DateTime]::UtcNow
  & aws cloudwatch set-alarm-state --alarm-name $SyntheticAlarmName --state-value ALARM --state-reason "synthetic smoke test" --region ap-northeast-2 1>$null 2>$null
  if ($LASTEXITCODE -ne 0) { throw "Synthetic alarm state change failed" }

  $incidentId = Wait-ForPublishedIncident $smokeStartedAt
  $slackConfirmation = Read-Host "After manually checking the test channel summary and private Issue link, enter CONFIRMED"
  if ($slackConfirmation -cne "CONFIRMED") { throw "Slack test-channel confirmation was not provided" }

  $logStartMilliseconds = ([DateTimeOffset]$smokeStartedAt).ToUnixTimeMilliseconds()
  $lambdaLogGroup = "/aws/lambda/$lambdaFunction"
  foreach ($filterPattern in @('"GetSecretValue"', '"AWS_SECRET_ACCESS_KEY"', '"xoxb-"', '"hooks.slack.com"', '"ghp_"', '"github_pat_"')) {
    $matchCount = Get-AwsText @("logs", "filter-log-events", "--log-group-name", $lambdaLogGroup, "--start-time", "$logStartMilliseconds", "--filter-pattern", $filterPattern, "--query", "length(events)", "--output", "text", "--region", "ap-northeast-2") "Lambda log sensitive-pattern check failed"
    if ($matchCount -notmatch "^\d+$" -or [int]$matchCount -ne 0) { throw "Lambda logs contain a forbidden sensitive pattern" }
  }

  # Incoming Webhook에는 read API가 없으므로 test channel에서 사람이 summary와 private Issue link 형식을 수동 확인한다.
}
catch {
  $smokeFailed = $true
  throw "Synthetic smoke verification failed"
}
finally {
  try {
    Assert-ApprovedAccount
    $finalAlarm = Get-ApprovedSyntheticMetricAlarm
    if ($finalAlarm.StateValue -ne $originalState) { throw "Synthetic alarm did not return to its recorded original state" }
  }
  catch {
    if ($smokeFailed) { throw "Synthetic smoke verification and cleanup verification failed" }
    throw "Synthetic smoke cleanup verification failed"
  }
}
~~~

set-alarm-state 재호출로 동일 event ID를 통제하거나 재사용할 수 없으므로 same-event 멱등성 증명이 아니다. 이미 alarm이 ALARM이면 state-change event 자체가 발생하지 않을 수 있다. same-event 멱등성은 기존 자동화 테스트로 검증하며, live 재검증은 실제 event ID를 포함한 보호된 임시 envelope로 Lambda를 한 번 재호출하는 별도 승인이 필요하다.

Bundle, Issue, DynamoDB checkpoint는 수동 삭제하지 않는다. final state가 원래 값으로 돌아오지 않으면 중단하고 보호 승인자에게 보고한다. 원래 값으로의 추가 상태 복구도 action-free 조건을 다시 확인한 뒤 명시적 보호 승인 범위에서만 수행한다.
