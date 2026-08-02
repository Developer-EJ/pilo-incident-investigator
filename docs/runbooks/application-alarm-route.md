# PILO dev application Alarm route 적용 runbook

이 runbook은 PILO dev(`ap-northeast-2`)의 기존 26개 활성 Alarm 경로에 승인된 8개 mapping만
추가해 정확히 34개 Alarm을 EventBridge rule로 라우팅한다. 전용 synthetic smoke Alarm mapping 1개는
topology에만 유지하며 EventBridge rule에는 포함하지 않는다. 적용 전 topology를 먼저
갱신하고, 검증한 단일 saved plan만 적용한다. 실제 Alarm의 상태나 정의를 변경하지 않으며,
실제 값·식별자·topology 본문은 화면이나 Git에 출력하지 않는다.

아래 모든 명령은 보호된 운영 세션에서 순서대로 실행한다. 다음 입력은 사전에 설정하며,
파일과 생성물은 저장소 추적 대상 밖의 보호된 위치를 사용한다.

~~~powershell
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

foreach ($name in @(
  'PILO_DEV_ACCOUNT_ID', 'PILO_BASELINE_TOPOLOGY_FILE', 'PILO_CANDIDATE_TOPOLOGY_FILE',
  'PILO_NEW_ALARM_MAPPINGS_FILE', 'PILO_TOPOLOGY_BUCKET', 'PILO_TOPOLOGY_KEY',
  'PILO_EVENT_RULE_NAME', 'PILO_LAMBDA_FUNCTION_NAME', 'PILO_DEPLOY_TFVARS_FILE',
  'PILO_SMOKE_ALARM_ARN'
)) {
  if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($name))) {
    throw 'A required protected input is missing'
  }
}

$account = aws sts get-caller-identity --query Account --output text --region ap-northeast-2 2>$null
if ($LASTEXITCODE -ne 0 -or $account -cne $env:PILO_DEV_ACCOUNT_ID) {
  throw 'AWS account preflight failed'
}
$region = aws configure get region 2>$null
if ($LASTEXITCODE -ne 0 -or $region -cne 'ap-northeast-2') {
  throw 'AWS region preflight failed'
}

$repositoryRootText = (& git rev-parse --show-toplevel 2>$null | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($repositoryRootText)) {
  throw 'Repository root lookup failed'
}
$repositoryRoot = [IO.Path]::GetFullPath($repositoryRootText).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
$repositoryPrefix = $repositoryRoot + [IO.Path]::DirectorySeparatorChar
function Assert-OutsideRepositoryPath([string]$Path, [bool]$MustExist) {
  if ([string]::IsNullOrWhiteSpace($Path) -or -not [IO.Path]::IsPathRooted($Path)) {
    throw 'Protected path must be absolute'
  }
  $pathRoot = [IO.Path]::GetPathRoot($Path)
  if ([string]::IsNullOrWhiteSpace($pathRoot) -or $pathRoot -match '^[A-Za-z]:$' -or $pathRoot -in @('\', '/')) {
    throw 'Protected path must be absolute'
  }
  $absolutePath = [IO.Path]::GetFullPath($Path)
  if ($MustExist) {
    $resolvedPath = (Resolve-Path -LiteralPath $absolutePath -ErrorAction Stop).Path
  } else {
    $parent = Split-Path -Parent $absolutePath
    if ([string]::IsNullOrWhiteSpace($parent)) { throw 'Protected output parent is missing' }
    $resolvedParent = (Resolve-Path -LiteralPath $parent -ErrorAction Stop).Path
    $resolvedPath = Join-Path $resolvedParent (Split-Path -Leaf $absolutePath)
  }
  $fullPath = [IO.Path]::GetFullPath($resolvedPath)
  if ($fullPath -ceq $repositoryRoot -or $fullPath.StartsWith($repositoryPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Protected path must be outside the repository'
  }
  return $fullPath
}

$baselineTopologyFile = Assert-OutsideRepositoryPath $env:PILO_BASELINE_TOPOLOGY_FILE $false
$candidateTopologyFile = Assert-OutsideRepositoryPath $env:PILO_CANDIDATE_TOPOLOGY_FILE $false
$newAlarmMappingsFile = Assert-OutsideRepositoryPath $env:PILO_NEW_ALARM_MAPPINGS_FILE $true
$deployTfvarsFile = Assert-OutsideRepositoryPath $env:PILO_DEPLOY_TFVARS_FILE $true
$routeTempDirectory = Split-Path -Parent $candidateTopologyFile
$savedPlanFile = Join-Path $routeTempDirectory 'application-route.tfplan'
$planJsonFile = Join-Path $routeTempDirectory 'application-route-plan.json'
$eventPatternFile = Join-Path $routeTempDirectory 'application-route-event-pattern.json'
$terraformPlanLog = Join-Path $routeTempDirectory 'application-route-terraform-plan.log'
$terraformShowLog = Join-Path $routeTempDirectory 'application-route-terraform-show.log'
$terraformApplyLog = Join-Path $routeTempDirectory 'application-route-terraform-apply.log'

$terraformLambdaFunctionName = (& terraform -chdir=infra output -raw lambda_function_name 2>$null | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($terraformLambdaFunctionName) -or $terraformLambdaFunctionName -cne $env:PILO_LAMBDA_FUNCTION_NAME) {
  throw 'Lambda deployment binding is invalid'
}
$configuration = aws lambda get-function-configuration --function-name $terraformLambdaFunctionName --region ap-northeast-2 --output json 2>$null | ConvertFrom-Json
if (
  $LASTEXITCODE -ne 0 -or
  $configuration.FunctionName -cne $env:PILO_LAMBDA_FUNCTION_NAME -or
  $configuration.Environment.Variables.PILO_TOPOLOGY_BUCKET -cne $env:PILO_TOPOLOGY_BUCKET -or
  $configuration.Environment.Variables.PILO_TOPOLOGY_KEY -cne $env:PILO_TOPOLOGY_KEY
) {
  throw 'Lambda deployment binding is invalid'
}
~~~

## 1. topology를 먼저 갱신하고 checksum 확인

보호된 additions JSON은 정확히 8개 mapping이어야 한다. baseline topology는 synthetic smoke mapping을
포함해 정확히 27개이고, candidate topology는 정확히 35개여야 한다. 이 중 EventBridge 활성 경로는
각각 26개와 34개이며, `$env:PILO_SMOKE_ALARM_ARN`은 두 경로 집합에 포함되면 안 된다. validator가 이를
확인하므로 count나 mapping을 수동으로 수정하지 않는다. 아래 생성물은 모두 저장소 밖 보호
임시 artifact여야 하며, 실제 topology나 identifier를 저장소에 추가하지 않는다. 위 사전 점검에서
Terraform Lambda 이름이나 배포 Lambda의 topology bucket/key가 보호 입력과 다르면 upload와 plan을
실행하지 않는다.

~~~powershell
aws s3api get-object --bucket $env:PILO_TOPOLOGY_BUCKET --key $env:PILO_TOPOLOGY_KEY --region ap-northeast-2 $baselineTopologyFile 1>$null 2>$null
if ($LASTEXITCODE -ne 0) { throw 'Protected topology download failed' }
if (-not (Test-Path -LiteralPath $baselineTopologyFile -PathType Leaf)) { throw 'Protected topology download output is missing' }
python scripts/verify_application_alarm_route.py build-candidate --baseline $baselineTopologyFile --additions $newAlarmMappingsFile --output $candidateTopologyFile --non-routed-alarm $env:PILO_SMOKE_ALARM_ARN *> $null
if ($LASTEXITCODE -ne 0) { throw 'Protected topology candidate build failed' }
python scripts/verify_application_alarm_route.py validate-transition --baseline $baselineTopologyFile --candidate $candidateTopologyFile --additions $newAlarmMappingsFile --non-routed-alarm $env:PILO_SMOKE_ALARM_ARN *> $null
if ($LASTEXITCODE -ne 0) { throw 'Protected topology transition failed' }
aws s3api put-object --bucket $env:PILO_TOPOLOGY_BUCKET --key $env:PILO_TOPOLOGY_KEY --body $candidateTopologyFile --server-side-encryption AES256 --checksum-algorithm SHA256 --region ap-northeast-2 1>$null 2>$null
if ($LASTEXITCODE -ne 0) { throw 'Protected topology upload failed' }

$sha256 = [Security.Cryptography.SHA256]::Create()
try {
  $localTopologyChecksum = [Convert]::ToBase64String($sha256.ComputeHash([IO.File]::ReadAllBytes($candidateTopologyFile)))
} finally {
  $sha256.Dispose()
}
$topologyHead = aws s3api head-object --bucket $env:PILO_TOPOLOGY_BUCKET --key $env:PILO_TOPOLOGY_KEY --checksum-mode ENABLED --region ap-northeast-2 --output json 2>$null | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or $topologyHead.ServerSideEncryption -cne 'AES256' -or [int64]$topologyHead.ContentLength -lt 1 -or $topologyHead.ChecksumSHA256 -cne $localTopologyChecksum) {
  throw 'Protected topology checksum verification failed'
}
~~~

## 2. full saved plan을 검증한 뒤 동일 파일만 적용

보호 tfvars는 정확히 34개 Alarm, `event_route_enabled=true`,
`operating_mode="snapshot_only"`, `lambda_reserved_concurrency=2`를 제공해야 한다.
artifact를 재현 빌드한 뒤 현재 Lambda의 `CodeSha256`가 로컬 zip checksum과 다르면
drift로 보고 plan 전에 중단한다. `application-route.tfplan`은 full plan이며 partial plan을
만들거나 적용하지 않는다. EventBridge rule 외 변경이 보이면 validator 결과와 무관하게
중단한다.

~~~powershell
python scripts/build_lambda.py *> $null
if ($LASTEXITCODE -ne 0) { throw 'Lambda artifact build failed' }
$sha256 = [Security.Cryptography.SHA256]::Create()
try {
  $localLambdaChecksum = [Convert]::ToBase64String($sha256.ComputeHash([IO.File]::ReadAllBytes('dist/pilo-incident-investigator.zip')))
} finally {
  $sha256.Dispose()
}
$deployedLambdaChecksum = aws lambda get-function --function-name $terraformLambdaFunctionName --query Configuration.CodeSha256 --output text --region ap-northeast-2 2>$null
if ($LASTEXITCODE -ne 0 -or $deployedLambdaChecksum -cne $localLambdaChecksum) {
  throw 'Lambda artifact differs from the deployed function'
}

terraform -chdir=infra plan -input=false -var-file=$deployTfvarsFile -out=$savedPlanFile *> $terraformPlanLog
if ($LASTEXITCODE -ne 0) { throw 'Terraform plan failed' }
$planJson = terraform -chdir=infra show -json $savedPlanFile 2>$terraformShowLog
if ($LASTEXITCODE -ne 0) { throw 'Terraform plan JSON export failed' }
[IO.File]::WriteAllText($planJsonFile, $planJson, [Text.UTF8Encoding]::new($false))
python scripts/verify_application_alarm_route.py validate-plan --baseline $baselineTopologyFile --candidate $candidateTopologyFile --plan $planJsonFile --non-routed-alarm $env:PILO_SMOKE_ALARM_ARN *> $null
if ($LASTEXITCODE -ne 0) { throw 'Terraform plan scope validation failed' }
terraform -chdir=infra apply -input=false $savedPlanFile *> $terraformApplyLog
if ($LASTEXITCODE -ne 0) { throw 'Terraform apply failed' }
~~~

## 3. read-only 사후 검증

자연 발생 EventBridge event가 없다고 구성 실패로 판단하지 않는다. 아래 검증은 read-only이며
실제 Alarm 상태를 바꾸지 않는다.

~~~powershell
$rule = aws events describe-rule --name $env:PILO_EVENT_RULE_NAME --region ap-northeast-2 --output json 2>$null | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or $rule.State -cne 'ENABLED' -or [string]::IsNullOrWhiteSpace($rule.EventPattern)) { throw 'EventBridge rule inspection failed' }
$eventPattern = $rule.EventPattern
[IO.File]::WriteAllText($eventPatternFile, $eventPattern, [Text.UTF8Encoding]::new($false))
python scripts/verify_application_alarm_route.py validate-event-pattern --candidate $candidateTopologyFile --pattern $eventPatternFile --non-routed-alarm $env:PILO_SMOKE_ALARM_ARN *> $null
if ($LASTEXITCODE -ne 0) { throw 'EventBridge event pattern validation failed' }

$terraformLambdaFunctionName = (& terraform -chdir=infra output -raw lambda_function_name 2>$null | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $terraformLambdaFunctionName -cne $env:PILO_LAMBDA_FUNCTION_NAME) { throw 'Terraform Lambda name output is invalid' }
$configuration = aws lambda get-function-configuration --function-name $terraformLambdaFunctionName --region ap-northeast-2 --output json 2>$null | ConvertFrom-Json
if (
  $LASTEXITCODE -ne 0 -or
  $configuration.FunctionName -cne $terraformLambdaFunctionName -or
  [string]::IsNullOrWhiteSpace($configuration.FunctionArn) -or
  $configuration.Environment.Variables.PILO_MODE -cne 'snapshot_only' -or
  $configuration.Environment.Variables.PILO_TOPOLOGY_BUCKET -cne $env:PILO_TOPOLOGY_BUCKET -or
  $configuration.Environment.Variables.PILO_TOPOLOGY_KEY -cne $env:PILO_TOPOLOGY_KEY
) {
  throw 'Lambda runtime configuration is invalid'
}
$lambdaArn = $configuration.FunctionArn
$listTargetsCommand = 'list' + '-' + 'targets-by-rule'
$targets = & aws events $listTargetsCommand --rule $env:PILO_EVENT_RULE_NAME --region ap-northeast-2 --output json 2>$null | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or @($targets.Targets).Count -ne 1 -or $targets.Targets[0].Arn -cne $lambdaArn) { throw 'EventBridge target binding is invalid' }
foreach ($field in @('Input', 'InputPath', 'InputTransformer')) {
  if ($null -ne $targets.Targets[0].PSObject.Properties[$field]) { throw 'EventBridge target must preserve the original event' }
}
$concurrency = aws lambda get-function-concurrency --function-name $terraformLambdaFunctionName --region ap-northeast-2 --output json 2>$null | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or $null -eq $concurrency.ReservedConcurrentExecutions -or [int]$concurrency.ReservedConcurrentExecutions -ne 2) { throw 'Lambda reserved concurrency is invalid' }
terraform -chdir=infra plan -input=false -detailed-exitcode -var-file=$deployTfvarsFile 1>$null 2>$null
if ($LASTEXITCODE -ne 0) { throw 'Post-apply Terraform plan is not empty' }
~~~

## 4. 성공 후 보호 임시 artifact 정리

모든 사후 검증이 성공한 뒤 candidate, plan JSON, saved tfplan, event pattern 및 Terraform log를
삭제한다. baseline topology는 사용자 결정에 따라 보호 위치에 보존하거나 삭제하며, 명시적인 삭제
결정이 없으면 보존한다.

~~~powershell
foreach ($path in @(
  $candidateTopologyFile, $planJsonFile, $savedPlanFile, $eventPatternFile,
  $terraformPlanLog, $terraformShowLog, $terraformApplyLog
)) {
  if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force }
}
# 사용자가 baseline 삭제를 명시적으로 결정한 경우에만 다음 명령을 별도로 실행한다.
# Remove-Item -LiteralPath $baselineTopologyFile -Force
~~~

## 5. 실패와 rollback 경계

검증 실패 시 자동 rollback하지 않는다. 현재 구성을 추측해 되돌리지 말고, 기존 26개 mapping을
복원하는 별도 saved plan을 생성해 검토한 뒤 사용자 승인을 받아 수동으로 적용한다. 이 절차도
새 candidate topology, checksum 검증, full-plan 검증 및 동일 saved plan 적용의 순서를 따른다.
