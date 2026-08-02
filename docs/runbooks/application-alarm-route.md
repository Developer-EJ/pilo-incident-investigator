# PILO dev application Alarm route 적용 runbook

이 runbook은 PILO dev(`ap-northeast-2`)의 기존 26개 Alarm 경로에 승인된 8개 mapping만
추가해 정확히 34개 Alarm을 EventBridge rule로 라우팅한다. 적용 전 topology를 먼저
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
  'PILO_EVENT_RULE_NAME', 'PILO_LAMBDA_FUNCTION_NAME', 'PILO_DEPLOY_TFVARS_FILE'
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
~~~

## 1. topology를 먼저 갱신하고 checksum 확인

보호된 additions JSON은 정확히 8개 mapping이어야 한다. baseline은 정확히 26개이고,
candidate는 baseline과 additions의 합집합인 정확히 34개여야 한다. validator가 이를
확인하므로 count나 mapping을 수동으로 수정하지 않는다. 아래 생성물은 모두 ignored
temporary file이어야 하며, 실제 topology나 identifier를 저장소에 추가하지 않는다.

~~~powershell
foreach ($path in @($env:PILO_CANDIDATE_TOPOLOGY_FILE, 'infra/application-route.tfplan', 'application-route-plan.json', 'application-route-event-pattern.json')) {
  git check-ignore -q $path
  if ($LASTEXITCODE -ne 0) { throw 'Temporary route artifact must be ignored' }
}

aws s3api get-object --bucket $env:PILO_TOPOLOGY_BUCKET --key $env:PILO_TOPOLOGY_KEY --region ap-northeast-2 $env:PILO_BASELINE_TOPOLOGY_FILE 1>$null 2>$null
if ($LASTEXITCODE -ne 0) { throw 'Protected topology download failed' }
python scripts/verify_application_alarm_route.py build-candidate --baseline $env:PILO_BASELINE_TOPOLOGY_FILE --additions $env:PILO_NEW_ALARM_MAPPINGS_FILE --output $env:PILO_CANDIDATE_TOPOLOGY_FILE *> $null
if ($LASTEXITCODE -ne 0) { throw 'Protected topology candidate build failed' }
python scripts/verify_application_alarm_route.py validate-transition --baseline $env:PILO_BASELINE_TOPOLOGY_FILE --candidate $env:PILO_CANDIDATE_TOPOLOGY_FILE --additions $env:PILO_NEW_ALARM_MAPPINGS_FILE *> $null
if ($LASTEXITCODE -ne 0) { throw 'Protected topology transition failed' }
aws s3api put-object --bucket $env:PILO_TOPOLOGY_BUCKET --key $env:PILO_TOPOLOGY_KEY --body $env:PILO_CANDIDATE_TOPOLOGY_FILE --server-side-encryption AES256 --checksum-algorithm SHA256 --region ap-northeast-2 1>$null 2>$null
if ($LASTEXITCODE -ne 0) { throw 'Protected topology upload failed' }

$sha256 = [Security.Cryptography.SHA256]::Create()
try {
  $localTopologyChecksum = [Convert]::ToBase64String($sha256.ComputeHash([IO.File]::ReadAllBytes($env:PILO_CANDIDATE_TOPOLOGY_FILE)))
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
$deployedLambdaChecksum = aws lambda get-function --function-name $env:PILO_LAMBDA_FUNCTION_NAME --query Configuration.CodeSha256 --output text --region ap-northeast-2 2>$null
if ($LASTEXITCODE -ne 0 -or $deployedLambdaChecksum -cne $localLambdaChecksum) {
  throw 'Lambda artifact differs from the deployed function'
}

terraform -chdir=infra plan -input=false -var-file=$env:PILO_DEPLOY_TFVARS_FILE -out=application-route.tfplan
if ($LASTEXITCODE -ne 0) { throw 'Terraform plan failed' }
terraform -chdir=infra show -json application-route.tfplan | Out-File -Encoding utf8 application-route-plan.json
if ($LASTEXITCODE -ne 0) { throw 'Terraform plan JSON export failed' }
python scripts/verify_application_alarm_route.py validate-plan --baseline $env:PILO_BASELINE_TOPOLOGY_FILE --candidate $env:PILO_CANDIDATE_TOPOLOGY_FILE --plan application-route-plan.json *> $null
if ($LASTEXITCODE -ne 0) { throw 'Terraform plan scope validation failed' }
terraform -chdir=infra apply -input=false application-route.tfplan
if ($LASTEXITCODE -ne 0) { throw 'Terraform apply failed' }
~~~

## 3. read-only 사후 검증

자연 발생 EventBridge event가 없다고 구성 실패로 판단하지 않는다. 아래 검증은 read-only이며
실제 Alarm 상태를 바꾸지 않는다.

~~~powershell
$eventPattern = aws events describe-rule --name $env:PILO_EVENT_RULE_NAME --query EventPattern --output text --region ap-northeast-2 2>$null
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($eventPattern)) { throw 'EventBridge rule inspection failed' }
[IO.File]::WriteAllText('application-route-event-pattern.json', $eventPattern, [Text.UTF8Encoding]::new($false))
python scripts/verify_application_alarm_route.py validate-event-pattern --candidate $env:PILO_CANDIDATE_TOPOLOGY_FILE --pattern application-route-event-pattern.json *> $null
if ($LASTEXITCODE -ne 0) { throw 'EventBridge event pattern validation failed' }

$lambdaArn = terraform -chdir=infra output -raw lambda_function_arn 2>$null
if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($lambdaArn)) { throw 'Terraform Lambda ARN output failed' }
$listTargetsCommand = 'list' + '-' + 'targets-by-rule'
$targets = & aws events $listTargetsCommand --rule $env:PILO_EVENT_RULE_NAME --region ap-northeast-2 --output json 2>$null | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or @($targets.Targets).Count -ne 1 -or $targets.Targets[0].Arn -cne $lambdaArn) { throw 'EventBridge target binding is invalid' }
foreach ($field in @('Input', 'InputPath', 'InputTransformer')) {
  if ($null -ne $targets.Targets[0].PSObject.Properties[$field]) { throw 'EventBridge target must preserve the original event' }
}
$configuration = aws lambda get-function-configuration --function-name $env:PILO_LAMBDA_FUNCTION_NAME --region ap-northeast-2 --output json 2>$null | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or $configuration.Environment.Variables.PILO_MODE -cne 'snapshot_only' -or [int]$configuration.ReservedConcurrentExecutions -ne 2) {
  throw 'Lambda runtime configuration is invalid'
}
terraform -chdir=infra plan -input=false -detailed-exitcode -var-file=$env:PILO_DEPLOY_TFVARS_FILE 1>$null 2>$null
if ($LASTEXITCODE -ne 0) { throw 'Post-apply Terraform plan is not empty' }
~~~

## 4. 실패와 rollback 경계

검증 실패 시 자동 rollback하지 않는다. 현재 구성을 추측해 되돌리지 말고, 기존 26개 mapping을
복원하는 별도 saved plan을 생성해 검토한 뒤 사용자 승인을 받아 수동으로 적용한다. 이 절차도
새 candidate topology, checksum 검증, full-plan 검증 및 동일 saved plan 적용의 순서를 따른다.
