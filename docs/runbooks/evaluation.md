# 평가 실행 Runbook

이 절차는 익명화된 21개 fixture에서 `snapshot_only`와 `hybrid_agent`를 비교하고, raw Alarm과 Incident Brief의 Codex handoff 구조를 회귀 검사한다. 기본 경로는 관찰 가능한 Alarm·Snapshot·recorded Tool 데이터로 만든 결정적 중립 출력을 replay하는 `offline_neutral_recording` harness이며 AWS, Bedrock, GitHub, Slack을 호출하지 않는다.

Offline neutral regression은 실제 모델 평가가 아니다. 보고서의 `model_called=false`는 모델을 호출하지 않았다는 뜻이다. 따라서 latency, input/output token, estimated cost의 `0`은 좋은 성능이나 무료 실행이 아니라 **미측정** 상태다. Offline 결과만으로 실제 모델의 품질·속도·비용·안전성을 주장하지 않는다.

## Offline 평가

저장소 루트에서 Python 3.12 개발 의존성을 설치한 뒤 다음 명령을 실행한다.

```shell
make eval
```

이 명령은 fixture 검증과 offline neutral 회귀 테스트를 실행한 다음 정확히 21×2 investigation run과 21×2 handoff run을 생성한다. JSON, Markdown, stdout에는 `execution_kind=offline_neutral_recording`, `model_called=false`, 미측정 경고가 함께 기록된다. stdout에는 fixture별 내용이 아닌 aggregate metric과 gate 결과만 출력된다. 상세 결과는 다음 두 파일에 기록되며 기본적으로 Git ignore 대상이다.

- `reports/eval-YYYYMMDDTHHMMSSZ.json`
- `reports/eval-YYYYMMDDTHHMMSSZ.md`

동일 timestamp의 `.eval-YYYYMMDDTHHMMSSZ.complete` marker가 있고, marker에 기록된 SHA-256이 두 nonempty final 파일과 모두 일치하는 pair만 유효하다. Marker는 JSON과 Markdown이 모두 게시된 뒤 마지막으로 생성된다. `KeyboardInterrupt`나 `SystemExit`처럼 잡을 수 있는 중단은 해당 실행이 만든 final/temp/lock/marker를 정리한다. 프로세스 강제 종료나 전원 손실은 cleanup할 수 없으므로 marker가 없거나 hash가 맞지 않는 final-looking 파일은 incomplete crash residue이며 보고서나 baseline으로 취급하지 않는다.

연속 offline 실행은 생성 시각을 제외한 metric 내용이 같아야 한다. JSON의 `operating_mode`와 Markdown의 `운영 권장 모드`를 확인하고, 이어지는 모든 gate reason의 PASS/FAIL을 함께 검토한다. Hybrid의 안전성과 개선을 모두 입증하지 못하면 권장 모드는 `snapshot_only`다.

보고서 metadata와 stdout의 `git_dirty`, `source_fixture_digest`, `baseline_eligible`를 함께 확인한다. `git_commit`은 exact HEAD만 기록하며 dirty suffix를 붙이지 않는다. Digest는 평가 Python source, `scripts/run_eval.py`, fixture YAML의 relative path와 content를 stable hash한 provenance다. Fixture expected oracle도 이 content hash에는 포함되지만 evaluated output 합성에는 사용되지 않는다. Relevant tracked·staged·untracked 변경이 있으면 `git_dirty=true`, `baseline_eligible=false`이며 보고서에는 baseline 부적격으로 표시된다. Ignore된 report 파일은 dirty 판정에서 제외한다.

전체 read-only 검증 계약은 다음과 같다.

```shell
make verify
```

이 명령은 `check`, `test`, `eval`, `terraform-check`를 실행한다. Terraform 단계는 format, backend 없는 init, validate, native test, IAM·소유권 검사까지만 수행하며 `plan`이나 `apply`를 실행하지 않는다.

## Live Bedrock 평가 승인 조건

Actual live model evaluation만 모델 품질·속도·token·비용을 측정할 수 있다. Live 평가는 비용과 외부 호출이 발생하므로 사람의 명시적 사전 승인이 필요하다. 승인 시에도 model 또는 inference profile ID를 실행 전체에서 고정하고, input/output 100만 token당 단가를 명시해야 한다. 허용되는 명령 형태는 다음 하나뿐이다.

```shell
python scripts/run_eval.py --live-bedrock --model-id "$PILO_BEDROCK_MODEL_ID" --input-cost-per-million "$PILO_BEDROCK_INPUT_RATE" --output-cost-per-million "$PILO_BEDROCK_OUTPUT_RATE" --acknowledge-cost
```

현재 CLI는 비용 승인, 고정 model ID, 두 token rate를 모두 검사하지만 안전한 strict structured investigation·`HandoffOutput` production adapter가 없으므로 live 호출을 fail-closed로 거부한다. 이 adapter와 별도 승인 절차가 구현되기 전에는 우회하거나 임시 Bedrock 호출을 추가하지 않는다.

## 민감 정보와 결과 검토

renderer는 모든 문자열을 redaction한 뒤 JSON과 Markdown을 쓴다. 그래도 보고서를 공유하거나 baseline으로 커밋하기 전에는 사람이 다음 항목을 직접 검토한다.

- 실제 계정 식별자, 로그, Secret, token, 자격 증명, webhook URL이 없는가
- unsupported claim과 Evidence ID 인용이 올바른가
- unknown·composite 사례가 억지로 분류되지 않았는가
- model ID, token 수, 명시 단가, 예상 비용이 기록됐는가
- 선택된 운영 모드와 모든 gate reason이 결과와 일치하는가

유효한 completion marker가 있고, relevant working tree가 clean이며, `baseline_eligible=true`인 결과만 baseline 검토 후보가 된다. 이 기술 조건만으로 자동 승인되지 않으며 사람이 익명화·비용 metadata·unsupported claim·운영 모드를 모두 검토해야 한다. 검토를 마친 익명화 baseline만 `fixtures/eval/baselines/` 아래에 의도적으로 커밋할 수 있다. 실제 Incident Bundle이나 실제 Incident Issue 내용은 공개 저장소에 넣지 않는다.

## 절대 금지

평가 과정에서 Terraform `apply`, 배포, 재시작, 롤백, 복구, 운영 리소스 변경을 실행하지 않는다. AWS Secrets Manager `GetSecretValue`를 호출하지 않고, topology allowlist 밖 리소스를 조회하지 않는다. Live 출력에서 민감 정보가 발견되거나 Tool이 범위 밖 요청을 시도하면 즉시 중단하고 결과를 게시하거나 커밋하지 않는다.
