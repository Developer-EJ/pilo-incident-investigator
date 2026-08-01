mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "000000000000"
    }
  }

  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
  }
}

variables {
  lambda_zip_path   = "../dist/pilo-incident-investigator.zip"
  alarm_arns        = ["arn:aws:cloudwatch:ap-northeast-2:000000000000:alarm:pilo-dev-service-01"]
  bedrock_model_arn = "arn:aws:bedrock:ap-northeast-2:000000000000:inference-profile/synthetic-model"
  bedrock_foundation_model_arns = [
    "arn:aws:bedrock:ap-northeast-1::foundation-model/synthetic.model-v1",
  ]
  topology_object_key         = "config/pilo-topology.yaml"
  incident_repository         = "synthetic-org/private-incidents"
  github_token_parameter_arn  = "arn:aws:ssm:ap-northeast-2:000000000000:parameter/pilo/investigator/github-token"
  slack_webhook_parameter_arn = "arn:aws:ssm:ap-northeast-2:000000000000:parameter/pilo/investigator/slack-webhook"
  pilo_ecs_cluster_arns       = ["arn:aws:ecs:ap-northeast-2:000000000000:cluster/pilo-dev"]
  pilo_ecs_service_arns = [
    "arn:aws:ecs:ap-northeast-2:000000000000:service/pilo-dev/pilo-dev-service-01",
    "arn:aws:ecs:ap-northeast-2:000000000000:service/pilo-dev/pilo-dev-service-02",
    "arn:aws:ecs:ap-northeast-2:000000000000:service/pilo-dev/pilo-dev-service-03",
    "arn:aws:ecs:ap-northeast-2:000000000000:service/pilo-dev/pilo-dev-service-04",
    "arn:aws:ecs:ap-northeast-2:000000000000:service/pilo-dev/pilo-dev-service-05",
    "arn:aws:ecs:ap-northeast-2:000000000000:service/pilo-dev/pilo-dev-service-06",
    "arn:aws:ecs:ap-northeast-2:000000000000:service/pilo-dev/pilo-dev-service-07",
    "arn:aws:ecs:ap-northeast-2:000000000000:service/pilo-dev/pilo-dev-service-08",
  ]
  pilo_log_group_arns    = ["arn:aws:logs:ap-northeast-2:000000000000:log-group:/aws/ecs/pilo-dev-service-01:*"]
  pilo_target_group_arns = ["arn:aws:elasticloadbalancing:ap-northeast-2:000000000000:targetgroup/pilo-dev-service-01/0000000000000001"]
  pilo_rds_instance_arns = ["arn:aws:rds:ap-northeast-2:000000000000:db:pilo-dev-db-01"]
  pilo_secret_arns       = ["arn:aws:secretsmanager:ap-northeast-2:000000000000:secret:pilo-dev-secret-01-synthetic"]
  pilo_queue_arns        = ["arn:aws:sqs:ap-northeast-2:000000000000:pilo-dev-queue-01"]
}

run "runtime_resources_are_bounded" {
  command = plan

  assert {
    condition     = aws_s3_bucket_lifecycle_configuration.bundle.rule[0].filter[0].prefix == "incidents/"
    error_message = "Only incident bundles may expire after seven days."
  }

  assert {
    condition     = aws_s3_bucket_lifecycle_configuration.bundle.rule[0].expiration[0].days == 7
    error_message = "Incident Bundles must expire after seven days."
  }

  assert {
    condition     = aws_s3_bucket_public_access_block.bundle.block_public_acls && aws_s3_bucket_public_access_block.bundle.block_public_policy && aws_s3_bucket_public_access_block.bundle.ignore_public_acls && aws_s3_bucket_public_access_block.bundle.restrict_public_buckets
    error_message = "The Incident Bundle bucket must block every public access path."
  }

  assert {
    condition     = aws_dynamodb_table.state.billing_mode == "PAY_PER_REQUEST" && aws_dynamodb_table.state.hash_key == "event_id"
    error_message = "The event state table must be on-demand and keyed by event_id."
  }

  assert {
    condition     = aws_lambda_function.investigator.timeout <= 300 && aws_lambda_function.investigator.reserved_concurrent_executions > 0
    error_message = "Lambda execution and concurrency must be explicitly bounded."
  }

  assert {
    condition     = aws_lambda_function.investigator.environment[0].variables.PILO_MODE == "snapshot_only"
    error_message = "The safe deployment default must remain snapshot_only."
  }

  assert {
    condition     = aws_cloudwatch_event_rule.alarm.state == "DISABLED"
    error_message = "The Alarm route must remain disabled until protected topology is uploaded and verified."
  }

  assert {
    condition     = aws_lambda_function.investigator.environment[0].variables.PILO_TOPOLOGY_BUCKET == "pilo-incident-investigator-000000000000-ap-northeast-2"
    error_message = "Protected topology must live in the service-owned private bucket."
  }

  assert {
    condition = anytrue([
      for statement in data.aws_iam_policy_document.runtime.statement :
      statement.sid == "ReadProtectedTopology" && toset(statement.resources) == toset(["arn:aws:s3:::pilo-incident-investigator-000000000000-ap-northeast-2/${var.topology_object_key}"])
    ])
    error_message = "Topology read access must be limited to the exact service-owned object."
  }

  assert {
    condition     = aws_lambda_function.investigator.source_code_hash == filebase64sha256(var.lambda_zip_path)
    error_message = "Terraform must detect Lambda artifact content changes at a stable path."
  }
}

run "hybrid_agent_mode_is_explicitly_supported" {
  command = plan

  variables {
    operating_mode = "hybrid_agent"
  }

  assert {
    condition     = aws_lambda_function.investigator.environment[0].variables.PILO_MODE == "hybrid_agent"
    error_message = "The evaluated hybrid mode must reach the Lambda environment unchanged."
  }
}

run "alarm_route_enablement_is_explicit" {
  command = plan

  variables {
    event_route_enabled = true
  }

  assert {
    condition     = aws_cloudwatch_event_rule.alarm.state == "ENABLED"
    error_message = "The Alarm route must be enabled only by an explicit second-stage input."
  }
}

run "foundation_model_arn_is_supported" {
  command = plan

  variables {
    bedrock_model_arn             = "arn:aws:bedrock:ap-northeast-2::foundation-model/synthetic.model-v1"
    bedrock_foundation_model_arns = []
  }

  assert {
    condition     = aws_lambda_function.investigator.environment[0].variables.PILO_BEDROCK_MODEL_ID == "arn:aws:bedrock:ap-northeast-2::foundation-model/synthetic.model-v1"
    error_message = "AWS foundation-model ARNs have an empty account segment and must remain supported."
  }
}

run "inference_profile_grants_only_associated_foundation_models" {
  command = plan

  assert {
    condition = anytrue([
      for statement in data.aws_iam_policy_document.runtime.statement :
      statement.sid == "InvokeInferenceProfileFoundationModels" && toset(statement.resources) == var.bedrock_foundation_model_arns
    ])
    error_message = "Inference profile invocation must grant its explicitly associated foundation models."
  }
}

run "inference_profile_requires_associated_foundation_models" {
  command = plan

  variables {
    bedrock_foundation_model_arns = []
  }

  expect_failures = [var.bedrock_foundation_model_arns]
}

run "wildcard_topology_key_is_rejected" {
  command = plan

  variables {
    topology_object_key = "config/*"
  }

  expect_failures = [var.topology_object_key]
}

run "expiring_topology_key_is_rejected" {
  command = plan

  variables {
    topology_object_key = "incidents/pilo-topology.yaml"
  }

  expect_failures = [var.topology_object_key]
}

run "wildcard_pilo_resource_arn_is_rejected" {
  command = plan

  variables {
    pilo_secret_arns = ["arn:aws:secretsmanager:ap-northeast-2:000000000000:secret:*"]
  }

  expect_failures = [var.pilo_secret_arns]
}

run "invalid_operating_mode_is_rejected" {
  command = plan

  variables {
    operating_mode = "automatic"
  }

  expect_failures = [var.operating_mode]
}
