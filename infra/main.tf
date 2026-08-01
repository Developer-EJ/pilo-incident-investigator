data "aws_caller_identity" "current" {}

locals {
  function_name                  = "${var.project_name}-dev"
  bundle_bucket_name             = "${var.project_name}-${data.aws_caller_identity.current.account_id}-${var.aws_region}"
  event_rule_name                = "${var.project_name}-alarm-dev"
  state_table_name               = "${var.project_name}-state-dev"
  github_parameter               = var.github_token_parameter_arn
  slack_parameter                = var.slack_webhook_parameter_arn
  lambda_handler_name            = "pilo_incident_investigator.handler.lambda_handler"
  bedrock_uses_inference_profile = can(regex(":(inference-profile|application-inference-profile)/", var.bedrock_model_arn))
  synthetic_smoke_alarm_arn      = "arn:aws:cloudwatch:ap-northeast-2:${data.aws_caller_identity.current.account_id}:alarm:pilo-incident-investigator-dev-smoke"
  unreserved_smoke_exception = (
    var.lambda_reserved_concurrency == -1 &&
    var.operating_mode == "snapshot_only" &&
    var.alarm_arns == toset([local.synthetic_smoke_alarm_arn])
  )
}

resource "aws_s3_bucket" "bundle" {
  bucket        = local.bundle_bucket_name
  force_destroy = false
}

resource "aws_s3_bucket_public_access_block" "bundle" {
  bucket = aws_s3_bucket.bundle.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "bundle" {
  bucket = aws_s3_bucket.bundle.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "bundle" {
  bucket = aws_s3_bucket.bundle.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "bundle" {
  bucket = aws_s3_bucket.bundle.id

  rule {
    id     = "expire-incident-bundles-after-seven-days"
    status = "Enabled"

    filter {
      prefix = "incidents/"
    }

    expiration {
      days = 7
    }
  }
}

resource "aws_dynamodb_table" "state" {
  name         = local.state_table_name
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "event_id"

  attribute {
    name = "event_id"
    type = "S"
  }

  point_in_time_recovery {
    enabled = true
  }
}

resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${local.function_name}"
  retention_in_days = 30
}

resource "aws_lambda_function" "investigator" {
  function_name = local.function_name
  description   = "Evidence-based initial incident investigation for PILO dev"
  role          = aws_iam_role.lambda.arn
  runtime       = "python3.12"
  handler       = local.lambda_handler_name
  architectures = ["x86_64"]

  filename         = var.lambda_zip_path
  source_code_hash = filebase64sha256(var.lambda_zip_path)

  memory_size                    = 512
  timeout                        = 300
  reserved_concurrent_executions = var.lambda_reserved_concurrency

  environment {
    variables = {
      PILO_REGION                  = var.aws_region
      PILO_TOPOLOGY_BUCKET         = local.bundle_bucket_name
      PILO_TOPOLOGY_KEY            = var.topology_object_key
      PILO_STATE_TABLE             = aws_dynamodb_table.state.name
      PILO_BUNDLE_BUCKET           = aws_s3_bucket.bundle.id
      PILO_GITHUB_REPOSITORY       = var.incident_repository
      PILO_GITHUB_TOKEN_PARAMETER  = local.github_parameter
      PILO_SLACK_WEBHOOK_PARAMETER = local.slack_parameter
      PILO_BEDROCK_MODEL_ID        = var.bedrock_model_arn
      PILO_MODE                    = var.operating_mode
    }
  }

  # The route must be created or updated to DISABLED before any Lambda binding change.
  depends_on = [aws_cloudwatch_log_group.lambda, aws_cloudwatch_event_rule.alarm]

  lifecycle {
    precondition {
      condition     = var.github_token_parameter_arn != var.slack_webhook_parameter_arn
      error_message = "GitHub and Slack must use two distinct existing SSM parameters."
    }

    precondition {
      condition     = var.lambda_reserved_concurrency > 0 || local.unreserved_smoke_exception
      error_message = "Unreserved Lambda concurrency is allowed only for the exact snapshot-only synthetic smoke Alarm."
    }
  }
}

resource "aws_cloudwatch_event_rule" "alarm" {
  name        = local.event_rule_name
  description = "Route existing PILO dev Alarm state changes to the investigator"
  state       = var.event_route_enabled ? "ENABLED" : "DISABLED"

  event_pattern = jsonencode({
    source      = ["aws.cloudwatch"]
    detail-type = ["CloudWatch Alarm State Change"]
    region      = [var.aws_region]
    resources   = sort(tolist(var.alarm_arns))
    detail = {
      state = {
        value = ["ALARM"]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "lambda" {
  rule = aws_cloudwatch_event_rule.alarm.name
  arn  = aws_lambda_function.investigator.arn

  retry_policy {
    maximum_event_age_in_seconds = 3600
    maximum_retry_attempts       = 2
  }
}

resource "aws_lambda_permission" "eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.investigator.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.alarm.arn
}
