data "aws_iam_policy_document" "lambda_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda" {
  name               = "${local.function_name}-runtime"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
}

data "aws_iam_policy_document" "runtime" {
  statement {
    sid       = "WriteOwnedLogs"
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.lambda.arn}:*"]
  }

  statement {
    sid       = "ReadProtectedTopology"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::${local.bundle_bucket_name}/${var.topology_object_key}"]
  }

  statement {
    sid       = "WriteOwnedIncidentBundles"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.bundle.arn}/incidents/*"]
  }

  statement {
    sid    = "WriteOwnedIncidentState"
    effect = "Allow"
    actions = [
      "dynamodb:GetItem",
      "dynamodb:PutItem",
      "dynamodb:UpdateItem",
    ]
    resources = [aws_dynamodb_table.state.arn]
  }

  statement {
    sid       = "ReadExactlyTwoCredentials"
    effect    = "Allow"
    actions   = ["ssm:GetParameter"]
    resources = [var.github_token_parameter_arn, var.slack_webhook_parameter_arn]
  }

  statement {
    sid       = "InvokeApprovedBedrockModel"
    effect    = "Allow"
    actions   = ["bedrock:InvokeModel"]
    resources = [var.bedrock_model_arn]
  }

  dynamic "statement" {
    for_each = local.bedrock_uses_inference_profile ? [1] : []

    content {
      sid       = "InvokeInferenceProfileFoundationModels"
      effect    = "Allow"
      actions   = ["bedrock:InvokeModel"]
      resources = var.bedrock_foundation_model_arns

      condition {
        test     = "ArnEquals"
        variable = "bedrock:InferenceProfileArn"
        values   = [var.bedrock_model_arn]
      }
    }
  }

  statement {
    sid       = "ReadAllowlistedEcsServices"
    effect    = "Allow"
    actions   = ["ecs:DescribeServices"]
    resources = var.pilo_ecs_service_arns
  }

  statement {
    sid       = "ReadAllowlistedEcsTasks"
    effect    = "Allow"
    actions   = ["ecs:DescribeTasks"]
    resources = [for arn in var.pilo_ecs_cluster_arns : "${replace(arn, ":cluster/", ":task/")}/*"]
  }

  # ECS ListTasks requires wildcard Resource; both region and cluster remain bounded.
  statement {
    sid       = "ListTasksInAllowlistedClusters"
    effect    = "Allow"
    actions   = ["ecs:ListTasks"]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = ["ap-northeast-2"]
    }

    condition {
      test     = "ArnEquals"
      variable = "ecs:cluster"
      values   = var.pilo_ecs_cluster_arns
    }
  }

  statement {
    sid       = "ReadAllowlistedApplicationLogs"
    effect    = "Allow"
    actions   = ["logs:FilterLogEvents"]
    resources = var.pilo_log_group_arns
  }

  statement {
    sid       = "ReadAllowlistedTargetHealth"
    effect    = "Allow"
    actions   = ["elasticloadbalancing:DescribeTargetHealth"]
    resources = var.pilo_target_group_arns
  }

  statement {
    sid       = "ReadAllowlistedRdsInstances"
    effect    = "Allow"
    actions   = ["rds:DescribeDBInstances"]
    resources = var.pilo_rds_instance_arns
  }

  # RDS DescribeEvents has no resource type in the AWS authorization model.
  statement {
    sid       = "ReadRegionalRdsEvents"
    effect    = "Allow"
    actions   = ["rds:DescribeEvents"]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = ["ap-northeast-2"]
    }
  }

  statement {
    sid       = "ReadAllowlistedSecretMetadata"
    effect    = "Allow"
    actions   = ["secretsmanager:DescribeSecret"]
    resources = var.pilo_secret_arns
  }

  statement {
    sid       = "ReadAllowlistedQueueStatus"
    effect    = "Allow"
    actions   = ["sqs:GetQueueAttributes"]
    resources = var.pilo_queue_arns
  }
}

resource "aws_iam_role_policy" "runtime" {
  name   = "${local.function_name}-runtime"
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.runtime.json
}
