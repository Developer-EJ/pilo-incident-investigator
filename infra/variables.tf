variable "project_name" {
  description = "Stable prefix for service-owned resources."
  type        = string
  default     = "pilo-incident-investigator"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{2,47}$", var.project_name))
    error_message = "project_name must be a bounded lowercase resource prefix."
  }
}

variable "aws_region" {
  description = "The only supported PILO dev region."
  type        = string
  default     = "ap-northeast-2"

  validation {
    condition     = var.aws_region == "ap-northeast-2"
    error_message = "PILO Incident Investigator is restricted to ap-northeast-2."
  }
}

variable "lambda_zip_path" {
  description = "Path to the deterministic Lambda artifact produced by the packaging task."
  type        = string

  validation {
    condition     = endswith(var.lambda_zip_path, ".zip") && !strcontains(var.lambda_zip_path, "..\\")
    error_message = "lambda_zip_path must name a zip artifact."
  }
}

variable "lambda_reserved_concurrency" {
  description = "Reserved Lambda concurrency; -1 is allowed only for the exact snapshot-only synthetic smoke route."
  type        = number
  default     = 2

  validation {
    condition = (
      var.lambda_reserved_concurrency == -1 ||
      (var.lambda_reserved_concurrency >= 1 && var.lambda_reserved_concurrency <= 1000 && floor(var.lambda_reserved_concurrency) == var.lambda_reserved_concurrency)
    )
    error_message = "lambda_reserved_concurrency must be -1 or an integer from 1 through 1000."
  }
}

variable "alarm_arns" {
  description = "Existing PILO dev CloudWatch Alarm ARNs routed to this service."
  type        = set(string)

  validation {
    condition = length(var.alarm_arns) > 0 && alltrue([
      for arn in var.alarm_arns : startswith(arn, "arn:aws:cloudwatch:ap-northeast-2:") && strcontains(arn, ":alarm:") && !strcontains(arn, "*") && !strcontains(arn, "?")
    ])
    error_message = "alarm_arns must contain only PILO dev Alarm ARNs in ap-northeast-2."
  }
}

variable "bedrock_model_arn" {
  description = "One approved Bedrock model or inference profile ARN."
  type        = string

  validation {
    condition = can(regex("^arn:aws:bedrock:ap-northeast-2::foundation-model/[^[:space:]*?]+$", var.bedrock_model_arn)) || can(regex(
      "^arn:aws:bedrock:ap-northeast-2:[0-9]{12}:(inference-profile|application-inference-profile)/[^[:space:]*?]+$",
      var.bedrock_model_arn,
    ))
    error_message = "bedrock_model_arn must be one bounded Bedrock ARN in ap-northeast-2."
  }
}

variable "bedrock_foundation_model_arns" {
  description = "Foundation model ARNs associated with an approved inference profile; empty for direct model invocation."
  type        = set(string)
  default     = []

  validation {
    condition = alltrue([
      for arn in var.bedrock_foundation_model_arns : can(regex("^arn:aws:bedrock:[a-z0-9-]+::foundation-model/[^[:space:]*?]+$", arn))
    ])
    error_message = "bedrock_foundation_model_arns must contain only concrete foundation model ARNs."
  }

  validation {
    condition = (
      can(regex(":(inference-profile|application-inference-profile)/", var.bedrock_model_arn))
      ? length(var.bedrock_foundation_model_arns) > 0
      : length(var.bedrock_foundation_model_arns) == 0
    )
    error_message = "Inference profiles require associated foundation model ARNs; direct foundation models require an empty set."
  }
}

variable "topology_object_key" {
  description = "Protected pilo-topology.yaml key in the service-owned private bucket."
  type        = string

  validation {
    condition     = length(var.topology_object_key) > 0 && length(var.topology_object_key) <= 1024 && !startswith(var.topology_object_key, "/") && !startswith(var.topology_object_key, "incidents/") && !strcontains(var.topology_object_key, "..") && !strcontains(var.topology_object_key, "\\") && !strcontains(var.topology_object_key, "*") && !strcontains(var.topology_object_key, "?")
    error_message = "topology_object_key must be a bounded relative S3 key outside the expiring incidents/ prefix."
  }
}

variable "event_route_enabled" {
  description = "Enable the Alarm route only after the protected topology object is uploaded and verified."
  type        = bool
  default     = false
}

variable "incident_repository" {
  description = "Existing private GitHub incident repository in owner/name form."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$", var.incident_repository)) && !endswith(var.incident_repository, "/.") && !endswith(var.incident_repository, "/..")
    error_message = "incident_repository must be a concrete owner/name repository."
  }
}

variable "github_token_parameter_arn" {
  description = "Existing service-only SSM SecureString ARN for the GitHub token."
  type        = string

  validation {
    condition     = can(regex("^arn:aws:ssm:ap-northeast-2:[0-9]{12}:parameter/[A-Za-z0-9_.\\-/]+$", var.github_token_parameter_arn))
    error_message = "github_token_parameter_arn must be one SSM parameter ARN."
  }
}

variable "slack_webhook_parameter_arn" {
  description = "Existing service-only SSM SecureString ARN for the Slack webhook."
  type        = string

  validation {
    condition     = can(regex("^arn:aws:ssm:ap-northeast-2:[0-9]{12}:parameter/[A-Za-z0-9_.\\-/]+$", var.slack_webhook_parameter_arn))
    error_message = "slack_webhook_parameter_arn must be one SSM parameter ARN."
  }
}

variable "operating_mode" {
  description = "Runtime mode; hybrid_agent requires the separate evaluation gate."
  type        = string
  default     = "snapshot_only"

  validation {
    condition     = contains(["snapshot_only", "hybrid_agent"], var.operating_mode)
    error_message = "operating_mode must be snapshot_only or hybrid_agent."
  }
}

variable "pilo_ecs_cluster_arns" {
  description = "Existing allowlisted PILO dev ECS cluster ARNs."
  type        = set(string)

  validation {
    condition     = length(var.pilo_ecs_cluster_arns) > 0 && alltrue([for arn in var.pilo_ecs_cluster_arns : can(regex("^arn:aws:ecs:ap-northeast-2:[0-9]{12}:cluster/[^*?]+$", arn))])
    error_message = "pilo_ecs_cluster_arns must contain concrete dev cluster ARNs."
  }
}

variable "pilo_ecs_service_arns" {
  description = "The eight existing allowlisted PILO dev ECS service ARNs."
  type        = set(string)

  validation {
    condition     = length(var.pilo_ecs_service_arns) == 8 && alltrue([for arn in var.pilo_ecs_service_arns : can(regex("^arn:aws:ecs:ap-northeast-2:[0-9]{12}:service/[^*?]+$", arn))])
    error_message = "pilo_ecs_service_arns must contain exactly eight concrete service ARNs."
  }
}

variable "pilo_log_group_arns" {
  description = "Existing allowlisted PILO application log group ARNs."
  type        = set(string)

  validation {
    condition     = length(var.pilo_log_group_arns) > 0 && alltrue([for arn in var.pilo_log_group_arns : can(regex("^arn:aws:logs:ap-northeast-2:[0-9]{12}:log-group:[^*?]+:\\*$", arn))])
    error_message = "pilo_log_group_arns must contain concrete log group stream ARNs."
  }
}

variable "pilo_target_group_arns" {
  description = "Existing allowlisted PILO ALB target group ARNs."
  type        = set(string)

  validation {
    condition     = length(var.pilo_target_group_arns) > 0 && alltrue([for arn in var.pilo_target_group_arns : can(regex("^arn:aws:elasticloadbalancing:ap-northeast-2:[0-9]{12}:targetgroup/[^*?]+$", arn))])
    error_message = "pilo_target_group_arns must contain concrete target group ARNs."
  }
}

variable "pilo_rds_instance_arns" {
  description = "Existing allowlisted PILO RDS instance ARNs."
  type        = set(string)

  validation {
    condition     = length(var.pilo_rds_instance_arns) > 0 && alltrue([for arn in var.pilo_rds_instance_arns : can(regex("^arn:aws:rds:ap-northeast-2:[0-9]{12}:db:[^*?]+$", arn))])
    error_message = "pilo_rds_instance_arns must contain concrete DB instance ARNs."
  }
}

variable "pilo_secret_arns" {
  description = "Existing allowlisted PILO Secret ARNs; values are never readable."
  type        = set(string)

  validation {
    condition     = length(var.pilo_secret_arns) > 0 && alltrue([for arn in var.pilo_secret_arns : can(regex("^arn:aws:secretsmanager:ap-northeast-2:[0-9]{12}:secret:[^*?]+$", arn))])
    error_message = "pilo_secret_arns must contain concrete Secret metadata ARNs."
  }
}

variable "pilo_queue_arns" {
  description = "Existing allowlisted PILO SQS queue ARNs."
  type        = set(string)

  validation {
    condition     = length(var.pilo_queue_arns) > 0 && alltrue([for arn in var.pilo_queue_arns : can(regex("^arn:aws:sqs:ap-northeast-2:[0-9]{12}:[^*?]+$", arn))])
    error_message = "pilo_queue_arns must contain concrete queue ARNs."
  }
}

variable "tags" {
  description = "Additional non-sensitive resource tags."
  type        = map(string)
  default     = {}
}
