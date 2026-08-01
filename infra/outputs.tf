output "bundle_bucket_name" {
  description = "Private bucket for seven-day Incident Bundles and the protected topology object."
  value       = aws_s3_bucket.bundle.id
}

output "state_table_name" {
  description = "DynamoDB event and publisher checkpoint table."
  value       = aws_dynamodb_table.state.name
}

output "lambda_function_name" {
  description = "PILO Incident Investigator Lambda function."
  value       = aws_lambda_function.investigator.function_name
}

output "event_rule_name" {
  description = "EventBridge rule for the existing PILO dev Alarms."
  value       = aws_cloudwatch_event_rule.alarm.name
}

output "runtime_role_arn" {
  description = "Dedicated least-privilege Lambda role."
  value       = aws_iam_role.lambda.arn
}
