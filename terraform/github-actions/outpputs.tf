output "ecr_policy_arn" {
  value       = aws_iam_policy.ecr_policy.arn
  description = "ARN of the ECR policy"
}