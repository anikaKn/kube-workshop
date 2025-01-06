data "aws_region" "current" {}
data "aws_caller_identity" "current" {}
locals {
  user                    = "aknys"
  repository_name         = "${local.user}-demo-frontend"
  github_action_user_name = "${local.user}-github-action"
}
