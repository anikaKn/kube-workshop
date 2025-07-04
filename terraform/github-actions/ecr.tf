# data "aws_iam_user" "github_action_user" {
#   name = "${local.user}-github-action"
# }

resource "aws_iam_policy" "ecr_policy" {
  name        = "${local.user}-ecr-policy"
  description = "Policy for ECR push and token retrieval"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid    = "AllowPush",
        Effect = "Allow",
        Action = [
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "ecr:BatchCheckLayerAvailability",
          "ecr:PutImage",
          "ecr:InitiateLayerUpload",
          "ecr:UploadLayerPart",
          "ecr:CompleteLayerUpload"
        ],
        Resource = "arn:aws:ecr:${data.aws_region.current.id}:${data.aws_caller_identity.current.account_id}:repository/${local.repository_name}"
      },
      {
        Sid    = "GetAuthorizationToken",
        Effect = "Allow",
        Action = [
          "ecr:GetAuthorizationToken"
        ],
        Resource = "*"
      }
    ]
  })
  tags = {
    Owner = local.user
  }
}

resource "aws_iam_user_policy_attachment" "attach_ecr_policy" {
  user       = local.github_action_user_name
  policy_arn = aws_iam_policy.ecr_policy.arn
}


resource "aws_ecr_repository" "my_repository" {
  name                 = local.repository_name
  image_tag_mutability = "MUTABLE" # or "IMMUTABLE" based on your requirements
  tags = {
    Name  = local.repository_name
    Owner = local.user
  }
}
