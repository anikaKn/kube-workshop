data "aws_region" "current" {}

locals {

  context_prefix = "gitops-bridge"
  #  git_repo="git@github.com:anikaKn"
  git_repo                  = "https://github.com/anikaKn"
  # git_token                 = "" # TODO SSM
  gitops_workload_repo_name = var.gitops_workload_repo_name
  gitops_workload_org       = local.git_repo
  gitops_workload_repo      = local.gitops_workload_repo_name

  # gitops_platform_repo_name = var.gitops_platform_repo_name
  # gitops_platform_org       = "ssh://${aws_iam_user_ssh_key.gitops.id}@git-codecommit.${data.aws_region.current.id}.amazonaws.com"
  # gitops_platform_repo      = "v1/repos/${local.gitops_platform_repo_name}"

  gitops_platform_repo_name = var.gitops_platform_repo_name
  gitops_platform_org       = local.git_repo
  gitops_platform_repo      = local.gitops_platform_repo_name

  gitops_addons_repo_name = var.gitops_addons_repo_name
  gitops_addons_org       = local.git_repo
  gitops_addons_repo      = local.gitops_addons_repo_name

  ssh_key_basepath           = var.ssh_key_basepath
  git_private_ssh_key        = "${local.ssh_key_basepath}/gitops_ssh.pem"
  git_private_ssh_key_config = "${local.ssh_key_basepath}/config"
  ssh_host                   = "github.com"
  ssh_config                 = <<-EOF
  # AWS Workshop https://github.com/aws-samples/argocd-on-amazon-eks-workshop.git
  Host ${local.ssh_host}
    User ${aws_iam_user.gitops.unique_id}
    IdentityFile ${local.git_private_ssh_key}
  EOF

}

# resource "aws_codecommit_repository" "workloads" {
#   repository_name = local.gitops_workload_repo_name
#   description     = "CodeCommit repository for ArgoCD workloads"
# }

# resource "aws_codecommit_repository" "platform" {
#   repository_name = local.gitops_platform_repo_name
#   description     = "CodeCommit repository for ArgoCD platform"
# }

# resource "aws_codecommit_repository" "addons" {
#   repository_name = local.gitops_addons_repo_name
#   description     = "CodeCommit repository for ArgoCD addons"
# }

# resource "aws_codecatalyst_space" "kube_space" {
#   name        = "my-kube-space" # Replace with your desired space name
#   description = "This is an kube space for organizing projects."
# }
# resource "aws_codecatalyst_project" "workloads" {
#   # name        = local.gitops_workload_repo_name
#   display_name= local.gitops_workload_repo_name
#   description = "Project for ArgoCD workloads"
#   space_name  = "my-kube-space"
# }

# resource "aws_codecatalyst_project" "platform" {
#   # name        = local.gitops_platform_repo_name
#   display_name= local.gitops_platform_repo_name
#   description = "Project for ArgoCD platform"
#   space_name  = "my-kube-space"
# }

# resource "aws_codecatalyst_project" "addons" {
#   # name        = local.gitops_addons_repo_name
#   display_name= local.gitops_addons_repo_name
#   description = "Project for ArgoCD addons"

#   space_name = "my-kube-space"
# }
resource "aws_iam_user" "gitops" {
  name = "${local.context_prefix}-gitops"
  path = "/"
}

resource "aws_iam_user_ssh_key" "gitops" {
  username   = aws_iam_user.gitops.name
  encoding   = "SSH"
  public_key = tls_private_key.gitops.public_key_openssh
}

resource "tls_private_key" "gitops" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "random_string" "secret_suffix" {
  length  = 5     # Length of the random string
  special = false # Set to true if you want to include special characters
  upper   = true  # Set to true if you want uppercase letters in the string
  lower   = true  # Set to true if you want lowercase letters in the string
  number  = true  # Set to true if you want numbers in the string
}
resource "aws_secretsmanager_secret" "codecommit_key" {
  name = "codecommit-key-${random_string.secret_suffix.result}"
}

resource "aws_secretsmanager_secret_version" "private_key_secret_version" {
  secret_id     = aws_secretsmanager_secret.codecommit_key.id
  secret_string = tls_private_key.gitops.private_key_pem
}

resource "local_file" "ssh_private_key" {
  content         = tls_private_key.gitops.private_key_pem
  filename        = pathexpand(local.git_private_ssh_key)
  file_permission = "0600"
}

resource "local_file" "ssh_config" {
  count           = local.ssh_key_basepath == "/home/ec2-user/.ssh" ? 1 : 0
  content         = local.ssh_config
  filename        = pathexpand(local.git_private_ssh_key_config)
  file_permission = "0600"
}

resource "null_resource" "append_string_block" {
  count = local.ssh_key_basepath == "/home/ec2-user/.ssh" ? 0 : 1
  triggers = {
    always_run = "${timestamp()}"
    file       = pathexpand(local.git_private_ssh_key_config)
  }

  provisioner "local-exec" {
    when    = create
    command = <<-EOL

      start_marker="### START BLOCK AWS Workshop ###"
      end_marker="### END BLOCK AWS Workshop ###"
      block="$start_marker\n${local.ssh_config}\n$end_marker"
      file="${self.triggers.file}"
      echo file "${self.triggers.file}"

      if ! grep -q "$start_marker" "$file"; then
        echo "$block" >> "$file"
      fi
    EOL
  }

  provisioner "local-exec" {
    when    = destroy
    command = <<-EOL
      start_marker="### START BLOCK AWS Workshop ###"
      end_marker="### END BLOCK AWS Workshop ###"
      file="${self.triggers.file}"
      echo file "${self.triggers.file}"

      if grep -q "$start_marker" "$file"; then
        sed -i '' "/$start_marker/,/$end_marker/d" "$file"
      fi
    EOL

  }
}


# data "aws_iam_policy_document" "gitops_access" {
#   statement {
#     sid = ""
#     actions = [
#       "codecatalyst:*",  # Adjust as necessary
#     ]
#     effect = "Allow"
#     resources = [
#       "arn:aws:codecatalyst:${data.aws_region.current.id}::space/my-kube-space/project/${local.gitops_workload_repo_name}",
#       "arn:aws:codecatalyst:${data.aws_region.current.id}::space/my-kube-space/project/${local.gitops_platform_repo_name}",
#       "arn:aws:codecatalyst:${data.aws_region.current.id}::space/my-kube-space/project/${local.gitops_addons_repo_name}"
#       # aws_codecatalyst_project.workloads.arn,
#       # aws_codecatalyst_project.platform.arn,
#       # aws_codecatalyst_project.addons.arn
#     ]
#   }
# }
# resource "aws_iam_policy" "gitops_access" {
#   name   = "${local.context_prefix}-gitops"
#   path   = "/"
#   policy = data.aws_iam_policy_document.gitops_access.json
# }

# resource "aws_iam_user_policy_attachment" "gitops_access" {
#   user       = aws_iam_user.gitops.name
#   policy_arn = aws_iam_policy.gitops_access.arn
# }
