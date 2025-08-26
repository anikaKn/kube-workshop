data "aws_caller_identity" "current" {}
data "aws_availability_zones" "available" {}
data "aws_region" "current" {}
data "aws_iam_session_context" "current" {
  # This data source provides information on the IAM source role of an STS assumed role
  # For non-role ARNs, this data source simply passes the ARN through issuer ARN
  # Ref https://github.com/terraform-aws-modules/terraform-aws-eks/issues/2327#issuecomment-1355581682
  # Ref https://github.com/hashicorp/terraform-provider-aws/issues/28381
  arn = data.aws_caller_identity.current.arn
}
data "aws_eks_cluster_auth" "eks" {
  name = local.name
}

provider "aws" {
  region = "us-east-1"
  alias  = "virginia"
}

data "aws_ecrpublic_authorization_token" "token" {
  provider = aws.virginia
}
data "aws_secretsmanager_secret_version" "git_token" {
  secret_id = "arn:aws:secretsmanager:us-west-2:022698001278:secret:aknys-git-token-C8pnBC"
  # secret_id = "arn:aws:secretsmanager:us-east-1:022698001278:secret:aknys-git-token-34nJ5C"
}

provider "helm" {
  kubernetes {
    host                   = module.eks.cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
    token                  = data.aws_eks_cluster_auth.eks.token
    # exec {
    #   api_version = "client.authentication.k8s.io/v1beta1"
    #   command     = "aws"
    #   # This requires the awscli to be installed locally where Terraform is executed
    #   args = ["eks", "get-token", "--cluster-name", module.eks.cluster_name, "--region", local.region]
    # }

  }
  registry {
    url      = "oci://public.ecr.aws"
    username = data.aws_ecrpublic_authorization_token.token.user_name
    password = data.aws_ecrpublic_authorization_token.token.password
  }
}

provider "kubernetes" {
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
  token                  = data.aws_eks_cluster_auth.eks.token

  # exec {
  #   api_version = "client.authentication.k8s.io/v1beta1"
  #   command     = "aws"
  #   # This requires the awscli to be installed locally where Terraform is executed
  #   args = ["eks", "get-token", "--cluster-name", module.eks.cluster_name, "--region", local.region]
  # }
}



locals {
  name            = "aknys"
  environment     = "control-plane"
  region          = data.aws_region.current.id
  cluster_version = var.kubernetes_version
  vpc_cidr        = var.vpc_cidr

  username                       = "anikaKn"
  git_token                      = jsondecode(data.aws_secretsmanager_secret_version.git_token.secret_string).gitToken
  paasword                       = local.git_token
  argocd_host                    = "itfuture.click" # TODO SET domain
  certificate_arn                = ""               #TODO cert
  external_dns_route53_zone_arns = ["arn:aws:route53:::hostedzone/Z0472995P920M8ZJM6Z2"]
  argocd_cert                    = "arn:aws:acm:us-west-2:022698001278:certificate/b1abf9e7-73b4-4099-bb3b-ec595dc3c61f"
  eks_cluster_domain             = local.argocd_host
  gitops_addons_url              = data.terraform_remote_state.git.outputs.gitops_addons_url
  gitops_addons_basepath         = data.terraform_remote_state.git.outputs.gitops_addons_basepath
  gitops_addons_path             = data.terraform_remote_state.git.outputs.gitops_addons_path
  gitops_addons_revision         = data.terraform_remote_state.git.outputs.gitops_addons_revision

  gitops_platform_url      = data.terraform_remote_state.git.outputs.gitops_platform_url
  gitops_platform_basepath = data.terraform_remote_state.git.outputs.gitops_platform_basepath
  gitops_platform_path     = data.terraform_remote_state.git.outputs.gitops_platform_path
  gitops_platform_revision = data.terraform_remote_state.git.outputs.gitops_platform_revision

  gitops_workload_url      = data.terraform_remote_state.git.outputs.gitops_workload_url
  gitops_workload_basepath = data.terraform_remote_state.git.outputs.gitops_workload_basepath
  gitops_workload_path     = data.terraform_remote_state.git.outputs.gitops_workload_path
  gitops_workload_revision = data.terraform_remote_state.git.outputs.gitops_workload_revision

  gitops_manifest_url      = data.terraform_remote_state.git.outputs.gitops_manifest_url
  gitops_manifest_basepath = data.terraform_remote_state.git.outputs.gitops_manifest_basepath
  gitops_manifest_path     = data.terraform_remote_state.git.outputs.gitops_manifest_path
  gitops_manifest_revision = data.terraform_remote_state.git.outputs.gitops_manifest_revision

  argocd_chart_version = "7.3.11" #"7.3.11"
  git_private_ssh_key  = data.terraform_remote_state.git.outputs.git_private_ssh_key

  argocd_namespace = "argocd"

  aws_addons = {
    enable_cert_manager                          = false
    enable_aws_efs_csi_driver                    = false
    enable_aws_fsx_csi_driver                    = false
    enable_aws_cloudwatch_metrics                = false
    enable_aws_privateca_issuer                  = false
    enable_cluster_autoscaler                    = false
    enable_external_dns                          = true
    enable_external_secrets                      = true
    enable_aws_load_balancer_controller          = true
    enable_fargate_fluentbit                     = false
    enable_aws_for_fluentbit                     = false
    enable_aws_node_termination_handler          = false
    enable_karpenter                             = true
    enable_velero                                = false
    enable_aws_gateway_api_controller            = false
    enable_aws_ebs_csi_resources                 = true # generate gp2 and gp3 storage classes for ebs-csi
    enable_aws_secrets_store_csi_driver_provider = false
    enable_aws_argocd                            = false
  }
  oss_addons = {
    enable_argocd             = false # disable default argocd application set, we enable enable_aws_argocd above
    enable_aws_argocd_ingress = true
    enable_metrics_server     = true
  }
  addons = merge(local.aws_addons, local.oss_addons, { kubernetes_version = local.cluster_version }, { aws_cluster_name = module.eks.cluster_name })

  addons_metadata = merge(
    module.eks_blueprints_addons.gitops_metadata,
    {
      aws_cluster_name = module.eks.cluster_name
      email            = "aknys@softserveinc.com"
      aws_region       = local.region
      aws_account_id   = data.aws_caller_identity.current.account_id
      aws_vpc_id       = module.vpc.vpc_id
    },
    {
      argocd_iam_role_arn = module.argocd_irsa.iam_role_arn
      argocd_namespace    = local.argocd_namespace
    },
    {
      argocd_hosts         = "[${local.argocd_host}]"
      argocd_host          = "${local.argocd_host}"
      argocd_cert          = local.argocd_cert
      eks_cluster_domain   = local.eks_cluster_domain
      addons_repo_url      = local.gitops_addons_url
      addons_repo_basepath = local.gitops_addons_basepath
      addons_repo_path     = local.gitops_addons_path
      addons_repo_revision = local.gitops_addons_revision
      aws_cluster_name     = local.name
    },
    {
      platform_repo_url      = local.gitops_platform_url
      platform_repo_basepath = local.gitops_platform_basepath
      platform_repo_path     = local.gitops_platform_path
      platform_repo_revision = local.gitops_platform_revision
    },
    {
      workload_repo_url      = local.gitops_workload_url
      workload_repo_basepath = local.gitops_workload_basepath
      workload_repo_path     = local.gitops_workload_path
      workload_repo_revision = local.gitops_workload_revision
    },
    {
      manifest_repo_url      = local.gitops_manifest_url
      manifest_repo_basepath = local.gitops_manifest_basepath
      manifest_repo_path     = local.gitops_manifest_path
      manifest_repo_revision = local.gitops_manifest_revision
    },
    {
      karpenter_node_instance_profile_name = module.eks_blueprints_addons.karpenter.node_instance_profile_name
      karpenter_node_iam_role_name         = module.eks_blueprints_addons.karpenter.node_iam_role_name
      karpenter_node_iam_role_arn          = module.eks_blueprints_addons.karpenter.node_iam_role_arn
      karpenter_sqs_queue_name             = module.eks_blueprints_addons.karpenter.sqs.queue_name
      karpenter_iam_role_arn               = module.eks_blueprints_addons.karpenter.iam_role_arn
      karpenter_cluster_endpoint           = module.eks.cluster_endpoint
      karpenter_namespace                  = "karpenter"
      karpenter_service_account            = "karpenter"
      karpenter_capacity_type              = "[\"spot\"]" #, \"on-demand\"
    }
  )
  argocd_tolerations_yaml = templatefile("${path.module}/argocd-tolerations.yaml.tmpl", {
    iam_role_arn = module.argocd_irsa.iam_role_arn
  })
  argocd_apps = {
    addons   = file("${path.module}/bootstrap/addons.yaml")
    platform = file("${path.module}/bootstrap/platform.yaml")
  }

  azs             = slice(data.aws_availability_zones.available.names, 0, 3)
  resource_prefix = "aknys"
  kubernetes_admins = [
    {
      userarn    = "arn:aws:iam::022698001278:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_PowerUserAccessCustom_a7d8c8044914d012"
      username   = "aknys"
      policy_arn = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
    }
  ]

  #  critical_addons_tolerations = [
  #     {
  #       key      = "CriticalAddonsOnly"
  #       operator = "Exists"
  #       effect   = "NoSchedule"
  #     },
  #     {
  #       key      = "CriticalAddonsOnly"
  #       operator = "Equal"
  #       value    = "false"
  #       effect   = "NoSchedule"
  #     }
  #   ]
  # existing_map_roles = lookup(data.kubernetes_config_map.aws_auth.data, "mapRoles", "")


  tags = {
    Blueprint  = local.name
    GithubRepo = "github.com/csantanapr/terraform-gitops-bridge"
    Owner      = "aknys@softserveinc.com"
    Schedule   = "running" #"utc-06:00-16:00"
    # "karpenter.sh/discovery" = local.name # PUBLIC SUBNET should not have this tag!!!!, 
    # "kubernetes.io/cluster/aknys" = "shared"
  }
}

################################################################################
# GitOps Bridge: Private ssh keys for git
################################################################################
resource "kubernetes_namespace" "argocd" {
  metadata {
    name = local.argocd_namespace
  }
  depends_on = [module.eks_blueprints_addons, module.eks]
}


# resource "kubernetes_cluster_role" "argocd_application_controller" {
#   metadata {
#     name = "argo-cd-argocd-application-controller"
#   }

#   rule {
#     api_groups = ["apps"]
#     resources  = ["statefulsets"]
#     verbs      = ["get", "list", "watch", "create", "update", "patch", "delete"]
#   }

#   depends_on = [kubernetes_namespace.argocd]
# }

# resource "kubernetes_cluster_role_binding" "argocd_application_controller_binding" {
#   metadata {
#     name = "argo-cd-argocd-application-controller"
#   }

#   role_ref {
#     api_group = "rbac.authorization.k8s.io"
#     kind      = "ClusterRole"
#     name      = kubernetes_cluster_role.argocd_application_controller.metadata[0].name
#   }

#   subject {
#     kind      = "ServiceAccount"
#     name      = "argocd-application-controller"
#     namespace = "argocd"
#   }
# }




# resource "kubernetes_cluster_role" "node_get_csinode" {
#   metadata {
#     name = "node-get-csinodes"
#   }

#   rule {
#     api_groups = ["storage.k8s.io"]
#     resources  = ["csinodes"]
#     verbs      = ["get"]
#   }
#   rule {
#     api_groups = [""]
#     resources  = ["nodes", "services"]
#     verbs      = ["get", "list", "watch"]
#   }
#   rule {
#     api_groups = ["storage.k8s.io"]
#     resources  = ["csinodes"]
#     verbs      = ["get", "list", "watch"]
#   }
#   rule {
#     api_groups = ["coordination.k8s.io"]
#     resources  = ["leases"]
#     verbs      = ["get", "list", "watch", "create", "update"]
#   }


# }

# resource "kubernetes_cluster_role_binding" "node_get_csinode_binding" {
#   metadata {
#     name = "node-get-csinodes-binding"
#   }

#   subject {
#     kind      = "Group"
#     name      = "system:nodes"
#     api_group = "rbac.authorization.k8s.io"
#   }

#   role_ref {
#     kind     = "ClusterRole"
#     name     = kubernetes_cluster_role.node_get_csinode.metadata[0].name
#     api_group = "rbac.authorization.k8s.io"
#   }
# }



# resource "kubernetes_config_map" "aws_auth" {
#   metadata {
#     name      = "aws-auth"
#     namespace = "kube-system"
#   }
#   data = {
#     mapRoles = yamlencode([
#       {
#         rolearn  = module.eks_blueprints_addons.karpenter.node_iam_role_arn
#         username = "system:node:{{EC2PrivateDNSName}}"
#         groups   = ["system:bootstrappers", "system:nodes"]
#       }
#       # additional mappings...
#     ])
#   }
#   depends_on = [module.eks]
# }


# data "kubernetes_config_map" "aws_auth" {
#   metadata {
#     name      = "aws-auth"
#     namespace = "kube-system"
#   }
# }

# # Prepare your additional mapRoles entry as YAML string via template
# data "template_file" "new_map_roles" {
#   template = <<EOF
# ${local.existing_map_roles}

# - rolearn: ${module.eks_blueprints_addons.karpenter.node_iam_role_arn}
#   username: system:node:{{EC2PrivateDNSName}}
#   groups:
#     - system:bootstrappers
#     - system:nodes
# EOF
# }

# # Example to output the new combined mapRoles - you can use this rendered template
# output "updated_map_roles" {
#   value = data.template_file.new_map_roles.rendered
# }



resource "aws_eks_access_entry" "karpenter_node_access_entry" {
  cluster_name  = module.eks.cluster_name
  principal_arn = module.eks_blueprints_addons.karpenter.node_iam_role_arn
  user_name     = "karpenter-node"
  kubernetes_groups = [
    "karpenter-nodes",
    # "system:bootstrappers",
    # "system:nodes"
  ]
  # # kubernetes_groups = []
  # type = "EC2_LINUX"
}

# 2. RBAC binding in Kubernetes
resource "kubernetes_cluster_role_binding" "karpenter_nodes" {
  metadata {
    name = "karpenter-nodes-binding"
  }

  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = "system:node"
  }

  subject {
    kind      = "Group"
    name      = "karpenter-nodes"
    api_group = "rbac.authorization.k8s.io"
  }
}


# resource "aws_eks_access_policy_association" "karpenter_node" { # NEW 
#   cluster_name  = module.eks.cluster_name
#   principal_arn = module.eks_blueprints_addons.karpenter.node_iam_role_arn
#   # policy_arn    = "arn:aws:eks:us-west-2::cluster-access-policy/AmazonEKSNodePolicy" # <-- update region here
#   policy_arn    = "arn:aws:eks:us-west-2:aws:cluster-access-policy/AmazonEKSNodePolicy"


#   access_scope {
#     type = "cluster"
#   }
# }

# resource "kubernetes_config_map" "aws_auth" {
#   metadata {
#     name      = "aws-auth"
#     namespace = "kube-system"
#   }

# data = {
#   mapRoles = yamlencode([
#     # Karpenter node IAM role
#     {
#       rolearn  = module.eks_blueprints_addons.karpenter.node_iam_role_arn
#       username = "system:node:{{EC2PrivateDNSName}}"
#       groups   = [
#         "system:bootstrappers",
#         "system:nodes"
#       ]
#     },
#     # EKS managed node group role (replace with your actual role ARN)
#     {
#       rolearn  = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aknys-critical-addons-arm20250731165617886800000003"
#       username = "system:node:{{EC2PrivateDNSName}}"
#       groups   = [
#         "system:bootstrappers",
#         "system:nodes"
#       ]
#     },
#     # (Optional) Admin IAM role for kubectl access
#     {
#       rolearn  = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_PowerUserAccessCustom_a7d8c8044914d012"
#       username = "admin"
#       groups   = [
#         "system:masters"
#       ]
#     }
#     # ...add more node or admin roles as needed...
#   ])
# }
# }

resource "kubernetes_secret" "git_secrets" {
  #depends_on = [kubernetes_namespace.argocd]
  for_each = {
    git-addons = {
      type     = "git"
      url      = local.gitops_addons_url
      username = local.username
      paasword = local.paasword
    }
    git-platform = {
      type     = "git"
      url      = local.gitops_platform_url
      username = local.username
      paasword = local.paasword
    }
    git-workloads = {
      type     = "git"
      url      = local.gitops_workload_url
      username = local.username
      paasword = local.paasword
    }
    git-manifest = {
      type     = "git"
      url      = local.gitops_manifest_url
      username = local.username
      paasword = local.paasword
    }

  }
  metadata {
    name = each.key
    # namespace = kubernetes_namespace.argocd.metadata[0].name
    labels = {
      "argocd.argoproj.io/secret-type" = "repository"
    }
  }
  data = each.value
}

################################################################################
# GitOps Bridge: Bootstrap
################################################################################
module "gitops_bridge_bootstrap" {
  source  = "gitops-bridge-dev/gitops-bridge/helm"
  version = "0.1.0"

  cluster = {
    cluster_name = module.eks.cluster_name
    environment  = local.environment
    metadata     = local.addons_metadata
    addons       = local.addons
  }

  apps = local.argocd_apps

  argocd = {
    namespace        = local.argocd_namespace
    chart_version    = local.argocd_chart_version
    timeout          = 1200
    create_namespace = false
    recreate_pods    = true
    force_update     = true

    # values = [local.argocd_tolerations_yaml]

  }

  depends_on = [kubernetes_secret.git_secrets, kubernetes_namespace.argocd]
}




################################################################################
# ArgoCD EKS Access
################################################################################
module "argocd_irsa" {
  source = "aws-ia/eks-blueprints-addon/aws"

  create_release             = false
  create_role                = true
  role_name_use_prefix       = false
  role_name                  = "${module.eks.cluster_name}-argocd-hub"
  assume_role_condition_test = "StringLike"
  create_policy              = false
  role_policies = {
    ArgoCD_EKS_Policy = aws_iam_policy.irsa_policy.arn
  }
  oidc_providers = {
    this = {
      provider_arn    = module.eks.oidc_provider_arn
      namespace       = local.argocd_namespace
      service_account = "argocd-*"
    }
  }
  tags = local.tags

}

resource "aws_iam_policy" "irsa_policy" {
  name        = "${module.eks.cluster_name}-argocd-irsa"
  description = "IAM Policy for ArgoCD Hub"
  policy      = data.aws_iam_policy_document.irsa_policy.json
  tags        = local.tags
}

# data "aws_iam_policy_document" "irsa_policy" {
#   statement {
#     effect    = "Allow"
#     resources = ["*"]
#     actions   = ["sts:AssumeRole"]
#   }

# }

data "aws_iam_policy_document" "irsa_policy" {
  statement {
    effect = "Allow"
    actions = [
      "sts:AssumeRole"
    ]
    resources = ["*"]
  }

  # Allow read access to Secrets Manager
  statement {
    effect = "Allow"
    actions = [
      "secretsmanager:GetSecretValue",
      "secretsmanager:DescribeSecret",
      "secretsmanager:ListSecrets"
    ]
    resources = ["*"] # Or restrict to specific ARNs
  }

  # Allow read access to SSM Parameter Store
  statement {
    effect = "Allow"
    actions = [
      "ssm:GetParameter",
      "ssm:GetParameters",
      "ssm:GetParametersByPath",
      "ssm:DescribeParameters"
    ]
    resources = ["*"] # Or restrict to specific ARNs
  }
}

################################################################################
# EKS Blueprints Addons
################################################################################
module "eks_blueprints_addons" {
  source  = "aws-ia/eks-blueprints-addons/aws"
  version = "~> 1.0"

  cluster_name      = module.eks.cluster_name
  cluster_endpoint  = module.eks.cluster_endpoint
  cluster_version   = module.eks.cluster_version
  oidc_provider_arn = module.eks.oidc_provider_arn

  # Using GitOps Bridge
  create_kubernetes_resources = false

  # EKS Blueprints Addons
  enable_cert_manager                 = try(local.aws_addons.enable_cert_manager, false)
  enable_aws_efs_csi_driver           = try(local.aws_addons.enable_aws_efs_csi_driver, false)
  enable_aws_fsx_csi_driver           = try(local.aws_addons.enable_aws_fsx_csi_driver, false)
  enable_aws_cloudwatch_metrics       = try(local.aws_addons.enable_aws_cloudwatch_metrics, false)
  enable_aws_privateca_issuer         = try(local.aws_addons.enable_aws_privateca_issuer, false)
  enable_cluster_autoscaler           = try(local.aws_addons.enable_cluster_autoscaler, false)
  enable_external_dns                 = try(local.aws_addons.enable_external_dns, false)
  enable_external_secrets             = try(local.aws_addons.enable_external_secrets, false)
  enable_aws_load_balancer_controller = try(local.aws_addons.enable_aws_load_balancer_controller, false)
  enable_fargate_fluentbit            = try(local.aws_addons.enable_fargate_fluentbit, false)
  enable_aws_for_fluentbit            = try(local.aws_addons.enable_aws_for_fluentbit, false)
  enable_aws_node_termination_handler = try(local.aws_addons.enable_aws_node_termination_handler, false)
  enable_karpenter                    = try(local.aws_addons.enable_karpenter, false)
  enable_velero                       = try(local.aws_addons.enable_velero, false)
  enable_aws_gateway_api_controller   = try(local.aws_addons.enable_aws_gateway_api_controller, false)
  external_dns_route53_zone_arns      = local.external_dns_route53_zone_arns


  tags = local.tags
  #   tags = merge(
  #   local.tags,
  #   {
  #     "karpenter.sh/discovery" = "aknys"
  #   }
  # )

  karpenter_enable_instance_profile_creation = true

  karpenter = {
    repository_username = data.aws_ecrpublic_authorization_token.token.user_name
    repository_password = data.aws_ecrpublic_authorization_token.token.password
  }

  karpenter_node = {
    iam_role_use_name_prefix = true
    iam_role_additional_policies = [
      "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
    ]
  }

}
################################################################################
# EKS Cluster
################################################################################
#tfsec:ignore:aws-eks-enable-control-plane-logging
module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.33" #"~> 20.4" # "~> 20.33"

  cluster_name                   = local.resource_prefix
  cluster_version                = local.cluster_version
  cluster_endpoint_public_access = true

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets
  # Fargate profiles use the cluster primary security group so these are not utilized
  # create_cluster_security_group = false #added from site
  #create_node_security_group    = false #added from site

  authentication_mode = "API_AND_CONFIG_MAP" ## TODO changed 22.07.24 

  #  create_node_iam_role = false
  # node_iam_role_arn    =  module.eks_blueprints_addons.karpenter.node_iam_role_arn
  #   # Since the node group role will already have an access entry
  #   create_access_entry = false


  #   manage_aws_auth = true
  # aws_auth_roles = [
  #   {
  #     rolearn  = module.eks_blueprints_addons.karpenter.node_iam_role_arn
  #     username = "system:node:{{EC2PrivateDNSName}}"
  #     groups   = [
  #       "system:bootstrappers",
  #       "system:nodes"
  #     ]
  #   },
  #   {
  #     rolearn  = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aknys-critical-addons-arm20250731165617886800000003"
  #     username = "system:node:{{EC2PrivateDNSName}}"
  #     groups   = [
  #       "system:bootstrappers",
  #       "system:nodes"
  #     ]
  #   },
  #   {
  #     rolearn  = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_PowerUserAccessCustom_a7d8c8044914d012"
  #     username = "admin"
  #     groups   = [
  #       "system:masters"
  #     ]
  #   }
  # ]



  # manage_aws_auth_configmap = true
  #  aws_auth_roles = [
  #   {
  #     rolearn  = module.eks_blueprints_addons.karpenter.node_iam_role_arn
  #     username = "system:node:{{EC2PrivateDNSName}}"
  #     groups   = [
  #       "system:bootstrappers",
  #       "system:nodes"
  #     ]
  #   },
  #   {
  #     rolearn  = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aknys-critical-addons-arm20250731165617886800000003"
  #     username = "system:node:{{EC2PrivateDNSName}}"
  #     groups   = [
  #       "system:bootstrappers",
  #       "system:nodes"
  #     ]
  #   },
  #   {
  #     rolearn  = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_PowerUserAccessCustom_a7d8c8044914d012"
  #     username = "admin"
  #     groups   = [
  #       "system:masters"
  #     ]
  #   }
  # ] // <-- Add this closing bracket here








  # Combine root account, current user/role and additinoal roles to be able to access the cluster KMS key - required for terraform updates
  kms_key_administrators = distinct(concat([
    "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"],
    var.kms_key_admin_roles,
    [data.aws_iam_session_context.current.issuer_arn]

  ))

  # The following is a code to add customed security group rules
  cluster_security_group_additional_rules = {
    hybrid-all = {
      cidr_blocks = [local.vpc_cidr]
      description = "Allow all traffic to Istio control plane"
      from_port   = 15017
      to_port     = 15017
      protocol    = "TCP"
      type        = "ingress"
    }
  }
  node_security_group_additional_rules = {
    nodes_istiod_port = {
      description                   = "Cluster API to Node group for istiod webhook"
      protocol                      = "tcp"
      from_port                     = 15017
      to_port                       = 15017
      type                          = "ingress"
      source_cluster_security_group = true
    }
    node_to_node_communication = {
      description = "Allow full access for cross-node communication"
      protocol    = "tcp"
      from_port   = 0
      to_port     = 65535
      type        = "ingress"
      self        = true
    }
  }

  # To add the current caller identity as an administrator
  enable_cluster_creator_admin_permissions = true

  eks_managed_node_groups = {
    critical-addons-arm = {
      instance_types = ["c6g.large"] #"t4g.medium"
      ami_type       = "AL2023_ARM_64_STANDARD"

      min_size     = 2
      max_size     = 3
      desired_size = 2

      labels = {
        # Used to ensure Karpenter runs on nodes that it does not manage
        "karpenter.sh/controller" = "true"
      }

      # taints = { # TODO GTP asked to uncomment
      #   # This Taint aims to keep just EKS Addons and Karpenter running on this MNG
      #   # The pods that do not tolerate this taint should run on nodes created by Karpenter
      #   addons = {
      #     key    = "CriticalAddonsOnly"
      #     value  = "false"
      #     effect = "NO_SCHEDULE"
      #   }
      # }
    }
  }

  # EKS Addons
  cluster_addons = {
    vpc-cni = {
      # Specify the VPC CNI addon should be deployed before compute to ensure
      # the addon is configured before data plane compute resources are created
      # See README for further details
      before_compute = true
      most_recent    = true # To ensure access to the latest settings provided
      configuration_values = jsonencode({
        env = {
          # Reference docs https://docs.aws.amazon.com/eks/latest/userguide/cni-increase-ip-addresses.html
          ENABLE_POD_ENI                    = "true"
          POD_SECURITY_GROUP_ENFORCING_MODE = "standard"
          ENABLE_PREFIX_DELEGATION          = "true"
          WARM_PREFIX_TARGET                = "1"
        }
      })
    }
    #eks-pod-identity-agent = {}
  }

  enable_efa_support = true

  tags = merge(
    local.tags,
    {
      # NOTE - if creating multiple security groups with this module, only tag the
      # security group that Karpenter should utilize with the following tag
      # (i.e. - at most, only one security group should have this tag in your account)
      "karpenter.sh/discovery" = local.resource_prefix
  })


}

################################################################################
# VPC
################################################################################
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.18"

  name = "${local.resource_prefix}-vpc"
  cidr = local.vpc_cidr

  azs             = local.azs
  private_subnets = [for k, v in local.azs : cidrsubnet(local.vpc_cidr, 4, k)]
  public_subnets  = [for k, v in local.azs : cidrsubnet(local.vpc_cidr, 8, k + 48)]

  # enable_ipv6 = false

  enable_dns_hostnames = true
  enable_dns_support   = true

  enable_nat_gateway     = true
  single_nat_gateway     = true
  one_nat_gateway_per_az = false
  enable_vpn_gateway     = false

  manage_default_network_acl    = false
  manage_default_route_table    = false
  manage_default_security_group = false

  public_subnet_tags = {
    "kubernetes.io/role/elb" = 1
  }

  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = 1
    # Tags subnets for Karpenter auto-discovery
    "karpenter.sh/discovery" = local.resource_prefix
  }

  tags = local.tags
}


# resource "kubernetes_secret" "incluster_argocd_cluster" {
#   metadata {
#     name      = "cluster-https-kubernetes-default-svc"
#     namespace = "argocd"
#     annotations = {
#       "aws_cluster_name" = local.name
#     }
#   }

#   data = {
#     # DO NOT override `data` unless you’re creating the secret from scratch
#     # If updating only annotations, use `kubectl_patch` instead
#   }

#   lifecycle {
#     ignore_changes = [data]
#   }
# }


# resource "null_resource" "patch_argocd_cluster" {
#   provisioner "local-exec" {
#     command = <<EOT
# kubectl -n argocd annotate secret cluster-https-kubernetes-default-svc \
#   aws_cluster_name=${local.name} --overwrite
# EOT
#   }
# }
