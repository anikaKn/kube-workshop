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

provider "helm" {
  kubernetes {
    host                   = module.eks.cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
    token                  = data.aws_eks_cluster_auth.eks.token
    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      # This requires the awscli to be installed locally where Terraform is executed
      args = ["eks", "get-token", "--cluster-name", module.eks.cluster_name, "--region", local.region]
    }
  }
}

provider "kubernetes" {
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
    token                  = data.aws_eks_cluster_auth.eks.token

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    # This requires the awscli to be installed locally where Terraform is executed
    args = ["eks", "get-token", "--cluster-name", module.eks.cluster_name, "--region", local.region]
  }
}

locals {
  name            = "hub-cluster"
  environment     = "control-plane"
  region          = data.aws_region.current.id
  cluster_version = var.kubernetes_version
  vpc_cidr        = var.vpc_cidr

  username                       = "anikaKn"
  paasword                       = var.git_token
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
    enable_external_secrets                      = false
    enable_aws_load_balancer_controller          = true
    enable_fargate_fluentbit                     = false
    enable_aws_for_fluentbit                     = false
    enable_aws_node_termination_handler          = false
    enable_karpenter                             = false
    enable_velero                                = false
    enable_aws_gateway_api_controller            = false
    enable_aws_ebs_csi_resources                 = true # generate gp2 and gp3 storage classes for ebs-csi
    enable_aws_secrets_store_csi_driver_provider = false
    enable_aws_argocd                            = false
  }
  oss_addons = {
    enable_argocd             = false # disable default argocd application set, we enable enable_aws_argocd above
    enable_aws_argocd_ingress = true
    #enable_argo_rollouts                         = true
    #enable_argo_events                          = true
    #enable_argo_workflows                        = true
    #enable_cluster_proportional_autoscaler       = true
    #enable_gatekeeper                            = true
    #enable_gpu_operator                          = true
    #enable_ingress_nginx                         = true
    #enable_kyverno                               = true
    #enable_kube_prometheus_stack                 = true
    enable_metrics_server = true
    #enable_prometheus_adapter                    = true
    #enable_secrets_store_csi_driver              = true
    #enable_vpa                                   = true
    #enable_foo                                   = true # you can add any addon here, make sure to update the gitops repo with the corresponding application set
  }
  addons = merge(local.aws_addons, local.oss_addons, { kubernetes_version = local.cluster_version }, { aws_cluster_name = module.eks.cluster_name })

  addons_metadata = merge(
    module.eks_blueprints_addons.gitops_metadata,
    {
      aws_cluster_name = module.eks.cluster_name
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
    }
  )

  argocd_apps = {
    addons   = file("${path.module}/bootstrap/addons.yaml")
    platform = file("${path.module}/bootstrap/platform.yaml")
  }

  azs = slice(data.aws_availability_zones.available.names, 0, 3)

kubernetes_admins = [
    {
      userarn    = "arn:aws:iam::022698001278:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_PowerUserAccessCustom_a7d8c8044914d012"
      username   = "aknys"
      policy_arn = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
    }
    ]


  tags = {
    Blueprint  = local.name
    GithubRepo = "github.com/csantanapr/terraform-gitops-bridge"
    Owner      = "aknys@softserveinc.com"
    Schedule   = "running" #"utc-06:00-16:00"
  }
}

################################################################################
# GitOps Bridge: Private ssh keys for git
################################################################################
resource "kubernetes_namespace" "argocd" {
  depends_on = [module.eks_blueprints_addons]
  metadata {
    name = local.argocd_namespace
  }
}
resource "kubernetes_secret" "git_secrets" {
  depends_on = [kubernetes_namespace.argocd]
  for_each = {
    git-addons = {
      type = "git"
      url  = local.gitops_addons_url
      # sshPrivateKey         = file(pathexpand(local.git_private_ssh_key))
      # insecureIgnoreHostKey = "true"
      username = local.username
      paasword = local.paasword
    }
    git-platform = {
      type = "git"
      url  = local.gitops_platform_url
      # sshPrivateKey         = file(pathexpand(local.git_private_ssh_key))
      # insecureIgnoreHostKey = "true"
      username = local.username
      paasword = local.paasword
    }
    git-workloads = {
      type = "git"
      url  = local.gitops_workload_url
      # sshPrivateKey         = file(pathexpand(local.git_private_ssh_key))
      # insecureIgnoreHostKey = "true"
      username = local.username
      paasword = local.paasword
    }
    git-manifest = {
      type = "git"
      url  = local.gitops_manifest_url
      # sshPrivateKey         = file(pathexpand(local.git_private_ssh_key))
      # insecureIgnoreHostKey = "true"
      username = local.username
      paasword = local.paasword
    }

  }
  metadata {
    name      = each.key
    namespace = kubernetes_namespace.argocd.metadata[0].name
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
  version = "0.0.1"
  cluster = {
    cluster_name = module.eks.cluster_name
    environment  = local.environment
    metadata     = local.addons_metadata
    addons       = local.addons
  }
  apps = local.argocd_apps
  argocd = {
    namespace        = local.argocd_namespace
    chart_version    = local.argocd_chart_version #"5.51.1"
    timeout          = 600
    create_namespace = false
    set = [
      {
        name  = "server.service.type"
        value = "LoadBalancer"
      },
      {
        name  = "server.serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
        value = module.argocd_irsa.iam_role_arn
      },
      {
        name  = "applicationSet.serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
        value = module.argocd_irsa.iam_role_arn
      },
      {
        name  = "controller.serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
        value = module.argocd_irsa.iam_role_arn
      }
    ]
  }
  depends_on = [kubernetes_secret.git_secrets]
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

data "aws_iam_policy_document" "irsa_policy" {
  statement {
    effect    = "Allow"
    resources = ["*"]
    actions   = ["sts:AssumeRole"]
  }

  # statement {
  #   effect    = "Allow"
  #   resources = ["*"]
  #   actions   = ["route53:ListHostedZones"]
  # }
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
}

################################################################################
# EKS Cluster
################################################################################
#tfsec:ignore:aws-eks-enable-control-plane-logging
module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.26"

  cluster_name                   = local.name
  cluster_version                = local.cluster_version
  cluster_endpoint_public_access = true

  # Combine root account, current user/role and additinoal roles to be able to access the cluster KMS key - required for terraform updates
  kms_key_administrators = distinct(concat([
    "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"],
    var.kms_key_admin_roles,
    [data.aws_iam_session_context.current.issuer_arn]

  ))
  # Optional: Adds the current caller identity as an administrator via cluster access entry
  enable_cluster_creator_admin_permissions = true

  # Manage aws-auth configmap to be able to add workshop roles into it
  # manage_aws_auth_configmap = true
  # authentication_mode = "API_AND_CONFIG_MAP"
  # manage_aws_auth = true # test
  # aws_auth_roles            = var.aws_auth_roles

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  eks_managed_node_groups = {
    initial = {
      instance_types = ["t3.medium"]

      min_size     = 1
      max_size     = 2
      desired_size = 1
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
          ENABLE_PREFIX_DELEGATION = "true"
          WARM_PREFIX_TARGET       = "1"
        }
      })
    }
  }
# access_entries = { for admin in local.kubernetes_admins : admin.username => {
#     kubernetes_groups = [],
#     principal_arn     = admin.userarn,
#     policy_associations = {
#       admin_policy = {
#         policy_arn = admin.policy_arn #"arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy",
#         access_scope = {
#           type = "cluster"
#         }
#       }
#     }
#     }
  # }

  tags = local.tags
}

################################################################################
# Supporting Resources
################################################################################
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"

  name = local.name
  cidr = local.vpc_cidr

  azs             = local.azs
  private_subnets = [for k, v in local.azs : cidrsubnet(local.vpc_cidr, 4, k)]
  public_subnets  = [for k, v in local.azs : cidrsubnet(local.vpc_cidr, 8, k + 48)]

  enable_nat_gateway = true
  single_nat_gateway = true

  public_subnet_tags = {
    "kubernetes.io/role/elb" = 1
  }

  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = 1
  }

  tags = local.tags
}
