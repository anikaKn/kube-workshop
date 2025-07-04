#!/usr/bin/env bash
export ACCOUNT_ID=$(aws sts get-caller-identity --output text --query Account)
export AWS_DEFAULT_REGION="us-west-2"
export WORKING_DIR=$PWD
export WORKSHOP_DIR=$PWD
export GITOPS_DIR="$WORKING_DIR/gitops-repos"
#git clone https://github.com/aws-samples/argocd-on-amazon-eks-workshop $WORKSHOP_DIR
cd $WORKSHOP_DIR
set -euo pipefail
echo "" > ~/.ssh/config # My code
SCRIPTDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
ROOTDIR=$SCRIPTDIR
[[ -n "${DEBUG:-}" ]] && set -x

# For AWS EC2 override with
# export TF_VAR_ssh_key_basepath="/home/ec2-user/.ssh"

# Deploy the infrastructure
${ROOTDIR}/terraform/github-actions/deploy.sh
# ${ROOTDIR}/terraform/codecommit/deploy.sh
# source ${ROOTDIR}/setup-git.sh
${ROOTDIR}/terraform/hub/deploy.sh
# ${ROOTDIR}/terraform/spokes/deploy.sh staging
# ${ROOTDIR}/terraform/spokes/deploy.sh prod
source ${ROOTDIR}/setup-kubectx.sh
