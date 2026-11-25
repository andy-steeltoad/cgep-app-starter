# terraform/oidc-trust.tf


variable "github_org" {
  type    = string
  default = "andy-steeltoad"
}

variable "github_repo" {
  type    = string
  default = "cgep-app-starter"
}

variable "tfstate_bucket" {
  type    = string
  default = "acme-health-intake-tfstate-015234162340"
}

variable "tfstate_kms_key_arn" {
  type    = string
  default = "arn:aws:kms:us-east-1:015234162340:key/d0f9049d-0f14-47c9-b82b-0e3abdb6b8b2"
}

resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

resource "aws_iam_role" "grc_gate" {
  name = "cgep-grc-gate"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = aws_iam_openid_connect_provider.github.arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = { "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com" }
        StringLike = {
          "token.actions.githubusercontent.com:sub" = [
            "repo:${var.github_org}/${var.github_repo}:*",     # repos created before Jul 15 2026
            "repo:${var.github_org}@*/${var.github_repo}@*:*", # repos created after: GitHub adds owner + repo IDs
          ]
        }
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "readonly" {
  role       = aws_iam_role.grc_gate.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

# State backend access, shared by the PR plan role and the deploy role.
locals {
  tfstate_access_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "ListStateBucket"
        Effect    = "Allow"
        Action    = "s3:ListBucket"
        Resource  = "arn:aws:s3:::${var.tfstate_bucket}"
        Condition = { StringLike = { "s3:prefix" = ["acme-health-intake/*"] } }
      },
      {
        Sid    = "ReadStateWriteLock"
        Effect = "Allow"
        Action = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
        Resource = [
          "arn:aws:s3:::${var.tfstate_bucket}/acme-health-intake/terraform.tfstate",
          "arn:aws:s3:::${var.tfstate_bucket}/acme-health-intake/terraform.tfstate.tflock",
        ]
      },
      {
        Sid      = "StateKey"
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"]
        Resource = var.tfstate_kms_key_arn
      },
    ]
  })
}

resource "aws_iam_role_policy" "grc_gate_tfstate" {
  name   = "terraform-state-access"
  role   = aws_iam_role.grc_gate.id
  policy = local.tfstate_access_policy
}

output "role_arn" { value = aws_iam_role.grc_gate.arn }

######################################################################
# Deploy role: assumed only by workflows running on refs/heads/main
# (.github/workflows/deploy.yml), after a PR has been approved and
# merged. PR branches can only assume cgep-grc-gate, which is read-only.
#
# CMMC: AC.L2-3.1.5 (least privilege), AC.L2-3.1.7 (prevent non-privileged
# users from running privileged functions), CM.L2-3.4.5 (access
# restrictions for change), AU.L2-3.3.8 (protect audit information).
#
# Guardrails:
# - Write access is limited to the names this stack uses. There are no
#   data-plane permissions on the PHI table or the uploads bucket.
# - The pipeline cannot change its own identity: the OIDC provider and
#   the cgep-* roles are outside its IAM scope, so changes to this file
#   must be applied locally by an administrator.
# - Explicit denies stop the pipeline from turning off CloudTrail or
#   Security Hub, or changing the state backend key.
######################################################################

resource "aws_iam_role" "deploy" {
  name                 = "cgep-deploy"
  max_session_duration = 3600

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = aws_iam_openid_connect_provider.github.arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = { "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com" }
        StringLike = {
          "token.actions.githubusercontent.com:sub" = [
            "repo:${var.github_org}/${var.github_repo}:ref:refs/heads/main",
            "repo:${var.github_org}@*/${var.github_repo}@*:ref:refs/heads/main",
          ]
        }
      }
    }]
  })
}

# Reads for plan/refresh.
resource "aws_iam_role_policy_attachment" "deploy_readonly" {
  role       = aws_iam_role.deploy.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

resource "aws_iam_role_policy" "deploy_tfstate" {
  name   = "terraform-state-access"
  role   = aws_iam_role.deploy.id
  policy = local.tfstate_access_policy
}

# Resource "*" appears only where AWS does not support resource-level
# scoping (EC2/VPC create calls, kms:CreateKey) and in explicit Deny statements.
#tfsec:ignore:aws-iam-no-policy-wildcards
resource "aws_iam_role_policy" "deploy_apply" {
  name = "terraform-apply"
  role = aws_iam_role.deploy.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Lambda"
        Effect = "Allow"
        Action = [
          "lambda:CreateFunction", "lambda:DeleteFunction",
          "lambda:UpdateFunctionCode", "lambda:UpdateFunctionConfiguration",
          "lambda:AddPermission", "lambda:RemovePermission",
          "lambda:PutFunctionConcurrency", "lambda:DeleteFunctionConcurrency",
          "lambda:TagResource", "lambda:UntagResource",
        ]
        Resource = "arn:aws:lambda:${var.aws_region}:${local.account_id}:function:acme-health-intake-handler-*"
      },
      {
        Sid       = "PassLambdaRole"
        Effect    = "Allow"
        Action    = "iam:PassRole"
        Resource  = "arn:aws:iam::${local.account_id}:role/acme-health-intake-lambda-*"
        Condition = { StringEquals = { "iam:PassedToService" = "lambda.amazonaws.com" } }
      },
      {
        Sid    = "LambdaExecutionRole"
        Effect = "Allow"
        Action = [
          "iam:CreateRole", "iam:DeleteRole", "iam:UpdateRole", "iam:UpdateAssumeRolePolicy",
          "iam:TagRole", "iam:UntagRole",
          "iam:PutRolePolicy", "iam:DeleteRolePolicy", "iam:DetachRolePolicy",
        ]
        Resource = "arn:aws:iam::${local.account_id}:role/acme-health-intake-lambda-*"
      },
      {
        Sid      = "LambdaExecutionRoleManagedPolicies"
        Effect   = "Allow"
        Action   = "iam:AttachRolePolicy"
        Resource = "arn:aws:iam::${local.account_id}:role/acme-health-intake-lambda-*"
        Condition = {
          ArnEquals = {
            "iam:PolicyARN" = [
              "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
              "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole",
            ]
          }
        }
      },
      {
        Sid    = "ApiGateway"
        Effect = "Allow"
        Action = [
          "apigateway:GET", "apigateway:POST", "apigateway:PUT", "apigateway:PATCH", "apigateway:DELETE",
          "apigateway:TagResource", "apigateway:UntagResource",
        ]
        Resource = [
          "arn:aws:apigateway:${var.aws_region}::/apis",
          "arn:aws:apigateway:${var.aws_region}::/apis/*",
          "arn:aws:apigateway:${var.aws_region}::/tags/*",
        ]
      },
      {
        # Table management only: no GetItem/Query/Scan on PHI.
        Sid    = "DynamoDBTableManagement"
        Effect = "Allow"
        Action = [
          "dynamodb:CreateTable", "dynamodb:DeleteTable", "dynamodb:UpdateTable",
          "dynamodb:UpdateContinuousBackups", "dynamodb:UpdateTimeToLive",
          "dynamodb:TagResource", "dynamodb:UntagResource",
        ]
        Resource = "arn:aws:dynamodb:${var.aws_region}:${local.account_id}:table/acme-health-intake-submissions-*"
      },
      {
        # Bucket configuration only: no object reads on the uploads bucket.
        Sid    = "S3BucketConfiguration"
        Effect = "Allow"
        Action = [
          "s3:CreateBucket", "s3:DeleteBucket",
          "s3:PutBucketPolicy", "s3:DeleteBucketPolicy",
          "s3:PutEncryptionConfiguration", "s3:PutBucketVersioning",
          "s3:PutBucketPublicAccessBlock", "s3:PutBucketOwnershipControls",
          "s3:PutBucketObjectLockConfiguration", "s3:PutLifecycleConfiguration",
          "s3:PutBucketTagging",
        ]
        Resource = [
          "arn:aws:s3:::acme-health-intake-uploads-*",
          "arn:aws:s3:::grc-evidence-vault-*",
          "arn:aws:s3:::cgep-lab-cloudtrail-*",
        ]
      },
      {
        # Write-once evidence: no delete, no retention override.
        Sid      = "EvidenceVaultUpload"
        Effect   = "Allow"
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.vault.arn}/deployments/*"
      },
      {
        Sid       = "PhiKeyViaS3ForEvidence"
        Effect    = "Allow"
        Action    = ["kms:GenerateDataKey", "kms:Encrypt", "kms:Decrypt"]
        Resource  = aws_kms_key.phi.arn
        Condition = { StringEquals = { "kms:ViaService" = "s3.${var.aws_region}.amazonaws.com" } }
      },
      {
        # DynamoDB creates a grant on the CMK when a table is created or updated.
        Sid       = "PhiKeyGrantForDynamoDB"
        Effect    = "Allow"
        Action    = ["kms:CreateGrant", "kms:DescribeKey"]
        Resource  = aws_kms_key.phi.arn
        Condition = { StringEquals = { "kms:ViaService" = "dynamodb.${var.aws_region}.amazonaws.com" } }
      },
      {
        Sid      = "KmsCreateKey"
        Effect   = "Allow"
        Action   = "kms:CreateKey"
        Resource = "*"
      },
      {
        Sid    = "KmsKeyManagement"
        Effect = "Allow"
        Action = [
          "kms:PutKeyPolicy", "kms:UpdateKeyDescription",
          "kms:EnableKeyRotation", "kms:DisableKeyRotation",
          "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion",
          "kms:TagResource", "kms:UntagResource",
          "kms:CreateAlias", "kms:DeleteAlias", "kms:UpdateAlias",
        ]
        Resource = [
          "arn:aws:kms:${var.aws_region}:${local.account_id}:key/*",
          "arn:aws:kms:${var.aws_region}:${local.account_id}:alias/acme-health-intake-phi-*",
        ]
      },
      {
        Sid    = "VpcNetworking"
        Effect = "Allow"
        Action = [
          "ec2:CreateVpc", "ec2:DeleteVpc", "ec2:ModifyVpcAttribute",
          "ec2:CreateSubnet", "ec2:DeleteSubnet", "ec2:ModifySubnetAttribute",
          "ec2:CreateInternetGateway", "ec2:DeleteInternetGateway",
          "ec2:AttachInternetGateway", "ec2:DetachInternetGateway",
          "ec2:CreateRouteTable", "ec2:DeleteRouteTable",
          "ec2:CreateRoute", "ec2:DeleteRoute", "ec2:ReplaceRoute",
          "ec2:AssociateRouteTable", "ec2:DisassociateRouteTable",
          "ec2:CreateVpcEndpoint", "ec2:DeleteVpcEndpoints", "ec2:ModifyVpcEndpoint",
          "ec2:CreateSecurityGroup", "ec2:DeleteSecurityGroup",
          "ec2:AuthorizeSecurityGroupEgress", "ec2:RevokeSecurityGroupEgress",
          "ec2:AuthorizeSecurityGroupIngress", "ec2:RevokeSecurityGroupIngress",
          "ec2:ModifySecurityGroupRules", "ec2:UpdateSecurityGroupRuleDescriptionsEgress",
          "ec2:CreateTags", "ec2:DeleteTags",
        ]
        Resource  = "*"
        Condition = { StringEquals = { "aws:RequestedRegion" = var.aws_region } }
      },
      {
        Sid    = "CloudTrail"
        Effect = "Allow"
        Action = [
          "cloudtrail:CreateTrail", "cloudtrail:UpdateTrail", "cloudtrail:StartLogging",
          "cloudtrail:PutEventSelectors", "cloudtrail:PutInsightSelectors",
          "cloudtrail:AddTags", "cloudtrail:RemoveTags",
        ]
        Resource = "arn:aws:cloudtrail:${var.aws_region}:${local.account_id}:trail/cgep-capstone"
      },
      {
        Sid    = "SecurityHub"
        Effect = "Allow"
        Action = [
          "securityhub:EnableSecurityHub", "securityhub:BatchEnableStandards",
          "securityhub:UpdateSecurityHubConfiguration",
          "securityhub:TagResource", "securityhub:UntagResource",
        ]
        Resource = "arn:aws:securityhub:${var.aws_region}:${local.account_id}:*"
      },
      {
        Sid       = "SecurityHubServiceLinkedRole"
        Effect    = "Allow"
        Action    = "iam:CreateServiceLinkedRole"
        Resource  = "arn:aws:iam::${local.account_id}:role/aws-service-role/securityhub.amazonaws.com/*"
        Condition = { StringEquals = { "iam:AWSServiceName" = "securityhub.amazonaws.com" } }
      },
      {
        # AU.L2-3.3.8: the pipeline can never switch off audit logging or monitoring.
        Sid    = "DenyDisablingAuditAndMonitoring"
        Effect = "Deny"
        Action = [
          "cloudtrail:StopLogging", "cloudtrail:DeleteTrail",
          "securityhub:DisableSecurityHub", "securityhub:BatchDisableStandards",
          "s3:PutObjectRetention", "s3:PutObjectLegalHold", "s3:BypassGovernanceRetention",
        ]
        Resource = "*"
      },
      {
        # The state key is managed by terraform/bootstrap, not by this stack.
        Sid    = "DenyStateKeyManagement"
        Effect = "Deny"
        Action = [
          "kms:PutKeyPolicy", "kms:DisableKey", "kms:ScheduleKeyDeletion",
          "kms:DisableKeyRotation", "kms:CreateGrant", "kms:TagResource", "kms:UntagResource",
        ]
        Resource = var.tfstate_kms_key_arn
      },
    ]
  })
}

output "deploy_role_arn" { value = aws_iam_role.deploy.arn }
