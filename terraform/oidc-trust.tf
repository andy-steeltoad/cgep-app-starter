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

resource "aws_iam_role_policy" "grc_gate_tfstate" {
  name = "terraform-state-access"
  role = aws_iam_role.grc_gate.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ListStateBucket"
        Effect   = "Allow"
        Action   = "s3:ListBucket"
        Resource = "arn:aws:s3:::${var.tfstate_bucket}"
        Condition = { StringLike = { "s3:prefix" = ["acme-health-intake/*"] } }
      },
      {
        Sid      = "ReadStateWriteLock"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
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

output "role_arn" { value = aws_iam_role.grc_gate.arn }