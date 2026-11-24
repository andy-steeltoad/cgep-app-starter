######################################################################
# GRC requirements: fixes for GAP-01 through GAP-05.
#
# Primary framework: CMMC Level 2 (NIST SP 800-171).
#
# This terraform addresses the gaps that could be addressed from a 
# seperate tf file, to keep the organization a bit cleaner and the 
# fixes more apparent.
# Two of the gaps, GAP-02 (DynamoDB server_side_encryption) 
# and GAP-05 (Lambda vpc_config), required small in-resource blocks in
# main.tf, because they can not be accessed from a reference to 
# an existing resource
######################################################################

data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
}

######################################################################
# Customer-managed KMS key (CMK) for PHI at rest.
# Used by GAP-01 (S3 uploads) and GAP-02 (DynamoDB submissions).
# CMMC: SC.L2-3.13.11
######################################################################

resource "aws_kms_key" "phi" {
  description             = "CMK for ${local.name_prefix} PHI data stores (S3 uploads, DynamoDB submissions)"
  enable_key_rotation     = true
  deletion_window_in_days = 7 # sandbox; use 30 in production

  # Delegates key access to IAM in this account.
  # This policy matches the default if nothing is specified, but
  # adding it here as an explicit policy allows Conftest to validate
  # and allows Terraform to detect changes made to the policy.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "EnableIAMPolicies"
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::${local.account_id}:root" }
      Action    = "kms:*"
      Resource  = "*"
    }]
  })
}

resource "aws_kms_alias" "phi" {
  name          = "alias/${local.name_prefix}-phi-${local.suffix}"
  target_key_id = aws_kms_key.phi.key_id
}

# S3 and DynamoDB call KMS on the Lambda's behalf. 
resource "aws_iam_role_policy" "lambda_phi_kms" {
  name = "intake-phi-kms"
  role = aws_iam_role.lambda.id

  # Attach permissions for S3 and Dynamo to access the key for
  # encyption and decryption operations
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["kms:GenerateDataKey", "kms:Decrypt", "kms:Encrypt", "kms:DescribeKey"]
      Resource = aws_kms_key.phi.arn
      Condition = {
        StringEquals = {
          "kms:ViaService" = [
            "s3.${var.aws_region}.amazonaws.com",
            "dynamodb.${var.aws_region}.amazonaws.com",
          ]
        }
      }
    }]
  })
}

######################################################################
# GAP-01: S3 uploads bucket encrypted with the CMK (SSE-KMS).
# CMMC: SC.L2-3.13.11
######################################################################

resource "aws_s3_bucket_server_side_encryption_configuration" "uploads" {
  bucket = aws_s3_bucket.uploads.id

  # Apply SSE to the uploads bucket
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.phi.arn
    }
    bucket_key_enabled = true
  }
}

######################################################################
# GAP-02: DynamoDB submissions table encrypted with the CMK.
# Implemented as a server_side_encryption block on
# aws_dynamodb_table.intake in main.tf, using aws_kms_key.phi.
# CMMC: SC.L2-3.13.11
######################################################################

######################################################################
# GAP-03: deny any request to the uploads bucket that isn't over TLS.
# CMMC: SC.L2-3.13.8
######################################################################

resource "aws_s3_bucket_policy" "uploads" {
  bucket = aws_s3_bucket.uploads.id

  # Attach a policy that denies insecure transport (non-TLS)
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.uploads.arn, "${aws_s3_bucket.uploads.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

######################################################################
# GAP-04: Enalbe versioning in the bucket
# so overwritten or deleted files can be recovered
# CMMC: MP.L2-3.8.9
######################################################################

resource "aws_s3_bucket_versioning" "uploads" {
  bucket = aws_s3_bucket.uploads.id

  versioning_configuration {
    status = "Enabled"
  }
}

######################################################################
# GAP-05: Lambda runs inside the VPC's private subnets.
# The Lambda's vpc_config is in main.tf. The private subnets have no
# internet route; the Lambda reaches DynamoDB and S3 only through
# gateway endpoints, and its security group allows nothing else.
# CMMC: SC.L2-3.13.1, SC.L2-3.13.5, AC.L2-3.1.3
######################################################################

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  tags = { Name = "${local.name_prefix}-private-rt" }
}

resource "aws_route_table_association" "private" {
  count          = 2
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# Attach policies limit traffic through each endpoint to this workload's
# resources and to the actions the handler performs.
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "IntakeUploadsOnly"
      Effect    = "Allow"
      Principal = "*"
      Action    = ["s3:PutObject", "s3:GetObject"]
      Resource  = "${aws_s3_bucket.uploads.arn}/*"
    }]
  })

  tags = { Name = "${local.name_prefix}-s3-endpoint" }
}

resource "aws_vpc_endpoint" "dynamodb" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.aws_region}.dynamodb"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "IntakeTableOnly"
      Effect    = "Allow"
      Principal = "*"
      Action    = ["dynamodb:PutItem", "dynamodb:GetItem"]
      Resource  = aws_dynamodb_table.intake.arn
    }]
  })

  tags = { Name = "${local.name_prefix}-dynamodb-endpoint" }
}

# A security group for managing rules
resource "aws_security_group" "lambda" {
  name        = "${local.name_prefix}-lambda-${local.suffix}"
  description = "Intake Lambda: egress to S3 and DynamoDB gateway endpoints only"
  vpc_id      = aws_vpc.main.id

  tags = { Name = "${local.name_prefix}-lambda-sg" }
}

# Egress to the S3 endpoints on 443.
resource "aws_vpc_security_group_egress_rule" "lambda_s3" {
  security_group_id = aws_security_group.lambda.id
  description       = "HTTPS to S3 gateway endpoint"
  prefix_list_id    = aws_vpc_endpoint.s3.prefix_list_id
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

# Egress to the DynamoDB endpoints on 443.
resource "aws_vpc_security_group_egress_rule" "lambda_dynamodb" {
  security_group_id = aws_security_group.lambda.id
  description       = "HTTPS to DynamoDB gateway endpoint"
  prefix_list_id    = aws_vpc_endpoint.dynamodb.prefix_list_id
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

# Policy to allow the Lambda service create and delete the 
# function's network interfaces in the private subnets.
resource "aws_iam_role_policy_attachment" "lambda_vpc_access" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}
