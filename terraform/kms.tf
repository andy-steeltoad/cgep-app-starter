
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

resource "aws_s3_bucket_public_access_block" "uploads" {
  bucket                  = aws_s3_bucket.uploads.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
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
