# Adding an S3 bucket with encryption and public access blocks
# to demonstrate successful grc-gate


resource "aws_s3_bucket" "prpass" {
  bucket         = "${local.name_prefix}-demo-${local.suffix}"
}

# Attach CMK encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "prpass" {
  bucket = aws_s3_bucket.prpass.id

  # Apply SSE to the prpass bucket
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.phi.arn
    }
    bucket_key_enabled = true
  }
}

# pre-configure the ARN so the bucket policy will generate and have
# something for conftest to validate against
locals {
  prpass_arn = "arn:aws:s3:::${aws_s3_bucket.prpass.bucket}"
}

# Attach a policy that denies insecure transport (non-TLS)
resource "aws_s3_bucket_policy" "prpass" {
  bucket = aws_s3_bucket.prpass.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [local.prpass_arn, "${local.prpass_arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

# Explicitly block public access
resource "aws_s3_bucket_public_access_block" "prpass" {
  bucket                  = aws_s3_bucket.prpass.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}