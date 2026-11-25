# Adding an S3 bucket without encryption to demonstrate grc-gate blocks merging

resource "aws_s3_bucket" "insecure" {
  bucket = "insecure-bucket"
}
