# policies/tests/sc_3_13_11_encryption_test.rego
package compliance.sc_3_13_11_test

import data.compliance.sc_3_13_11
import rego.v1

bucket := {"type": "aws_s3_bucket", "name": "uploads"}

sse := {
	"type": "aws_s3_bucket_server_side_encryption_configuration", "name": "uploads",
	"expressions": {"bucket": {"references": ["aws_s3_bucket.uploads.id", "aws_s3_bucket.uploads"]}},
}

test_encrypted_bucket_passes if {
	count(sc_3_13_11.deny) == 0 with input as {"configuration": {"root_module": {"resources": [bucket, sse]}}}
}

test_unencrypted_bucket_fails if {
	count(sc_3_13_11.deny) == 1 with input as {"configuration": {"root_module": {"resources": [bucket]}}}
}
