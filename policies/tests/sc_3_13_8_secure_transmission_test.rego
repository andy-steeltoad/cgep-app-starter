# policies/tests/sc_3_13_8_secure_transmission_test.rego
package compliance.sc_3_13_8_test

import data.compliance.sc_3_13_8
import rego.v1

plan(statement) := {
	"configuration": {"root_module": {"resources": [
		{"type": "aws_s3_bucket", "name": "uploads"},
		{
			"type": "aws_s3_bucket_policy", "name": "uploads",
			"expressions": {"bucket": {"references": ["aws_s3_bucket.uploads.id", "aws_s3_bucket.uploads"]}},
		},
	]}},
	"planned_values": {"root_module": {"resources": [
		{"address": "aws_s3_bucket_policy.uploads", "values": {"policy": json.marshal({"Version": "2012-10-17", "Statement": [statement]})}},
	]}},
}

deny_insecure := {"Effect": "Deny", "Principal": "*", "Action": "s3:*", "Condition": {"Bool": {"aws:SecureTransport": "false"}}}

test_tls_only_policy_passes if {
	count(sc_3_13_8.deny) == 0 with input as plan(deny_insecure)
}

test_policy_without_tls_condition_fails if {
	count(sc_3_13_8.deny) == 1 with input as plan({"Effect": "Deny", "Principal": "*", "Action": "s3:DeleteBucket"})
}

test_missing_policy_fails if {
	count(sc_3_13_8.deny) == 1 with input as {"configuration": {"root_module": {"resources": [{"type": "aws_s3_bucket", "name": "uploads"}]}}}
}
