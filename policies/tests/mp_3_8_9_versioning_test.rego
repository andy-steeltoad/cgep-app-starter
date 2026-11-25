# policies/tests/mp_3_8_9_versioning_test.rego
package compliance.mp_3_8_9_test

import data.compliance.mp_3_8_9
import rego.v1

plan(status) := {
	"configuration": {"root_module": {"resources": [
		{"type": "aws_s3_bucket", "name": "uploads"},
		{
			"type": "aws_s3_bucket_versioning", "name": "uploads",
			"expressions": {"bucket": {"references": ["aws_s3_bucket.uploads.id", "aws_s3_bucket.uploads"]}},
		},
	]}},
	"planned_values": {"root_module": {"resources": [
		{"address": "aws_s3_bucket_versioning.uploads", "values": {"versioning_configuration": [{"status": status}]}},
	]}},
}

test_enabled_versioning_passes if {
	count(mp_3_8_9.deny) == 0 with input as plan("Enabled")
}

test_suspended_versioning_fails if {
	count(mp_3_8_9.deny) == 1 with input as plan("Suspended")
}

test_missing_versioning_fails if {
	count(mp_3_8_9.deny) == 1 with input as {"configuration": {"root_module": {"resources": [{"type": "aws_s3_bucket", "name": "uploads"}]}}}
}
