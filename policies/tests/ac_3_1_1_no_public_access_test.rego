# policies/tests/ac_3_1_1_no_public_access_test.rego
package compliance.ac_3_1_1_test

import data.compliance.ac_3_1_1
import rego.v1

plan(flags) := {
	"configuration": {"root_module": {"resources": [
		{"type": "aws_s3_bucket", "name": "uploads"},
		{
			"type": "aws_s3_bucket_public_access_block", "name": "uploads",
			"expressions": {"bucket": {"references": ["aws_s3_bucket.uploads.id", "aws_s3_bucket.uploads"]}},
		},
	]}},
	"planned_values": {"root_module": {"resources": [
		{"address": "aws_s3_bucket_public_access_block.uploads", "values": flags},
	]}},
}

all_true := {"block_public_acls": true, "block_public_policy": true, "ignore_public_acls": true, "restrict_public_buckets": true}

test_complete_pab_passes if {
	count(ac_3_1_1.deny) == 0 with input as plan(all_true)
}

test_incomplete_pab_fails if {
	count(ac_3_1_1.deny) == 1 with input as plan(object.union(all_true, {"block_public_policy": false}))
}

test_missing_pab_fails if {
	count(ac_3_1_1.deny) == 1 with input as {"configuration": {"root_module": {"resources": [{"type": "aws_s3_bucket", "name": "uploads"}]}}}
}
