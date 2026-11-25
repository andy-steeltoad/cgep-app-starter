# policies/mp_3_8_9_versioning.rego
# METADATA
# title: MP.L2-3.8.9 - Protect Backups
# description: "Every aws_s3_bucket must have versioning enabled to protect backups from overwrite"
# custom:
#   control_id: 3.8.9
#   framework: nist-800-171
#   severity: high
#   remediation: "Add aws_s3_bucket_versioning { status = enabled } for the bucket."

package compliance.mp_3_8_9

import rego.v1

deny contains msg if {
	bucket := bucket_addresses[_]
	not has_versioning(bucket)
	msg := sprintf(
		"[MP.L2-3.8.9] %s: no aws_s3_bucket_versioning with status Enabled references this bucket. Remediation: Add aws_s3_bucket_versioning { status = enabled } for the bucket.",
		[bucket],
	)
}

bucket_addresses contains addr if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket"
	addr := sprintf("aws_s3_bucket.%s", [r.name])
}

has_versioning(bucket_addr) if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket_versioning"
	some ref in r.expressions.bucket.references
	references_bucket(ref, bucket_addr)
	some p in input.planned_values.root_module.resources
	p.address == sprintf("aws_s3_bucket_versioning.%s", [r.name])
	p.values.versioning_configuration[0].status == "Enabled"
}

references_bucket(ref, bucket_addr) if ref == bucket_addr
references_bucket(ref, bucket_addr) if ref == sprintf("%s.id", [bucket_addr])
references_bucket(ref, bucket_addr) if ref == sprintf("%s.bucket", [bucket_addr])
