# policies/sc_3_13_8_secure_transmission.rego
# METADATA
# title: SC.L2-3.13.8 - Secure Transmission
# description: "Every aws_s3_bucket must deny insecure transmissions"
# custom:
#   control_id: 3.13.8
#   framework: nist-800-171
#   severity: critical
#   remediation: "Reject uploads where aws:SecureTransport is false."

package compliance.sc_3_13_8

import rego.v1

deny contains msg if {
	bucket := bucket_addresses[_]
	not denies_insecure_transport(bucket)
	msg := sprintf(
		"[SC.L2-3.13.8] %s: no aws_s3_bucket_policy denying requests where aws:SecureTransport is false. Remediation: Add policy to deny access when aws:SecureTransport is false",
		[bucket],
	)
}

bucket_addresses contains addr if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket"
	addr := sprintf("aws_s3_bucket.%s", [r.name])
}

denies_insecure_transport(bucket_addr) if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket_policy"
	some ref in r.expressions.bucket.references
	references_bucket(ref, bucket_addr)
	some p in input.planned_values.root_module.resources
	p.address == sprintf("aws_s3_bucket_policy.%s", [r.name])
	some stmt in json.unmarshal(p.values.policy).Statement
	stmt.Effect == "Deny"
	stmt.Condition.Bool["aws:SecureTransport"] == "false"
}

references_bucket(ref, bucket_addr) if ref == bucket_addr
references_bucket(ref, bucket_addr) if ref == sprintf("%s.id", [bucket_addr])
references_bucket(ref, bucket_addr) if ref == sprintf("%s.bucket", [bucket_addr])
