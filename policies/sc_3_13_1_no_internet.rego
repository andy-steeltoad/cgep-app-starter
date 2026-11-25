# policies/sc_3_13_1_no_internet.rego
# METADATA
# title: SC.L2-3.13.1 - No Internet Route
# description: "Private subnets must not have internet routes"
# custom:
#   control_id: 3.13.1
#   framework: nist-800-171
#   severity: critical
#   remediation: "Remove internet routes from private subnets"

package compliance.sc_3_13_1

import rego.v1

deny contains msg if {
	some rt in private_route_tables
	has_internet_route(rt)
	msg := sprintf(
		"[SC.L2-3.13.1] aws_route_table.%s: associated with a private subnet but has a 0.0.0.0/0 route. Remediation: Remove internet routes from private subnets",
		[rt],
	)
}

# Route tables associated with any aws_subnet whose name contains "private".
private_route_tables contains rt if {
	some a in input.configuration.root_module.resources
	a.type == "aws_route_table_association"
	some sref in a.expressions.subnet_id.references
	startswith(sref, "aws_subnet.")
	contains(split(sref, ".")[1], "private")
	some rref in a.expressions.route_table_id.references
	startswith(rref, "aws_route_table.")
	rt := split(split(rref, ".")[1], "[")[0]
}

# Inline route block on the route table.
has_internet_route(rt) if {
	some r in input.configuration.root_module.resources
	r.type == "aws_route_table"
	r.name == rt
	some route in r.expressions.route
	route.cidr_block.constant_value == "0.0.0.0/0"
}

# Standalone aws_route targeting the route table.
has_internet_route(rt) if {
	some r in input.configuration.root_module.resources
	r.type == "aws_route"
	r.expressions.destination_cidr_block.constant_value == "0.0.0.0/0"
	some ref in r.expressions.route_table_id.references
	startswith(ref, sprintf("aws_route_table.%s", [rt]))
}
