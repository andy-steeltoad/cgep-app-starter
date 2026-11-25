# policies/tests/sc_3_13_1_no_internet_test.rego
package compliance.sc_3_13_1_test

import data.compliance.sc_3_13_1
import rego.v1

assoc := {"type": "aws_route_table_association", "name": "private", "expressions": {
	"subnet_id": {"references": ["aws_subnet.private", "count.index"]},
	"route_table_id": {"references": ["aws_route_table.private.id", "aws_route_table.private"]},
}}

plan(resources) := {"configuration": {"root_module": {"resources": resources}}}

test_private_rt_without_internet_route_passes if {
	count(sc_3_13_1.deny) == 0 with input as plan([assoc, {"type": "aws_route_table", "name": "private", "expressions": {}}])
}

test_inline_internet_route_fails if {
	rt := {"type": "aws_route_table", "name": "private", "expressions": {"route": [
		{"cidr_block": {"constant_value": "0.0.0.0/0"}, "gateway_id": {"references": ["aws_internet_gateway.main.id"]}},
	]}}
	count(sc_3_13_1.deny) == 1 with input as plan([assoc, rt])
}

test_standalone_internet_route_fails if {
	route := {"type": "aws_route", "name": "egress", "expressions": {
		"destination_cidr_block": {"constant_value": "0.0.0.0/0"},
		"route_table_id": {"references": ["aws_route_table.private.id", "aws_route_table.private"]},
	}}
	count(sc_3_13_1.deny) == 1 with input as plan([assoc, {"type": "aws_route_table", "name": "private", "expressions": {}}, route])
}
