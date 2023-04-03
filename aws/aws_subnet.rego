package main

import data.aws

deny[msg] {
	aws.is_subnet
	subnet = input.resource.aws_subnet[_]
	not re_match(".*public", subnet.tags.Name)
	msg = "Public subnet missing tag `Name`"
}
deny[msg] {
	aws.is_subnet
	subnet = input.resource.aws_subnet[_]
	not subnet.tags.project
	msg = "VPC missing tag `project`"
}

deny[msg] {
	aws.is_subnet
	subnet = input.resource.aws_subnet[_]
	not re_match(".*public", subnet.tags.state)
	msg = "Public subnet missing tag `state`"
}

deny[msg] {
	aws.is_subnet
	subnet = input.resource.aws_subnet[_]
	not contains(subnet.availability_zone, "data.aws_availability_zones.available")
	msg = "Use data resources to interpolate availability zone"
}
