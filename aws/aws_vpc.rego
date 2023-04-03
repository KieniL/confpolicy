package main

import data.aws



deny_missing_default_sg[msg] {
	aws.is_vpc
	default_sg := input.resource.aws_default_security_group[_]
	not default_sg
	msg := sprintf("Define Default Security Group %v ", [default_sg])
}

deny_disabled_dns[msg] {
	aws.is_vpc
	vpc := input.resource.aws_vpc[_]
	not vpc.enable_dns_support
	msg := sprintf("VPC `%v` does not have dns support enabled.", [vpc])
}

deny_disabled_hostname[msg] {
	aws.is_vpc
	vpc := input.resource.aws_vpc[_]
	not vpc.enable_dns_hostnames
	msg = sprintf("VPC `%v` is missing enable dns hostname . Should have enable_dns_hostnames", [vpc])
}

deny_missing_tag_name[msg] {
	aws.is_vpc
	vpc := input.resource.aws_vpc[_]
	not vpc.tags.Name
	msg = sprintf("VPC `%v` is missing tag `Name ", [vpc])
}

deny_missing_tag_project[msg] {
	aws.is_vpc
	vpc := input.resource.aws_vpc[_]
	not vpc.tags.project
	msg = sprintf("VPC `%v` is missing tag `project` ", [vpc])
}

deny_missing_default_sg_ingress_rules[msg] {
	aws.is_vpc
	default_sg := input.resource.aws_default_security_group[_]
	not count(default_sg.ingress) < 1
	msg = sprintf("No ingress on default security group `%v`", [default_sg])
}

deny_missing_default_sg_egress_rules[msg] {
	aws.is_vpc
	default_sg := input.resource.aws_default_security_group[_]
	not count(default_sg.egress) < 1
	msg = sprintf("No egress on default security group `%v`", [default_sg])
}

deny_missing_vpc_id_in_sg[msg] {
	aws.is_vpc
	default_sg := input.resource.aws_default_security_group[_]
	not default_sg.vpc_id
	msg = sprintf("Define vpc_id in securitygroup `%v`", [default_sg])
}

deny_non_referencing_vpc[msg] {
	aws.is_vpc
	default_sg := input.resource.aws_default_security_group[_]
	not contains(default_sg.vpc_id, "aws_vpc[name].id")
	msg = "Securitygroup vpc_id should point to the vpc with aws_vpc[name].id"
}
