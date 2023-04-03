package main

import data.aws

deny_missing_resource[msg] {
	aws.is_vpc
	not input.resource.aws_vpc.main
	msg = "Define VPC resource"
}

deny_missing_default_sg[msg] {
	aws.is_vpc
	not input.resource.aws_default_security_group.ident
	msg = "Define Default Security Group"
}

deny_disabled_dns[msg] {
	aws.is_vpc
	not input.resource.aws_vpc.main.enable_dns_support
	msg = "VPC is missing enable dns. Should have enable_dns_support"
}

deny_disabled_hostname[msg] {
	aws.is_vpc
	not input.resource.aws_vpc.main.enable_dns_hostnames
	msg = "VPC is missing enable dns hostname . Should have enable_dns_hostnames"
}

deny_missing_cidr_variable[msg] {
	aws.is_vpc
	not contains(input.resource.aws_vpc.main.cidr_block, "var.vpc_cidr")
	msg = "VPC CIDR Block should have variable `var.vpc_cidr`"
}

deny_missing_tag_name[msg] {
	aws.is_vpc
	not input.resource.aws_vpc.main.tags.Name
	msg = "VPC missing tag `Name`"
}

deny_missing_variable_project[msg] {
	aws.is_vpc
	not contains(input.resource.aws_vpc.main.tags.Name, "var.project")
	msg = "VPC name tags Block should have variable `var.project` included "
}

deny_missing_tag_project[msg] {
	aws.is_vpc
	not input.resource.aws_vpc.main.tags.project
	msg = "VPC missing tag `project`"
}

deny_missing_variable_project[msg] {
	aws.is_vpc
	not contains(input.resource.aws_vpc.main.tags.project, "var.project")
	msg = "VPC project tags Block should have variable `var.project` included"
}

deny_missing_default_sg_ingress_rules[msg] {
	aws.is_vpc
	not count(input.resource.aws_default_security_group.ident.ingress) < 1
	msg = "No ingress on default security group is allowed"
}

deny_missing_default_sg_egress_rules[msg] {
	aws.is_vpc
	not count(input.resource.aws_default_security_group.ident.egress) < 1
	msg = "No egress on default security group is allowed"
}

deny_missing_vpc_id_in_sg[msg] {
	aws.is_vpc
	not input.resource.aws_default_security_group.ident.vpc_id
	msg = "Define vpc_id in securitygroup"
}

deny_non_referencing_vpc[msg] {
	aws.is_vpc
	not contains(input.resource.aws_default_security_group.ident.vpc_id, "aws_vpc.main.id")
	msg = "Securitygroup vpc_id should point to the vpc with aws_vpc.main.id"
}
