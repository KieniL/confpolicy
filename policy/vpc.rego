package main

deny[msg] {
	not input.resource.aws_vpc.main
	msg = "Define VPC resource"
}

deny[msg] {
	not input.resource.aws_default_security_group.ident
	msg = "Define Default Security Group"
}

deny[msg] {
	not input.resource.aws_vpc.main.enable_dns_support
	msg = "VPC is missing enable dns. Should have enable_dns_support"
}

deny[msg] {
	not input.resource.aws_vpc.main.enable_dns_hostnames
	msg = "VPC is missing enable dns hostname . Should have enable_dns_hostnames"
}

deny[msg] {
	not contains(input.resource.aws_vpc.main.cidr_block, "var.vpc_cidr")
	msg = "VPC CIDR Block should have variable `var.vpc_cidr`"
}

deny[msg] {
	not input.resource.aws_vpc.main.tags.Name
	msg = "VPC missing tag `Name`"
}

deny[msg] {
	not contains(input.resource.aws_vpc.main.tags.Name, "var.project")
	msg = "VPC name tags Block should have variable `var.project` included "
}

deny[msg] {
	not input.resource.aws_vpc.main.tags.project
	msg = "VPC missing tag `project`"
}

deny[msg] {
	not contains(input.resource.aws_vpc.main.tags.project, "var.project")
	msg = "VPC project tags Block should have variable `var.project` included"
}

deny[msg] {
	not count(input.resource.aws_default_security_group.ident.ingress) < 1
	msg = "No ingress on default security group is allowed"
}

deny[msg] {
	not count(input.resource.aws_default_security_group.ident.egress) < 1
	msg = "No egress on default security group is allowed"
}

deny[msg] {
	not input.resource.aws_default_security_group.ident.vpc_id
	msg = "Define vpc_id in securitygroup"
}

deny[msg] {
	not contains(input.resource.aws_default_security_group.ident.vpc_id, "aws_vpc.main.id")
	msg = "Securitygroup vpc_id should point to the vpc with aws_vpc.main.id"
}
