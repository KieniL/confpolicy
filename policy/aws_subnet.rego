package main

import data.aws

deny[msg] {
	aws.is_subnet
	not input.resource.aws_subnet.public
	msg = "Define public subnet resource"
}

deny[msg] {
	aws.is_subnet
	not re_match(".*public", input.resource.aws_subnet.public.tags.Name)
	msg = "Public subnet missing tag `Name`"
}

deny[msg] {
	aws.is_subnet
	not contains(input.resource.aws_subnet.public.tags.Name, "var.project")
	msg = "VPC name tags Block should have variable `var.project` included "
}

deny[msg] {
	aws.is_subnet
	not input.resource.aws_subnet.public.tags.project
	msg = "VPC missing tag `project`"
}

deny[msg] {
	aws.is_subnet
	not contains(input.resource.aws_subnet.public.tags.project, "var.project")
	msg = "VPC project tags Block should have variable `var.project` included"
}

deny[msg] {
	aws.is_subnet
	not re_match(".*public", input.resource.aws_subnet.public.tags.state)
	msg = "Public subnet missing tag `state`"
}

deny[msg] {
	aws.is_subnet
	not contains(input.resource.aws_subnet.public.availability_zone, "data.aws_availability_zones.available")
	msg = "Use data resources to interpolate availability zone"
}

deny[msg] {
	aws.is_subnet
	not contains(input.resource.aws_subnet.public.cidr_block, "var.subnet_cidr")
	msg = "Subnet CIDR Block should have variable `var.subnet_cidr`"
}

deny[msg] {
	aws.is_subnet
	not contains(input.resource.aws_subnet.public.vpc_id, "var.vpc_id")
	msg = "Subnet vpc_id should have variable `var.vpc_id`"
}
