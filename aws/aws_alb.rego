package main

import data.aws

listener = input.resource.aws_lb_listener
deny[msg] {
	aws.is_lb_listener
	not listener.ssl_policy
    msg := sprintf("lb_listener %v does not have a ssl_policy defined", [listener])
}