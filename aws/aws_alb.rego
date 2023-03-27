package main

import data.aws

allowed_ssl_policies = [
    "ELBSecurityPolicy-TLS-1-2-2017-01",
	"ELBSecurityPolicy-TLS13-1-2-2021-06",
	"ELBSecurityPolicy-TLS13-1-2-Res-2021-06",
	"ELBSecurityPolicy-TLS13-1-2-Ext1-2021-06",
	"ELBSecurityPolicy-TLS13-1-2-Ext2-2021-06",
    "ELBSecurityPolicy-TLS13-1-2-Ext2-2021-06",
    "ELBSecurityPolicy-TLS13-1-1-2021-06",
    "ELBSecurityPolicy-TLS13-1-0-2021-06",
    "ELBSecurityPolicy-TLS13-1-3-2021-06",
    "ELBSecurityPolicy-FS-1-2-Res-2020-10",
    "ELBSecurityPolicy-FS-1-2-Res-2019-08",
    "ELBSecurityPolicy-FS-1-2-2019-08",
    "ELBSecurityPolicy-TLS-1-2-Ext-2018-06"
]
    
listener = input.resource.aws_lb_listener

deny[msg] {
	aws.is_lb_listener
	not listener.ssl_policy
    msg := sprintf("lb_listener %v does not have a ssl_policy defined", [listener])
}


deny[msg] {
	aws.is_lb_listener
    listener.ssl_policy
    not exists_in_list(listener.ssl_policy, allowed_ssl_policies)
	
    msg := sprintf("lb_listener %v does not have a ssl_policy defined which allows TLS >= 1.2 or better", [listener])
}