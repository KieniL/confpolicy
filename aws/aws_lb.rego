package main

import data.aws

exists_in_list(element, list) {
	val := list[_]
	element == val
}

allowed_alb_ssl_policies = [
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

allowed_nlb_ssl_policies = [
    "ELBSecurityPolicy-TLS13-1-2-2021-06",
    "ELBSecurityPolicy-TLS13-1-3-2021-06",
    "ELBSecurityPolicy-TLS13-1-2-Res-2021-06",
    "ELBSecurityPolicy-TLS13-1-2-Ext1-2021-06",
    "ELBSecurityPolicy-TLS13-1-2-Ext2-2021-06",
    "ELBSecurityPolicy-FS-1-2-2019-08",
    "ELBSecurityPolicy-FS-1-2-Res-2019-08",
    "ELBSecurityPolicy-FS-1-2-Res-2020-10",
    "ELBSecurityPolicy-TLS-1-2-Ext-2018-06",
    "ELBSecurityPolicy-TLS-1-2-2017-01"
]

listener = input.resource.aws_lb_listener
protocol := listener[_].protocol
ssl_policy := listener[_].ssl_policy

deny_missing_https_on_alb[msg] {
	aws.is_lb_listener

  not exists_in_list(protocol, ["HTTPS", "TLS", "TCP", "UDP", "TCP_UDP"])

  msg := sprintf("lb_listener %v for ALB does not have HTTPS defined", [listener])
}

deny_missing_tls_on_nlb[msg] {
	aws.is_lb_listener

  not exists_in_list(protocol, ["HTTPS", "HTTP", "TLS"])

  msg := sprintf("lb_listener %v for NLB does not have TLS defined", [listener])
}

deny_missing_policy[msg] {
	aws.is_lb_listener

	not ssl_policy
  msg := sprintf("lb_listener %v does not have a ssl_policy defined", [listener])
}

deny_nlb_non_higher_tls1_2[msg] {
	aws.is_lb_listener

  protocol = "TLS"
  ssl_policy
  not exists_in_list(ssl_policy, allowed_nlb_ssl_policies)

  msg := sprintf("lb_listener %v must use a secure SSL policy with TLS >= 1.2. See https://docs.aws.amazon.com/elasticloadbalancing/latest/network/create-tls-listener.html", [listener])
}

deny_alb_non_higher_tls1_2[msg] {
	aws.is_lb_listener

  protocol = "HTTPS"
  ssl_policy
  not exists_in_list(ssl_policy, allowed_alb_ssl_policies)

  msg := sprintf("lb_listener %v must use a secure SSL policy with TLS >= 1.2. See https://docs.aws.amazon.com/elasticloadbalancing/latest/network/create-tls-listener.html", [listener])
}

# deny_non_tls1_2[msg] {
# 	aws.is_lb_listener

#   ssl_policy
#   # and not has_tls_v12_or_higher(listener_attrs)) 
#   # or
#   # ((listener_attrs.protocol == "TCP" or listener_attrs.protocol == "TLS") and listener_attrs.ssl_policy == null and not has_tls_v1_or_higher(listener_attrs)) 

#   msg := sprintf("Load balancer %v must use a secure SSL policy", [listener.protocol])

# }

#https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html