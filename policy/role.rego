package main

import data.kubernetes

name = input.metadata.name
namespace = input.metadata.namespace
rules = input.rules


wildcard_resource_is_in_list(list) {
  list[_] = "*"
}

deny[msg] {
  kubernetes.is_role
  not name

  msg := sprintf("role %v has no name provided", [name])
}

deny[msg] {
  kubernetes.is_role
  not namespace

  msg := sprintf("role %v has no namespace provided", [name])
}

deny[msg] {
  kubernetes.is_role
  not startswith(name, "unittest-")

  msg := sprintf("role %v does not start with unittest-. Use: {{ .Release.Name }}- in name", [name])
}


deny[msg] {
  kubernetes.is_role
  not rules

  msg := sprintf("role %v does not have a rules section", [name])
}

deny[msg] {
  kubernetes.is_role
  rule := input.rules[_]
  wildcard_resource_is_in_list(rule.resources)

  msg := sprintf("role %v does have at least one rule which allow all resources", [name])
}

deny[msg] {
  kubernetes.is_role
  rule := input.rules[_]
  wildcard_resource_is_in_list(rule.verbs)

  msg := sprintf("role %v does have at least one rule which allow all verbs", [name])
}

