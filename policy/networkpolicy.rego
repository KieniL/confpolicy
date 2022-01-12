package main

import data.kubernetes

name = input.metadata.name
namespace = input.metadata.namespace
spec = input.spec

deny[msg] {
  kubernetes.is_networkpolicy
  not name

  msg := sprintf("networkpolicy %v has no name provided", [name])
}

deny[msg] {
  kubernetes.is_networkpolicy
  not namespace

  msg := sprintf("networkpolicy %v has no namespace provided", [name])
}

deny[msg] {
  kubernetes.is_networkpolicy
  not startswith(name, "unittest-")

  msg := sprintf("networkpolicy %v does not start with unittest-. Use: {{ .Release.Name }}- in name", [name])
}

deny[msg] {
  kubernetes.is_networkpolicy
  not spec.ingress

  msg := sprintf("networkpolicy %v has no ingress provided", [name])
}

deny[msg] {
  kubernetes.is_networkpolicy
  not spec.egress

  msg := sprintf("networkpolicy %v has no egress provided", [name])
}