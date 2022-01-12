package main

import data.kubernetes

name = input.metadata.name
namespace = input.metadata.namespace
spec = input.spec

required_selector_labels {
	spec.selector["app.kubernetes.io/name"]
}

deny[msg] {
  kubernetes.is_service
  not startswith(name, "unittest-")

  msg := sprintf("service %v does not start with", [name])
}

deny[msg] {
  kubernetes.is_service
  not spec.type

  msg := sprintf("Service %v does not have a type", [name])
}

deny[msg] {
  kubernetes.is_service
  not spec.type == "ClusterIP"

  msg := sprintf("Service %v is not of type ´ClusterIP´", [name])
}

deny[msg] {
  kubernetes.is_service
  not spec.selector

  msg := sprintf("service %v does not have a selector section", [name])
}

deny[msg] {
  kubernetes.is_service
  not required_selector_labels

  msg := sprintf("Does not contain label app in select for service %v", [name])
}


