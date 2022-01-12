package main

import data.kubernetes

name = input.metadata.name
namespace = input.metadata.namespace

deny[msg] {
  kubernetes.is_service_account
  not name

  msg := sprintf("serviceaccount %v has no name provided", [name])
}

deny[msg] {
  kubernetes.is_service_account
  not namespace

  msg := sprintf("serviceaccount %v has no namespace provided", [name])
}

deny[msg] {
  kubernetes.is_service_account
  not startswith(name, "unittest-")

  msg := sprintf("serviceaccount %v does not start with unittest-. Use: {{ .Release.Name }}- in name", [name])
}

