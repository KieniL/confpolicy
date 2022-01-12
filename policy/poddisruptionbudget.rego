package main

import data.kubernetes

name = input.metadata.name
namespace = input.metadata.namespace
spec = input.spec

deny[msg] {
  kubernetes.is_poddisruptionbudget
  not name

  msg := sprintf("poddisruptionbudget %v has no name provided", [name])
}

deny[msg] {
  kubernetes.is_poddisruptionbudget
  not namespace

  msg := sprintf("poddisruptionbudget %v has no namespace provided", [name])
}

deny[msg] {
  kubernetes.is_poddisruptionbudget
  not startswith(name, "unittest-")

  msg := sprintf("poddisruptionbudget %v does not start with unittest-. Use: {{ .Release.Name }}- in name", [name])
}

deny[msg] {
  kubernetes.is_poddisruptionbudget
  not spec.selector

  msg := sprintf("poddisruptionbudget %v does not have a selector", [name])
}

deny[msg] {
  kubernetes.is_poddisruptionbudget
  not spec.maxUnavailable
  not spec.minAvailable

  msg := sprintf("poddisruptionbudget %v does not have a maxUnavailable or minAvailable", [name])
}

deny[msg] {
  kubernetes.is_poddisruptionbudget
  spec.minAvailable
  spec.maxUnavailable

  msg := sprintf("poddisruptionbudget %v does have maxUnavailable and minAvailable set. Cannot be both set", [name])
}