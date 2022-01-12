package main

import data.kubernetes

name = input.metadata.name
namespace = input.metadata.namespace
spec = input.spec

deny[msg] {
  kubernetes.is_pvc
  not startswith(name, "unittest-")

  msg := sprintf("pvc %v does not start with unittest-. Use: {{ .Release.Name }}- in name", [name])
}

deny[msg] {
  kubernetes.is_pvc
  not spec.storageClassName == "manual"

  msg := sprintf("StorageclassName should be manual in pv %v", [name])
}

deny[msg] {
  kubernetes.is_pvc
  not spec.resources

  msg := sprintf("Resource should be present in pvc %v", [name])
}

deny[msg] {
  kubernetes.is_pvc
  not spec.resources.requests

  msg := sprintf("Resource.requests should be present in pvc %v", [name])
}

deny[msg] {
  kubernetes.is_pvc
  not spec.resources.requests.storage

  msg := sprintf("Resource.requests.storage should be present in pvc %v", [name])
}

deny[msg] {
  kubernetes.is_pvc
  contains(spec.resources.requests.storage,"Gi")
  to_number(split(lower(spec.resources.requests.storage),"gi")[0], storagesize)
  not storagesize <= 100
  type_name(storagesize, types)

  msg := sprintf("Storage above 100Gi is not allowd in pvc %v", [name])
}

deny[msg] {
  kubernetes.is_pvc
  not spec.storageClassName == "manual"

  msg := sprintf("StorageclassName should be manual in pvc %v", [name])
}