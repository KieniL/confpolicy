package main

import data.kubernetes

name = input.metadata.name
namespace = input.metadata.namespace
spec = input.spec

deny[msg] {
  kubernetes.is_pv
  not startswith(name, "unittest-")

  msg := sprintf("pv %v does not start with unittest-. Use: {{ .Release.Name }}- in name", [name])
}

deny[msg] {
  kubernetes.is_pv
  not spec.storageClassName == "manual"

  msg := sprintf("StorageclassName should be manual in pv %v", [name])
}

deny[msg] {
  kubernetes.is_pv
  not spec.capacity

  msg := sprintf("Storagecapacity should be present in pv %v", [name])
}

deny[msg] {
  kubernetes.is_pv
  contains(spec.capacity.storage,"Gi")
  to_number(split(lower(spec.capacity.storage),"gi")[0], storagesize)
  not storagesize <= 100
  type_name(storagesize, types)

  msg := sprintf("Storagecapacity not allowed above 100Gi in pv %v", [name])
}


deny[msg] {
  kubernetes.is_pv
  not spec.persistentVolumeReclaimPolicy == "Retain"

  msg := sprintf("Only Retain Policy is allowed in PersistentVolumeReclaimPolicy in pv %v", [name])
}