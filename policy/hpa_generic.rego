package main

import data.kubernetes

name = input.metadata.name
namespace = input.metadata.namespace
spec = input.spec
scaleRef = input.spec.scaleTargetRef

required_selector_labels {
	spec.selector["app"]
}

deny[msg] {
  kubernetes.is_hpa
  not startswith(name, "unittest-")

  msg := sprintf("horizontalpodautoscaler %v does not start with unittest-. Use: {{ .Release.Name }}- in name", [name])
}


deny[msg] {
  kubernetes.is_hpa
  not scaleRef

  msg := sprintf("horizontalpodautoscaler %v does not have a scaleTargetRef", [name])
}

deny[msg] {
  kubernetes.is_hpa
  not scaleRef.apiVersion

  msg := sprintf("scaleTargetRef in horizontalpodautoscaler %v does not have an apiVersion provided", [name])
}

deny[msg] {
  kubernetes.is_hpa
  not scaleRef.kind

  msg := sprintf("scaleTargetRef in horizontalpodautoscaler %v does not have an kind provided", [name])
}

deny[msg] {
  kubernetes.is_hpa
  not scaleRef.name

  msg := sprintf("scaleTargetRef in horizontalpodautoscaler %v does not have an name provided", [name])
}

deny[msg] {
  kubernetes.is_hpa
  not spec.minReplicas

  msg := sprintf("horizontalpodautoscaler %v does not have minReplicas provided", [name])
}

deny[msg] {
  kubernetes.is_hpa
  not spec.maxReplicas

  msg := sprintf("horizontalpodautoscaler %v does not have maxReplicas provided", [name])
}


deny[msg] {
  kubernetes.is_hpa
  not spec.metrics

  msg := sprintf("horizontalpodautoscaler %v does not have a metrics section provided", [name])
}

