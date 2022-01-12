package main

allowed_kinds = [
	"ConfigMap",
	"Secret",
	"Service",
	"Deployment",
	"PersistentVolume",
	"PersistentVolumeClaim",
	"HorizontalPodAutoscaler",
	"Ingress",
	"Job",
	"Role",
	"RoleBinding",
	"ServiceAccount",
	"PodDisruptionBudget",
	"NetworkPolicy",
	"Pod",
	"PodSecurityPolicy"
]

allowed_subject_kinds = [
	"ServiceAccount",
	"Group"
]

exists_in_list(element, list) {
	val := list[_]
	element == val
}

deny_not_allowed_kind[msg] {
	val := input.kind
	not exists_in_list(input.kind, allowed_kinds)

  msg = sprintf("%v is not a allowed kind", [val])
}