package main

required_labels {
	input.metadata.labels["app.kubernetes.io/name"]
	input.metadata.labels["app.kubernetes.io/instance"]
	input.metadata.labels["app.kubernetes.io/version"]
	input.metadata.labels["app.kubernetes.io/component"]
	input.metadata.labels["app.kubernetes.io/part-of"]
	input.metadata.labels["app.kubernetes.io/managed-by"]
}

# a list of ressources which needes a serviceaccount
serviceaccount_needed = [
	"unittest-ansparservice",
	"unittest-authservice",
	"unittest-certservice",
	"unittest-mysql",
]

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
	"PodSecurityPolicy",
]

allowed_subject_kinds = [
	"ServiceAccount",
	"Group",
]

deny[msg] {
	not required_labels
	msg = sprintf("%s of kind %s must include Kubernetes recommended labels: https://kubernetes.io/docs/concepts/overview/working-with-objects/common-labels/#labels", [name, input.kind])
}

exists_in_list(element, list) {
	val := list[_]
	element == val
}

deny_not_allowed_kind[msg] {
	val := input.kind
	not exists_in_list(input.kind, allowed_kinds)

	msg = sprintf("%v is not a allowed kind", [val])
}
