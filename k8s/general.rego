package kubernetes

required_labels {
	input.metadata.labels["app.kubernetes.io/name"]
	input.metadata.labels["app.kubernetes.io/instance"]
	input.metadata.labels["app.kubernetes.io/version"]
	input.metadata.labels["app.kubernetes.io/component"]
	input.metadata.labels["app.kubernetes.io/part-of"]
	input.metadata.labels["app.kubernetes.io/managed-by"]
}

deny[msg] {
	not required_labels
	msg = sprintf("%s of kind %s must include Kubernetes recommended labels: https://kubernetes.io/docs/concepts/overview/working-with-objects/common-labels/#labels", [name, input.kind])
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

exists_in_list(element, list) {
	val := list[_]
	element == val
}

deny_not_allowed_kind[msg] {
	val := input.kind
	not exists_in_list(input.kind, allowed_kinds)

	msg = sprintf("%v is not a allowed kind", [val])
}

is_service {
	input.kind = "Service"
}

is_deployment {
	input.kind = "Deployment"
}

is_configmap {
	input.kind = "ConfigMap"
}

is_secret {
	input.kind = "Secret"
}

is_pv {
	input.kind = "PersistentVolume"
}

is_pvc {
	input.kind = "PersistentVolumeClaim"
}

is_ingress {
	input.kind = "Ingress"
}

is_nginx_ingress {
	input.metadata.annotations["kubernetes.io/ingress.class"] = "nginx"
}

is_hpa {
	input.kind = "HorizontalPodAutoscaler"
}

is_job {
	input.kind = "Job"
}

is_role {
	input.kind = "Role"
}

is_role_binding {
	input.kind = "RoleBinding"
}

is_service_account {
	input.kind = "ServiceAccount"
}

is_pod {
	input.kind = "Pod"
}

is_poddisruptionbudget {
	input.kind = "PodDisruptionBudget"
}

is_networkpolicy {
	input.kind = "NetworkPolicy"
}
