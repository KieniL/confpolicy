package main


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