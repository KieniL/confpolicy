package kubernetes

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

is_ingress{
  input.kind = "Ingress"
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