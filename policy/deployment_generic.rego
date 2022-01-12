package main

import data.kubernetes

name = input.metadata.name
namespace = input.metadata.namespace
spec = input.spec
template_spec = input.spec.template.spec
containers = input.spec.template.spec.containers
first_container = input.spec.template.spec.containers[0]
ports = input.spec.template.spec.containers[0].ports

jolokia = {
    "containerPort": 8778,
    "name": "jolokia",
    "protocol": "TCP"
  }

not_needed_for_jolokia = [
  "mysql"
]


jolokia_is_in_list(list) {
  list[_] = jolokia
}

required_selector_labels {
	spec.selector.matchLabels["app"]
}

deny[msg] {
  kubernetes.is_deployment
  not name

  msg := sprintf("deployment %v has no name provided", [name])
}

deny[msg] {
  kubernetes.is_deployment
  not namespace

  msg := sprintf("deployment %v has no namespace provided", [name])
}

deny[msg] {
  kubernetes.is_deployment
  not startswith(name, "unittest-")

  msg := sprintf("deployment %v does not start with unittest-. Use: {{ .Release.Name }}- in name", [name])
}

deny[msg] {
  kubernetes.is_deployment
  not required_selector_labels

  msg := sprintf("Does not contain label app in deployment %v", [name])
}

deny[msg] {
  kubernetes.is_deployment
  not containers

  msg := sprintf("Deployment %v has no containers provided", [name])
}

deny[msg] {
  kubernetes.is_deployment
  not template_spec.terminationGracePeriodSeconds

  msg := sprintf("Deployment %v has no terminationGracePeriodSeconds provided which should be there for a graceful shutdown", [name])
}

warn[msg] {
  kubernetes.is_deployment
  template_spec.terminationGracePeriodSeconds > 50

  msg := sprintf("Deployment %v has a terminationGracePeriodSeconds above 50 seconds (reality: %v). This could lead to a long waiting before SIGKILL", [name, template_spec.terminationGracePeriodSeconds])
}

warn[msg] {
  kubernetes.is_deployment
  not count(containers) <= 1

  msg = sprintf("deployment %v has more than one container. Should not be done due to scaling. Use it wisely.", [name])
}

deny[msg] {
  kubernetes.is_deployment
  container := input.spec.template.spec.containers[_]
  not container.name

  msg := sprintf("at least one container in deployment %v has no name", [name])
}

deny[msg] {
  kubernetes.is_deployment
  container := input.spec.template.spec.containers[_]
  not container.image

  msg := sprintf("at least one container in deployment %v has no image", [name])
}

deny[msg] {
  kubernetes.is_deployment
  container := input.spec.template.spec.containers[_]
  not container.imagePullPolicy

  msg := sprintf("at least one container in deployment %v has no imagePullPolicy", [name])
}

deny[msg] {
  kubernetes.is_deployment
  container := input.spec.template.spec.containers[_]
  not container.resources

  msg := sprintf("at least one container in deployment %v has no resources section", [name])
}

deny[msg] {
  kubernetes.is_deployment
  container := input.spec.template.spec.containers[_]
  not container.resources.limits

  msg := sprintf("at least one container in deployment %v has no resources limits section", [name])
}

deny[msg] {
  kubernetes.is_deployment
  container := input.spec.template.spec.containers[_]
  not container.resources.requests

  msg := sprintf("at least one container in deployment %v has no resources requests section", [name])
}


deny[msg] {
  kubernetes.is_deployment
  container := input.spec.template.spec.containers[_]
  not container.resources.limits.memory

  msg := sprintf("at least one container in deployment %v has no memory limits section", [name])
}

deny[msg] {
  kubernetes.is_deployment
  container := input.spec.template.spec.containers[_]
  not container.resources.limits.cpu

  msg := sprintf("at least one container in deployment %v has no cpu limits section", [name])
}

deny[msg] {
  kubernetes.is_deployment
  container := input.spec.template.spec.containers[_]
  not container.resources.requests.memory

  msg := sprintf("at least one container in deployment %v has no memory requests section", [name])
}

deny[msg] {
  kubernetes.is_deployment
  container := input.spec.template.spec.containers[_]
  not container.resources.requests.cpu

  msg := sprintf("at least one container in deployment %v has no cpu requests section", [name])
}

deny[msg] {
  kubernetes.is_deployment
  not template_spec.affinity

  msg = sprintf("deployment %v does not have an affinity section", [name])
}

deny[msg] {
  kubernetes.is_deployment
  not template_spec.affinity.podAntiAffinity

  msg = sprintf("deployment %v does not have an podAnitAffinity section", [name])
}

deny[msg] {
  kubernetes.is_deployment
  image := input.spec.template.spec.containers[_].image
  not startswith_in_list(image, trusted_registries)

  msg := sprintf("at least one containerimage in deployment %v is not from the allowed source", [name])
}

deny[msg] {
  kubernetes.is_deployment
  imagetag := split(input.spec.template.spec.containers[_].image, "@")
  count(imagetag) == 1

  msg := sprintf("imagetags are used instead of hash for deployment %v", [name])
}

deny[msg] {
  kubernetes.is_deployment
  imagetag := split(input.spec.template.spec.containers[_].image, "@")[1]
  not startswith(imagetag, "sha256")

  msg := sprintf("use sha256 instead of tagname to prevent usage of multiple pushed images for deployment %v", [name])
}

deny[msg] {
  kubernetes.is_deployment
  container := template_spec.containers[_]
  container.securityContext.privileged == true

  msg := sprintf("at least one container in deployment %v is privileged which is not allowed", [name])
}

deny[msg] {
  kubernetes.is_deployment
  not exists_in_list(name, serviceaccount_needed)
  not template_spec.automountServiceAccountToken == false

  msg := sprintf("deployment %v uses the automounted serviceaccount but doesn't need to. Please disable it with automountServiceAccountToken: false ", [name])
}

deny[msg] {
  kubernetes.is_deployment
  exists_in_list(name, serviceaccount_needed)
  template_spec.serviceAccountName == "default"
  template_spec.automountServiceAccountToken == false

  msg := sprintf("deployment %v has the automount of serviceaccounts disabled. The set serviceAccountName will not be used.", [name])
}

deny[msg] {
  kubernetes.is_deployment
  exists_in_list(name, serviceaccount_needed)
  template_spec.serviceAccountName == "default"
  not template_spec.automountServiceAccountToken == false

  msg := sprintf("deployment %v uses the default serviceaccount. Please create a separate one based on Least Privilege.", [name])
}

deny[msg] {
  kubernetes.is_deployment
  emptyDir := template_spec.volumes[_].emptyDir
  not emptyDir.sizeLimit

  msg := sprintf("at least one emptydir volume in deployment %v does not have a sizelimit ", [name])
}

#deny[msg] {
#  kubernetes.is_deployment
#  not exists_in_list(name, not_needed_for_jolokia)
#  not jolokia_is_in_list(ports)
#  msg = sprintf("image %v in deployment %v is missing jolokiaport", [first_container.image, name])
#}