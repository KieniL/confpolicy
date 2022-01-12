package main

import data.kubernetes

name = input.metadata.name
namespace = input.metadata.namespace
spec = input.spec
template_spec = input.spec.template.spec
containers = input.spec.template.spec.containers
first_container = input.spec.template.spec.containers[0]
ports = input.spec.template.spec.containers[0].ports


deny[msg] {
  kubernetes.is_job
  not name

  msg := sprintf("job %v has no name provided", [name])
}

deny[msg] {
  kubernetes.is_job
  not namespace

  msg := sprintf("job %v has no namespace provided", [name])
}

deny[msg] {
  kubernetes.is_job
  not startswith(name, "unittest-")

  msg := sprintf("job %v does not start with unittest-. Use: {{ .Release.Name }}- in name", [name])
}


deny[msg] {
  kubernetes.is_job
  not containers

  msg := sprintf("job %v has no containers provided", [name])
}

deny[msg] {
  kubernetes.is_job
  not template_spec.terminationGracePeriodSeconds

  msg := sprintf("job %v has no terminationGracePeriodSeconds provided which should be there for a graceful shutdown", [name])
}

warn[msg] {
  kubernetes.is_job
  not count(containers) <= 1

  msg = sprintf("job %v has more than one container. Should not be done due to scaling. Use it wisely.", [name])
}

deny[msg] {
  kubernetes.is_job
  container := input.spec.template.spec.containers[_]
  not container.name

  msg := sprintf("at least one container in job %v has no name", [name])
}

deny[msg] {
  kubernetes.is_job
  container := input.spec.template.spec.containers[_]
  not container.image

  msg := sprintf("at least one container in job %v has no image", [name])
}

deny[msg] {
  kubernetes.is_job
  container := input.spec.template.spec.containers[_]
  not container.imagePullPolicy

  msg := sprintf("at least one container in job %v has no imagePullPolicy", [name])
}

deny[msg] {
  kubernetes.is_job
  container := input.spec.template.spec.containers[_]
  not container.resources

  msg := sprintf("at least one container in job %v has no resources section", [name])
}

deny[msg] {
  kubernetes.is_job
  container := input.spec.template.spec.containers[_]
  not container.resources.limits

  msg := sprintf("at least one container in job %v has no resources limits section", [name])
}

deny[msg] {
  kubernetes.is_job
  container := input.spec.template.spec.containers[_]
  not container.resources.requests

  msg := sprintf("at least one container in job %v has no resources requests section", [name])
}


deny[msg] {
  kubernetes.is_job
  container := input.spec.template.spec.containers[_]
  not container.resources.limits.memory

  msg := sprintf("at least one container in job %v has no memory limits section", [name])
}

deny[msg] {
  kubernetes.is_job
  container := input.spec.template.spec.containers[_]
  not container.resources.limits.cpu

  msg := sprintf("at least one container in job %v has no cpu limits section", [name])
}

deny[msg] {
  kubernetes.is_job
  container := input.spec.template.spec.containers[_]
  not container.resources.requests.memory

  msg := sprintf("at least one container in job %v has no memory requests section", [name])
}

deny[msg] {
  kubernetes.is_job
  container := input.spec.template.spec.containers[_]
  not container.resources.requests.cpu

  msg := sprintf("at least one container in job %v has no cpu requests section", [name])
}

deny[msg] {
  kubernetes.is_job
  image := input.spec.template.spec.containers[_].image
  not startswith_in_list(image, trusted_registries)

  msg := sprintf("at least one containerimage in job %v is not from the allowed source", [name])
}

deny[msg] {
  kubernetes.is_job
  imagetag := split(input.spec.template.spec.containers[_].image, "@")
  count(imagetag) == 1

  msg := sprintf("imagetags are used instead of hash for job %v", [name])
}

deny[msg] {
  kubernetes.is_job
  imagetag := split(input.spec.template.spec.containers[_].image, "@")[1]
  not startswith(imagetag, "sha256")

  msg := sprintf("use sha256 instead of tagname to prevent usage of multiple pushed images for job %v", [name])
}

deny[msg] {
  kubernetes.is_job
  not exists_in_list(name, serviceaccount_needed)
  not template_spec.automountServiceAccountToken == false

  msg := sprintf("job %v uses the automounted serviceaccount but doesn't need to. Please disable it with automountServiceAccountToken: false ", [name])
}

deny[msg] {
  kubernetes.is_job
  exists_in_list(name, serviceaccount_needed)
  template_spec.serviceAccountName == "default"
  template_spec.automountServiceAccountToken == false

  msg := sprintf("job %v has the automount of serviceaccounts disabled. The set serviceAccountName will not be used.", [name])
}

deny[msg] {
  kubernetes.is_job
  exists_in_list(name, serviceaccount_needed)
  template_spec.serviceAccountName == "default"
  not template_spec.automountServiceAccountToken == false

  msg := sprintf("job %v uses the default serviceaccount. Please create a separate one based on Least Privilege.", [name])
}

deny[msg] {
  kubernetes.is_job
  container := template_spec.containers[_]
  container.securityContext.privileged == true

  msg := sprintf("at least one container in job %v is privileged which is not allowed", [name])
}