package main

import data.kubernetes

name = input.metadata.name
namespace = input.metadata.namespace
spec = input.spec
containers = input.spec.containers

deny[msg] {
  kubernetes.is_pod
  not name

  msg := sprintf("pod %v has no name provided", [name])
}

deny[msg] {
  kubernetes.is_pod
  not namespace

  msg := sprintf("pod %v has no namespace provided", [name])
}

deny[msg] {
  kubernetes.is_pod
  not startswith(name, "unittest-")

  msg := sprintf("pod %v does not start with unittest-. Use: {{ .Release.Name }}- in name", [name])
}

deny[msg] {
  kubernetes.is_pod
  not containers

  msg := sprintf("pod %v has no containers provided", [name])
}


deny[msg] {
  kubernetes.is_pod
  not spec.terminationGracePeriodSeconds

  msg := sprintf("Pod %v has no terminationGracePeriodSeconds provided which should be there for a graceful shutdown", [name])
}

warn[msg] {
  kubernetes.is_pod
  spec.terminationGracePeriodSeconds > 50

  msg := sprintf("Pod %v has a terminationGracePeriodSeconds above 50 seconds (reality: %v). This could lead to a long waiting before SIGKILL", [name, template_spec.terminationGracePeriodSeconds])
}

warn[msg] {
  kubernetes.is_pod
  not count(containers) <= 1

  msg = sprintf("pod %v has more than one container. Should not be done due to scaling. Use it wisely.", [name])
}

deny[msg] {
  kubernetes.is_pod
  container := containers[_]
  not container.name

  msg := sprintf("at least one container in pod %v has no name", [name])
}

deny[msg] {
  kubernetes.is_pod
  container := containers[_]
  not container.image

  msg := sprintf("at least one container in pod %v has no image", [name])
}

deny[msg] {
  kubernetes.is_pod
  container := containers[_]
  not container.imagePullPolicy

  msg := sprintf("at least one container in pod %v has no imagePullPolicy", [name])
}

deny[msg] {
  kubernetes.is_pod
  container := containers[_]
  not container.resources

  msg := sprintf("at least one container in pod %v has no resources section", [name])
}

deny[msg] {
  kubernetes.is_pod
  container := containers[_]
  not container.resources.limits

  msg := sprintf("at least one container in pod %v has no resources limits section", [name])
}

deny[msg] {
  kubernetes.is_pod
  container := containers[_]
  not container.resources.requests

  msg := sprintf("at least one container in pod %v has no resources requests section", [name])
}


deny[msg] {
  kubernetes.is_pod
  container := containers[_]
  not container.resources.limits.memory

  msg := sprintf("at least one container in pod %v has no memory limits section", [name])
}

deny[msg] {
  kubernetes.is_pod
  container := containers[_]
  not container.resources.limits.cpu

  msg := sprintf("at least one container in pod %v has no cpu limits section", [name])
}

deny[msg] {
  kubernetes.is_pod
  container := containers[_]
  not container.resources.requests.memory

  msg := sprintf("at least one container in pod %v has no memory requests section", [name])
}

deny[msg] {
  kubernetes.is_pod
  container := containers[_]
  not container.resources.requests.cpu

  msg := sprintf("at least one container in pod %v has no cpu requests section", [name])
}

deny[msg] {
  kubernetes.is_pod
  not spec.affinity

  msg = sprintf("pod %v does not have an affinity section", [name])
}

deny[msg] {
  kubernetes.is_pod
  not spec.affinity.podAntiAffinity

  msg = sprintf("pod %v does not have an podAnitAffinity section", [name])
}

deny[msg] {
  kubernetes.is_pod
  image := containers[_].image
  not startswith_in_list(image, trusted_registries)

  msg := sprintf("at least one containerimage in pod %v is not from the allowed source", [name])
}

deny[msg] {
  kubernetes.is_pod
  imagetag := split(containers[_].image, "@")
  count(imagetag) == 1

  msg := sprintf("imagetags are used instead of hash for pod %v", [name])
}

deny[msg] {
  kubernetes.is_pod
  imagetag := split(containers[_].image, "@")[1]
  not startswith(imagetag, "sha256")

  msg := sprintf("use sha256 instead of tagname to prevent usage of multiple pushed images for pod %v", [name])
}

deny[msg] {
  kubernetes.is_pod
  not exists_in_list(name, serviceaccount_needed)
  not spec.automountServiceAccountToken == false

  msg := sprintf("pod %v uses the automounted serviceaccount but doesn't need to. Please disable it with automountServiceAccountToken: false ", [name])
}

deny[msg] {
  kubernetes.is_pod
  exists_in_list(name, serviceaccount_needed)
  spec.serviceAccountName == "default"
  spec.automountServiceAccountToken == false

  msg := sprintf("pod %v has the automount of serviceaccounts disabled. The set serviceAccountName will not be used.", [name])
}

deny[msg] {
  kubernetes.is_pod
  exists_in_list(name, serviceaccount_needed)
  spec.serviceAccountName == "default"
  not spec.automountServiceAccountToken == false

  msg := sprintf("pod %v uses the default serviceaccount. Please create a separate one based on Least Privilege.", [name])
}

deny[msg] {
  kubernetes.is_pod
  emptyDir := spec.volumes[_].emptyDir
  not emptyDir.sizeLimit

  msg := sprintf("at least one emptydir volume in pod %v does not have a sizelimit ", [name])
}


deny[msg] {
  kubernetes.is_pod
  container := containers[_]
  container.securityContext.privileged == true

  msg := sprintf("at least one container in job %v is privileged which is not allowed", [name])
}