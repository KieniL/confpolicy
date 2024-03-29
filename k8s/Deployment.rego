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
	"protocol": "TCP",
}

not_needed_for_jolokia = ["mysql"]

jolokia_is_in_list(list) {
	list[_] = jolokia
}

required_selector_labels {
	spec.selector.matchLabels.app
}

deny_missing_name[msg] {
	kubernetes.is_deployment
	not name

	msg := sprintf("deployment %v has no name provided", [name])
}

deny_missing_namespace[msg] {
	kubernetes.is_deployment
	not namespace

	msg := sprintf("deployment %v has no namespace provided", [name])
}

deny_missing_label_app[msg] {
	kubernetes.is_deployment
	not required_selector_labels

	msg := sprintf("Does not contain label app in deployment %v", [name])
}

deny_missing_containers[msg] {
	kubernetes.is_deployment
	not containers

	msg := sprintf("Deployment %v has no containers provided", [name])
}

deny_missing_terminationgraceperiodseconds[msg] {
	kubernetes.is_deployment
	not template_spec.terminationGracePeriodSeconds

	msg := sprintf("Deployment %v has no terminationGracePeriodSeconds provided which should be there for a graceful shutdown", [name])
}

warn_high_terminationgraceperiodseconds[msg] {
	kubernetes.is_deployment
	template_spec.terminationGracePeriodSeconds > 50

	msg := sprintf("Deployment %v has a terminationGracePeriodSeconds above 50 seconds (reality: %v). This could lead to a long waiting before SIGKILL", [name, template_spec.terminationGracePeriodSeconds])
}

warn_more_than_one_container[msg] {
	kubernetes.is_deployment
	not count(containers) <= 1

	msg = sprintf("deployment %v has more than one container. Should not be done due to scaling. Use it wisely.", [name])
}

deny_missing_container_name[msg] {
	kubernetes.is_deployment
	container := input.spec.template.spec.containers[_]
	not container.name

	msg := sprintf("at least one container in deployment %v has no name", [name])
}

deny_missing_image[msg] {
	kubernetes.is_deployment
	container := input.spec.template.spec.containers[_]
	not container.image

	msg := sprintf("at least one container in deployment %v has no image", [name])
}

deny_missing_imagePullPolicy[msg] {
	kubernetes.is_deployment
	container := input.spec.template.spec.containers[_]
	not container.imagePullPolicy

	msg := sprintf("at least one container in deployment %v has no imagePullPolicy", [name])
}

deny_missing_resources[msg] {
	kubernetes.is_deployment
	container := input.spec.template.spec.containers[_]
	not container.resources

	msg := sprintf("at least one container in deployment %v has no resources section", [name])
}

deny_missing_limits[msg] {
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
	not container.securityContext

	msg := sprintf("at least one container in deployment %v is missing securityContext", [name])
}

deny[msg] {
	kubernetes.is_deployment
	container := template_spec.containers[_]
	container.securityContext
	container.securityContext.privileged

	msg := sprintf("at least one container in deployment %v is privileged which is not allowed", [name])
}

deny[msg] {
	kubernetes.is_deployment
	container := template_spec.containers[_]
	container.securityContext
	not container.securityContext.readOnlyRootFilesystem

	msg := sprintf("at least one container in deployment %v has a writable Filesystem", [name])
}

deny[msg] {
	kubernetes.is_deployment
	container := template_spec.containers[_]
	container.securityContext
	container.securityContext.allowPrivilegeEscalation

	msg := sprintf("at least one container in deployment %v allows privilege escalation", [name])
}

deny[msg] {
	kubernetes.is_deployment
	container := template_spec.containers[_]
	container.securityContext
	not container.securityContext.runAsNonRoot

	msg := sprintf("at least one container in deployment %v has the permission to be executed as root.", [name])
}

deny[msg] {
	kubernetes.is_deployment
	container := template_spec.containers[_]
	container.securityContext
	not container.securityContext.capabilities

	msg := sprintf("at least one container in deployment %v is not removing linux capabilities via securityContext.capabilities", [name])
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

deny[msg] {
	kubernetes.is_deployment
	hostPath := template_spec.volumes[_].hostPath
	hostPath

	msg := sprintf("at least one volume in deployment %v does have a hostPath mounting. Ensure that this is not done to prevent full hostpath mounting.", [name])
}

deny[msg] {
	kubernetes.is_deployment
	template_spec.hostNetwork
	not template_spec.hostNetwork == "false"
	
	msg := sprintf("deployment %v has hostNetwork set to true.", [name])
}

deny[msg] {
	kubernetes.is_deployment
	template_spec.hostPID
	not template_spec.hostPID == "false"
	
	msg := sprintf("deployment %v has hostPID set to true.", [name])
}

deny[msg] {
	kubernetes.is_deployment
	template_spec.hostIPC
	not template_spec.hostIPC == "false"
	
	msg := sprintf("deployment %v has hostIPC set to true.", [name])
}


deny[msg] {
	kubernetes.is_deployment
	container := input.spec.template.spec.containers[_]
	container.command
	not container.args
	commands := container.command[_]
	contains(lower(commands), bad_commands[_])

	msg := sprintf("deployment %v runs a bad command in command %v.", [name, commands])
}

deny[msg] {
	kubernetes.is_deployment
	container := input.spec.template.spec.containers[_]
	not container.command
	container.args
	commands := container.args[_]
	contains(lower(commands), bad_commands[_])

	msg := sprintf("deployment %v runs a bad command in args %v.", [name, commands])
}

deny[msg] {
	kubernetes.is_deployment
	container := input.spec.template.spec.containers[_]
	container.command
	container.args
	commands := container.command[_]
	contains(lower(commands), bad_commands[_])

	msg := sprintf("deployment %v runs a bad command in command %v.", [name, commands])
}


deny[msg] {
	kubernetes.is_deployment
	container := input.spec.template.spec.containers[_]
	container.command
	container.args
	commands := container.args[_]
	contains(lower(commands), bad_commands[_])

	msg := sprintf("deployment %v runs a bad command in args %v.", [name, commands])
}

deny_missing_liveness[msg] {
	kubernetes.is_deployment
	container := input.spec.template.spec.containers[_]
	not container.livenessProbe

	msg := sprintf("at least one container in deployment %v does not have a livenessprobe", [name])
}

deny_missing_readiness[msg] {
	kubernetes.is_deployment
	container := input.spec.template.spec.containers[_]
	not container.readinessProbe

	msg := sprintf("at least one container in deployment %v does not have a readinessprobe", [name])
}

#deny[msg] {
#  kubernetes.is_deployment
#  not exists_in_list(name, not_needed_for_jolokia)
#  not jolokia_is_in_list(ports)
#  msg = sprintf("image %v in deployment %v is missing jolokiaport", [first_container.image, name])
#}
