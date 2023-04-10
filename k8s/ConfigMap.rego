package main

import data.kubernetes

namespace = input.metadata.namespace

name = input.metadata.name

content = input.data

deny[msg] {
	kubernetes.is_configmap
	not name

	msg := sprintf("configmap %v has no name provided", [name])
}

deny[msg] {
	kubernetes.is_configmap
	not namespace

	msg := sprintf("configmap %v has no namespace provided", [name])
}

deny[msg] {
	kubernetes.is_configmap
	not content

	msg := sprintf("Does not contain data section in configmap %v", [name])
}
