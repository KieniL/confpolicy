package main

import data.kubernetes

name = input.metadata.name

namespace = input.metadata.namespace

deny[msg] {
	kubernetes.is_secret
	not input.type

	msg := sprintf("secret %v does not have a type", [name])
}
