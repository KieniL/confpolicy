package main

import data.kubernetes

name = input.metadata.name

namespace = input.metadata.namespace

deny[msg] {
	kubernetes.is_service_account
	not name

	msg := sprintf("serviceaccount %v has no name provided", [name])
}

deny[msg] {
	kubernetes.is_service_account
	not namespace

	msg := sprintf("serviceaccount %v has no namespace provided", [name])
}
