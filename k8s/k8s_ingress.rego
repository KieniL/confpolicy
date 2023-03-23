package main

import data.kubernetes

name = input.metadata.name

namespace = input.metadata.namespace

annotations = input.metadata.annotations

spec = input.spec

deny[msg] {
	kubernetes.is_ingress
	not spec.tls

	msg := sprintf("ingress %v is not secured by tls", [name])
}

deny[msg] {
	kubernetes.is_ingress
	not spec.rules

	msg := sprintf("ingress %v has not rules section provided", [name])
}

deny[msg] {
	kubernetes.is_ingress
	not annotations

	msg := sprintf("ingress %v does not have any annotations", [name])
}

deny[msg] {
	kubernetes.is_ingress
	kubernetes.is_nginx_ingress
	not annotations["nginx.ingress.kubernetes.io/limit-rps"]
	not annotations["nginx.ingress.kubernetes.io/limit-rpm"]

	msg := sprintf("ingress %v needs to have a limit-per-seconds and limit-per-minutes to mitigate DDoS. See https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/#rate-limiting", [name])
}

deny[msg] {
	kubernetes.is_ingress
	kubernetes.is_nginx_ingress
	annotations["nginx.ingress.kubernetes.io/limit-rps"]
	not annotations["nginx.ingress.kubernetes.io/limit-rpm"]

	msg := sprintf("ingress %v only has limit-rps needs to have a limit-per-seconds and limit-per-minutes to mitigate DDoS. See https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/#rate-limiting", [name])
}

deny[msg] {
	kubernetes.is_ingress
	kubernetes.is_nginx_ingress
	not annotations["nginx.ingress.kubernetes.io/limit-rps"]
	annotations["nginx.ingress.kubernetes.io/limit-rpm"]

	msg := sprintf("ingress %v only has limit-rpm needs to have a limit-per-seconds and limit-per-minutes to mitigate DDoS. See https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/#rate-limiting", [name])
}

deny[msg] {
	kubernetes.is_ingress
	kubernetes.is_nginx_ingress
	not annotations["nginx.ingress.kubernetes.io/enable-modsecurity"]

	msg := sprintf("ingress %v does not have enable-modsecurity for nginx ingess set. See https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/configmap/#enable-modsecurity", [name])
}

deny[msg] {
	kubernetes.is_ingress
	kubernetes.is_nginx_ingress
	not annotations["nginx.ingress.kubernetes.io/enable-modsecurity"] = "true"

	msg := sprintf("ingress %v does not have enable-modsecurity for nginx ingess enabled. See https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/configmap/#enable-modsecurity", [name])
}

deny[msg] {
	kubernetes.is_ingress
	kubernetes.is_nginx_ingress
	not annotations["nginx.ingress.kubernetes.io/enable-owasp-core-rules"]

	msg := sprintf("ingress %v does not have enable-owasp-core-rules for nginx ingess set. See https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/#modsecurity", [name])
}

deny[msg] {
	kubernetes.is_ingress
	kubernetes.is_nginx_ingress
	not annotations["nginx.ingress.kubernetes.io/enable-owasp-core-rules"] = "true"

	msg := sprintf("ingress %v does not have enable-owasp-core-rules for nginx ingess enabled. See https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/#modsecurity", [name])
}

deny[msg] {
	kubernetes.is_ingress
	kubernetes.is_nginx_ingress
	not annotations["nginx.ingress.kubernetes.io/enable-owasp-modsecurity-crs"]

	msg := sprintf("ingress %v does not have enable-owasp-core-rules for nginx ingess set. See https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/configmap/#modsecurity-snippet", [name])
}

deny[msg] {
	kubernetes.is_ingress
	kubernetes.is_nginx_ingress
	not annotations["nginx.ingress.kubernetes.io/enable-owasp-modsecurity-crs"] = "true"

	msg := sprintf("ingress %v does not have enable-owasp-core-rules for nginx ingess enabled. See https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/configmap/#modsecurity-snippet", [name])
}
