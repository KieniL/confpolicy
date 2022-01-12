package main

import data.kubernetes

name = input.metadata.name
namespace = input.metadata.namespace
annotations = input.metadata.annotations
spec = input.spec


deny[msg] {
  kubernetes.is_ingress
  not startswith(name, "unittest-")

  msg := sprintf("ingress %v does not start with unittest-. Use: {{ .Release.Name }}- in name", [name])
}

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
  not annotations["nginx.ingress.kubernetes.io/limit-rps"]
  not annotations["nginx.ingress.kubernetes.io/limit-rpm"]

  msg := sprintf("ingress %v needs to have a limit-per-seconds and limit-per-minutes to mitigate DDoS. See https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/#rate-limiting", [name])
}

deny[msg] {
  kubernetes.is_ingress
  annotations["nginx.ingress.kubernetes.io/limit-rps"]
  not annotations["nginx.ingress.kubernetes.io/limit-rpm"]

  msg := sprintf("ingress %v only has limit-rps needs to have a limit-per-seconds and limit-per-minutes to mitigate DDoS. See https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/#rate-limiting", [name])
}

deny[msg] {
  kubernetes.is_ingress
  not annotations["nginx.ingress.kubernetes.io/limit-rps"]
  annotations["nginx.ingress.kubernetes.io/limit-rpm"]

  msg := sprintf("ingress %v only has limit-rpm needs to have a limit-per-seconds and limit-per-minutes to mitigate DDoS. See https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/#rate-limiting", [name])
}