package main

import data.kubernetes

name = input.metadata.name
namespace = input.metadata.namespace
subjects = input.subjects
roleRef = input.roleRef

wildcard_resource_is_in_list(list) {
  list[_] = "*"
}

deny[msg] {
  kubernetes.is_role_binding
  not name

  msg := sprintf("rolebinding %v has no name provided", [name])
}

deny[msg] {
  kubernetes.is_role_binding
  not namespace

  msg := sprintf("rolebinding %v has no namespace provided", [name])
}

deny[msg] {
  kubernetes.is_role_binding
  not startswith(name, "unittest-")

  msg := sprintf("rolebinding %v does not start with unittest-. Use: {{ .Release.Name }}- in name", [name])
}

deny[msg] {
  kubernetes.is_role_binding
  not subjects

  msg := sprintf("rolebinding %v does not have a subjects section", [name])
}

deny[msg] {
  kubernetes.is_role_binding
  not roleRef

  msg := sprintf("rolebinding %v does not have a roleRef section", [name])
}

deny[msg] {
  kubernetes.is_role_binding
  subjectList  := subjects[_]
  not exists_in_list(subjectList.kind, allowed_subject_kinds)

  msg := sprintf("at least one subject in rolebinding %v references a not allowed kind. Only serviceaccount or group is allowed", [name])
}

deny[msg] {
  kubernetes.is_role_binding
  subjectList  := subjects[_]
  not subjectList.name

  msg := sprintf("at least one subject in rolebinding %v does not have a name provided", [name])
}

deny[msg] {
  kubernetes.is_role_binding
  not roleRef.kind == "Role"

  msg := sprintf("ClusterRoles are not allowed for rolebinding %v", [name])
}

deny[msg] {
  kubernetes.is_role_binding
  not roleRef.name

  msg := sprintf("roleref in rolebinding %v does not have a name provided", [name])
}