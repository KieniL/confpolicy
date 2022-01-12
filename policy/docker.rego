package main

import data.docker


suspicious_env_keys = [
    "passwd",
    "password",
    "secret",
    "key",
    "access",
    "api_key",
    "apikey",
    "token",
]

pkg_update_commands = [
    "apk upgrade",
    "apt-get upgrade",
    "dist-upgrade",
    "apt upgrade",
    "yum upgrade"
]

image_tag_list = [
    "latest",
    "LATEST",
]

maintainer = 
  {
    "Cmd": "label",
    "Flags": [],
    "JSON": false,
    "Stage": 0,
    "SubCmd": "",
    "Value": [
      "maintainer",
      "\"KieniL\""
    ]
  }

maintainer_is_in_list(list){
  list[_] = maintainer
}

#checking that the baseimage is from the trusted source
deny_trusted_registry[msg] {
    docker.is_from(input[i].Cmd)
    not startswith_in_list(input[i].Value[0], trusted_registries)
    msg = sprintf("use a trusted base image instead of %s", [input[i].Value[0]])
}

# images in this list are allowed to have an untrusted baseimage
exception[rules] {
  docker.is_from(input[i].Cmd)
  exists_in_list(input[i].Value[0], baseimages_exceptions)

  rules := ["trusted_registry", "at_used", "sha256"]
}

#check that no cmd is used
deny[msg] {
    docker.is_cmd(input[i].Cmd)
    msg = sprintf("use ENTRYPOINT instead of cmd %s to not have it overriden", [input[i].Value])
}

#check that no copy with all files is there
deny[msg] {
    docker.is_copy(input[i].Cmd)
    input[i].Value[0] == "."
    msg = sprintf("dont use . in copy like %s to not expose unwanted sensitive data", [input[i].Value])
}

#check that no add with all files is there
deny[msg] {
    docker.is_add(input[i].Cmd)
    input[i].Value[0] == "."
    msg = sprintf("dont use . in add like %s to not expose unwanted sensitive data", [input[i].Value])
}

#check that no maintainer is set
deny[msg] {
    docker.is_maintainer(input[i].Cmd)
    msg = sprintf("The maintainer %s tag is deprecated. See https://docs.docker.com/engine/reference/builder/#maintainer-deprecated. Set the label instead", [input[i].Value[0]])
}

#check that label maintainer is there
deny[msg] {
    docker.is_label(input[i].Cmd)
    not maintainer_is_in_list(input)

    msg = sprintf("Label with maintainer is missing", [])
}


# Looking for suspicious environemnt variables
warn[msg] {   
    docker.is_env(input[i].Cmd) 
    val := input[i].Value
    contains(lower(val[_]), suspicious_env_keys[_])
    msg = sprintf("Suspicious ENV key found: %s", [val])
}

# Looking for latest docker image used
warn[msg] {
    docker.is_from(input[i].Cmd)
    val := split(input[i].Value[0], ":")
    count(val) == 1
    msg = sprintf("Do not use latest tag with image: %s", [val])
}

# Looking for latest docker image used
warn[msg] {
    docker.is_from(input[i].Cmd)
    val := split(input[i].Value[0], ":")
    contains(val[1], image_tag_list[_])
    msg = sprintf("Do not use latest tag with image: %s", [input[i].Value])
}

deny_at_used[msg] {
  docker.is_from(input[i].Cmd)
  imagetag := split(input[i].Value[0], "@")
  not count(imagetag) == 0

  msg := sprintf("imagetags are used instead of hash for image %v", [input[i].Value])
}

deny_sha256[msg] {
  docker.is_from(input[i].Cmd)
  imagetag := split(input[i].Value[0], "@")[1]
  not startswith(imagetag, "sha256")

  msg := sprintf("use sha256 instead of tagname to prevent usage of multiple pushed images for image %v", [input[i].Value])
}

# Looking for apk upgrade command used in Dockerfile
warn[msg] {
    docker.is_run(input[i].Cmd)
    val := concat(" ", input[i].Value)
    contains(val, pkg_update_commands[_])
    msg = sprintf("Do not use upgrade commands: %s if you don't really need to", [val])
}

# Looking for ADD command instead using COPY command
deny[msg] {
    docker.is_add(input[i].Cmd)
    val := concat(" ", input[i].Value)
    msg = sprintf("Use COPY instead of ADD: %s. See https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#add-or-copy", [val])
}

# Looking for bashing
warn[msg] {
    docker.is_run(input[i].Cmd)
    val := concat(" ", input[i].Value)
    matches := regex.find_n("(curl|wget)[^|^>]*[|>]", lower(val), -1)
    count(matches) > 0
    msg = sprintf("Line %d: Avoid curl bashing (could also be a false positive)", [i])
}