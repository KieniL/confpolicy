package docker

is_from(cmd) {
	cmd == "from"
}

is_add(cmd) {
	cmd == "add"
}

is_copy(cmd) {
	cmd == "copy"
}

is_run(cmd) {
	cmd == "run"
}

is_workdir(cmd) {
	cmd == "workdir"
}

is_env(cmd) {
	cmd == "env"
}

is_expose(cmd) {
	cmd == "expose"
}

is_cmd(cmd) {
	cmd == "cmd"
}

is_maintainer(cmd) {
	cmd == "maintainer"
}

is_label(cmd) {
	cmd == "label"
}

is_entrypoint(cmd) {
	cmd == "entrypoint"
}

is_volume(cmd) {
	cmd == "volume"
}

is_user(cmd) {
	cmd == "user"
}

is_arg(cmd) {
	cmd == "arg"
}

is_onbuild(cmd) {
	cmd == "onbuild"
}

is_stopsignal(cmd) {
	cmd == "stopsignal"
}

is_healthcheck(cmd) {
	cmd == "healthcheck"
}

is_shell(cmd) {
	cmd == "shell"
}