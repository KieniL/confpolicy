package main

trusted_registries = [
	"luke19",
	"curlimages",
	"test"
]

startswith_in_list(element, list) {
	startswith(element, list[_])
}
