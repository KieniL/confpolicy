package main


#test with conftest verify --policy ./

# "not deny" doesn't work because deny is a set.
# Instead we need to define "no_violations" to be true when `deny` is empty.
empty(value) {
  count(value) == 0
}

no_violations {
  empty(deny)
}

test_deny_namespace {
	cfg := parse_config("json", `
{
  "apiVersion": "apps/v1",
  "kind": "Deployment",
  "metadata": {
	    "namespace": "test"
  }
}
	`)
	#cfg := parse_config_file("./deployment.yaml")
  	deny_missing_name with input as cfg
}

