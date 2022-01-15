package azure

is_availability_set {
	input.resource.azurerm_availability_set
}

is_network_interface {
	input.resource.azurerm_network_interface
}

is_network_interface_security_group_association {
	input.resource.azurerm_network_interface_security_group_association
}

is_security_group {
	input.resource.azurerm_network_security_group
}

is_public_ip {
	input.resource.azurerm_public_ip.public_ip
}

is_resource_group {
	input.resource.azurerm_resource_group
}

is_subnet {
	input.resource.azurerm_subnet.subnet
}

is_vnet {
	input.resource.azurerm_virtual_network
}

is_vm {
	input.resource.azurerm_windows_virtual_machine
}

is_app_service {
	input.resource.azurerm_app_service
}

is_app_servic_plan {
	input.resource.azurerm_app_service_plan
}

is_conainer_group {
	input.resource.azurerm_container_group
}

is_storage_account {
	input.resource.azurerm_storage_account
}

is_storage_container {
	input.resource.azurerm_storage_container
}

is_mssql_server {
	input.resource.azurerm_mssql_server
}

is_mssql_database {
	input.resource.azurerm_mssql_database
}

is_mssql_database_extended_auditing_policy {
	input.resource.azurerm_mssql_database_extended_auditing_policy
}

is_sql_vnet_rule {
	input.resource.azurerm_sql_virtual_network_rule
}

is_sql_firewall_rule {
	input.resource.azurerm_sql_firewall_rule
}

is_function_app {
	input.resource.azurerm_function_app
}

is_key_vault {
	input.resource.azurerm_key_vault
}

is_key_vault_secret {
	input.resource.azurerm_key_vault_secret
}

is_policy_assignment {
	input.resource.azurerm_policy_assignment
}