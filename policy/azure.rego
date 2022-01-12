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
	input.resource.azurerm_network_security_group.sg
}

is_public_ip {
	input.resource.azurerm_public_ip.public_ip
}

is_resource_group {
	input.resource.azurerm_resource_group.rg
}

is_subnet {
	input.resource.azurerm_subnet.subnet
}

is_vnet {
	input.resource.azurerm_virtual_network.vnet
}

is_vm {
	input.resource.azurerm_windows_virtual_machine.vm
}
