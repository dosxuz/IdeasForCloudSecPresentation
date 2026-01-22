# Azure Managed Identity Abuse through Virtual Machines attack chain and some Detection

## Ways to execute commands on Virtual Machines

### Execute as normal user

#### Output of these actions and logs related these

#### Standard detection for these actions


## Same executions when Managed Identity is involved

### Executing 1 linux vm using a normal user who has access to only that VM

### That Linux VM has a Managed Identity (System Assigned) that has access to another Windows VM on a Different resource group

### The Windows VM has a User Defined Managed Identity that can enumerate Keys and KeyVaults in their own resource group


## Attack Flow

### Attack Path

- Consider that a low level user is exploited
	- But this user only has access to a particular VM
	- They can execute commands on this particular VM
- Login to this VM by updating the SSH keys of this VM or have the user login rights into this VM
- Once logged into this VM 
	- While inside the VM ->
		- Use the metadata endpoint to get access token for the system assigned
		- This will generate a Managed Identity login event similar to what is generated for `az login --identity --object-id <MI>`
- Update the Password of the WindowsVM. (For this the System Assigned MI on the Linux machine needs to have Contributor access)
	- Login to the Windows VM using RDP
	- Login to the local Managed Identity of the Windows VM
	- Use that Local Identity to enumerate and Access keyvaults
- Once these are done, look into the detection for it.
	- The Linux VM will have logs of commands being invoked
	- There will be Managed Identity logins for the System Assigned Managed Identity of the Linux VM but no command executions under that particular managed identity
	- When you check the Windows VM, there will be command executions from the System Assigned Managed Identity of the Linux VM
		- This is an indicator that Lateral Movement has occured
	- There will be commands executions and MI logins for the Windows VM as well
	- There will also be logs of the MI of the Windows VM accessing the KeyVaults
		- The details can be obtained from the Diagnostics logs of the keyvaults

