# Scenario 1 Setup


## Linux VM in Resource Group 1

- This will have a System Assigned Managed Identity
	- This System Assigned MI will have Contributor access on another Windows VM in a different Resource Group
- We will consider that the attacker has somehow compromised a low level user that only has access to the Linux VM
	- He can ssh into that VM or execute code into that VM

```
vm-user@az.floralbask.com :8OgM\Y}0T5dN 
```

## Windows VM in Resource Group 2

- The Linux VM has Contributor on this Windows VM
- The Windows VM has a User Defined MI which has access to enumerate and Read KeyVaults
- The accesses this MI and enumerates the keyvaults


```
Windows VM Password

azureadmin : h5x&d/VYB81K
```


