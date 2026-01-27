# Detecting Attacks Against Azure VMs

# Moving Laterally through Abuse of Managed Identities attached to VMs

## Managed Identities

*A managed identity is an identity that can be assigned to an Azure compute resource (Azure Virtual Machine, Azure Virtual Machine Scale Set, Service Fabric Cluster, Azure Kubernetes cluster) or any App hosting platform supported by Azure. Once a managed identity is assigned on the compute resource, it can be authorized, directly or indirectly, to access downstream dependency resources, such as a storage account, SQL database, Cosmos DB, and so on. Managed identity replaces secrets such as access keys or passwords.*

They can also be considered as Service Principals that can be used with Azure Resources

There are 2 different types of Managed Identities in Azure:

1. **System Assigned Managed Identity** -> It is essentially tied to a particular resources and cannot be shared or attached to another resource
2. **User Assigned Managed Identity** -> It is independent and can be shared with other resources. It also gives the user a more granular way to access resources


# Abusing Managed Identities attached To Virtual Machines

This is what we will be focusing on today. The way a Virtual Machine can be leveraged to abuse the Managed Identity attached to it may vary depending on the scenario and the way a tenant is setup.

In this discussion we will take a path as follows:

- First we will consider that the attacker has compromised a user called `vm-user`
- This VM user has `Virtual Machine Administrator` on a Linux VM in the resource group called `ResourceGroup1`
- However, this Linux VM has a `System Assigned` Managed Identity which has `Virtual Machine Contributor` on another VM which is in a different resource group called `ResourceGroup2`
- So the user will first request their own access token using the `az cli`
- Using that access token they will use the Virtual Machine endpoint to execute command on the target Virtual Machine
	- Using this ability to execute command they will hit the metadata endpoint, the attacker will be able to extract the access token of the `System Assigned` Managed Identity.
- Now using this access token from the System Assigned Managed Identity they will be able to execute command on the Virtual Machine in `ResourceGroup2`
- Even specific IP address might be allowed to login to the VM in `ResourceGroup2` and there's no direct path of access to the Virtual Machine, the attacker is able to execute code into that VM
- Now this second VM has a `User Assigned` Managed Identity attached to it, which has `Key Vault Administrator` role attached to it. 
	- The attacker can now request access token for the `vault.azure.net` service from the metadata endpoint 
	- This will allow the attacker to enumerate keyvaults and keys

## Introduction

There can be multiple attacks against Virtual Machines in Azure. Mostly it is due to the fact that Azure allows an authenticated user with the right permissions to execute arbitrary commands on a target Virtual Machine (whether it be Windows or Linux).

This type of attacks can be easily emulated by tools like Stratus Red Team for cloud. Which makes it easier for an analyst to find the event logs and develop detections for this type of attacks. 

However, when an attacker starts chaining attacks and laterally moving in the victim tenant through code executions on the VMs and using the Managed Identities (System Assigned and User Assigned) to access the resources on the victim tenant and resource groups. Just depending on the `AzureActivity` logs also makes it difficult to differentiate between the legitimate command executions against a VM.


### Executing PowerShell commands through Custom Script Extension

- First we will be using Stratus Red Team tool to execute command through Custom Script Extension
- It will use the following Azure RM API

```http
PUT https://management.azure.com/subscriptions/{subscription-id}/resourceGroups/{resource_group}/providers/Microsoft.Compute/virtualMachines/{vm_name}/extensions/CustomScriptExtension?api-version=2022-03-01
```

- It first uploads a PowerShell script from local and then executes that PowerShell script on a VM
- Using Stratus Red team we will detonate the action [azure.execution.vm-custom-script-extension](https://stratus-red-team.cloud/attack-techniques/azure/azure.execution.vm-custom-script-extension/) 


![[1.png]]


- This would result in the execution of a pre-defined script by Stratus Red Team called `CustomScriptExtension-StratusRedTeam-Example`
- This we can confirm from the `AzureActivity` log

![[2.png]]


![[3.png]]

![[4.png]]

- We can perform the same thing using `az cli` where we will be running a custom PowerShell script

- And if an attacker changes the script name to something like `Admin-Script.ps1` it will be very difficult to distinguish between a legitimate script execution done by an administrator and a malicious one
- This is because the actual contents of the scripts are not found anywhere, even in the detailed event logs from the endpoint, unless PowerShell script logging is enabled individually on that machine
	- Upon allowing PowerShell logging for sysmon we will start getting the `EventID` `4104` which will indicate Powershell script block logging and will show the Powershell commands that has been executed. 
	- This will give us more insight into the powershell script but it is still not enough to detect based on behavioral analysis


- Upon using `stratus reverert azure.execution.vm-custom-script-extension` it deletes the Extension which we can also see in the `AzureActivity` logs

![[5.png]]


- Both the script executions look completely similar with nothing but the differing names of the Custom Extensions

```powershell
az vm extension set --name "CustomScriptExtension" --publisher Microsoft.Compute --vm-name srt-vm-vmcse --resource-group srt-vmcse-rg-u52znki7 --settings '{"commandToExecute":"powershell.exe Get-Service"}'
```


- Here in the `az` cli command we used the name `CustomScriptExtension` without the names Stratus Red Team
- We can even execute PowerShell script using this.


### Executing PowerShell commands through Run Command

- This is another way of executing PowerShell commands in a remote Virtual Machine
- For this we can either use the `azure.execution.vm-run-command` tool from stratus red team or we can directly use the AZ CLI `run-command` parameter

![[7.png]]

- If we go through the Logs of this event we will find the following


![[8.png]]

- We can see that the message shows the `'MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMAND/ACTION'` which is a indicator that run command has been invoked or created (stratus red team creates instance of the command)

![[9.png]]

- We also see the username who has executed the command


### Common Mitigations and Detections for VM Command execution

- The main methods of detections along with the respective KQL queries to find such events can be found in [Azure Threat Research Matrix](https://microsoft.github.io/Azure-Threat-Research-Matrix/Execution/AZT301/AZT301-2/) itself. Where see that if we filter out the following we will find the custom scripts that were executed

```sql
AzureActivity 
| where OperationNameValue == 'MICROSOFT.COMPUTE/VIRTUALMACHINES/EXTENSIONS/WRITE' and Properties has 'CustomScriptExtension'
```

- This is actually found in the `properties` attribute of the `Properties` field

![[6.png]]

- We can also allow selective IP addresses to login to the VM through SSH or RDP ports.


## Attack Execution

### Exploiting the first VM

Here since, we are considering that we already have compromised a user called `vm-user`

- This user has `Virtual Machine Contributor` on the `ResourceGroup1`

![[MILateralMovement/Pictures/10.png]]

![[11.png]]

- If we carefully check what role assignments the user has on the resource `lower-powervm`

```powershell
az role assignment list --scope "/subscriptions/17ca970a-212c-430b-9aa6-6365b4d82b92/resourceGroups/ResourceGroup1/providers/Microsoft.Compute/virtualMachines/lower-powervm" --output json --query '[].{principalName:principalName, roleDefinitionName:roleDefinitionName, scope:scope}'
```

![[12.png]]

- This shows us that the user has a `Virtual Machine Contributor` on the VM called `lower-powervm` which is in `ResourceGroup1`

- We can use `az vm run-command invoke` to execute a shell command on the VM
	- But like we have seen this can be detected by checking Azure Activity logs for `Invoke` logs
	- Also, our aim is not just to execute code on the remote VM, we need to use it to move laterally

![[13.png]]


- We can see that there is a `System Assigned` MI attached to this VM
	- However, as a VM contributor we don't have enough privileges to check what access does this have to other resources
- Therefore, we will first authenticate using this Managed Identity and then list all the resources available to it

- For doing this we will be using access tokens only to execute API calls 

- First we need to get the access token of our current user i.e. `vm-user`

```
az account get-access-token
```


![[14.png]]

### Obtaining access token from first VM

- Now we will execute code on the `lower-powervm` using this access token, since our user has `Virtual Machine Administrator` on this Resource Group
- For this we will be using the endpoint `https://management.azure.com/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Compute/virtualMachines/{}/runCommand?api-version=2023-03-01`
- And the command that we will be executing will be `curl 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource={}' -H \"Metadata: true\"`
	- This command is going to send a `GET` request to the metadata endpoint 
	- In the first case we will define the `resource` as `https://management.azure.com`, which will give us the access token for `Azure Resource Manager` API.
	- Using this API we can perform various operations on other resources depending on the permissions available
- We will send the access token as a `Bearer` token

- First we will try to list resources using our access token from `vm-user`

![[15.png]]

- This is the same as we found previously
- Now we will try and execute code on this VM to obtain an access token for the `System Assigned` Managed Identity

![[16.png]]

- Now lets use this access token to get check what resources we have access to

![[17.png]]

- We see that we have access to another VM called `powerful-vm` which is in a different resource group called `ResourceGroup2`
- If we enumerate further we will find we have capability to execute code on this particular VM


### Exploiting the second VM for 

- Now we need to get the access token for Management API for this `powerful-vm`

![[18.png]]

- If we list the resources accessible to this VM, we find that there is a Key Vault called `importantkeyvault` accessible to this particular VM
- This means there is a Managed Identity that is attached to this VM which can access this Key Vault


### Using Access token to enumerate Key Vault

- Therefore, we will next request the access token authenticated for the Key Vault URI which is `https://vault.azure.net`
	- This will allow us to check the keys inside the Key Vault
- So our endpoint request will look as follows

```
curl 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net -H \"Metadata: true\"
```

- Now we can use the Key Vault URI as follows

```
GET https://importantkeyvault.vault.azure.net/keys?api-version=2025-07-01
```

- Now when we use our access token to list the keys inside a Key Vault

![[19.png]]

We have a key named `veryimportantkeys`

- We can use this same access token to list the contents of the key vault as well


```
GET https://importantkeyvault.vault.azure.net/keys/veryimportantkeys?api-version=2025-07-01
```

![[20.png]]


Therefore, we have a clear path into the Key Vault in another resource group. And we didn't need to login to the other Virtual Machine either


# Analysing Logs and Developing Detection Based on them

- This technique does not need to login to a specific VM
- It also does not require you to login to a Managed Identity from within a particular VM
- Other than that we are using the Key Vault URI directly to view the key vaults
- We will investigate if this attack flow also generates enough logs that will allow us to develop a definitive detection

### Understanding Activity Logs

- First we will check the `AzureActivityLogs` which will tell us the actions that have been executed on the VMs

![[21.png]]


We will see that actions have been performed on the `lower-powervm` and `powerful-vm` as well

- If we check the callers of these APIs we will find the following

![[22.png]]

- Here we can see that the `lower-powervm` had access from the `vm-user` user, which is normal in this case
- However, `powerful-vm` doesn't have any user as its called, its a `Managed Identity` object ID
	- If we check type we will find that its a Service Principal and Managed Identities are also a type of Service Principals

![[23.png]]


- Now the presence of Service Principal which belongs to another resource tells us that there is some sort of Lateral Movement has occurred
	- This is because usually the System Assigned Managed Identity is attached to a single resource and always indicates to that particular resource
	- Now the Managed Identity of a Virtual Machine should not be executing code on another Virtual Machine


### Analysing the Managed Identity Sign-in Logs


![[24.png]]


- We will first see that the Service Principal ID of the `lower-powervm` VM Logging into the resource for Azure Resource Manager API
	- This was triggered when we requested Access token from within the `lower-powervm` using the System Assigned MI 
- Next we will find that there was a login into Azure RM API using a different Service Principal ID
	- This essential belongs to the User Defined Managed Identity `keyvaultuser`

![[25.png]]

This is the Managed Identity that is attached to the other Linux VM `powerful-vm`

- Then there's another login to a `Azure Key Vault` resource using this same Managed Identity

![[26.png]]


This is basically the fixed Object ID for Application for Azure Key Vault. This was triggered when we requested an access token for `vault.azure.net`


### Developing a Detection Logic

- In this case we are not going to consider logs from endpoint like Sysmon logs or Linux Diagnostics Agent logs
	- This will come under during the investigation part once the attack has been detected

- The first point of check will be when there is a Managed Identity accessing a Virtual Machine, in our case `powerful-vm` 
- Also if we check the `xms_mirid` under the `Claims` field we will find that the name of the entity who has initiated the activity is passed. 
	- Even though we already have the Service Principal ID, we can see that its another resource that has initiated the activity

```sql
AzureActivity 
| where TimeGenerated > ago(100m)
| extend LocalTime = datetime_utc_to_local(TimeGenerated, 'Asia/Kolkata')
| extend Caller = tostring(parse_json(Properties)["caller"]),
         Entity = tostring(parse_json(Properties)["entity"]),
         EventCategory = tostring(parse_json(Properties)["eventCategory"]),
         ActivityStatus = tostring(parse_json(Properties)["activityStatusValue"]),
         Message = tostring(parse_json(Properties)["message"]),
         Resource = tostring(parse_json(Properties)["resource"]),
         ResourceProvider = tostring(parse_json(Properties)["resourceProviderValue"]),
         Action = tostring(parse_json(Authorization)["action"]),
         PrincipalId = tostring(parse_json(parse_json(Authorization)["evidence"])["principalId"]),
         principalType = tostring(parse_json(parse_json(Authorization)["evidence"])["principalType"]),
         role = tostring(parse_json(parse_json(Authorization)["evidence"])["role"]),
         roleAssignmentScope = tostring(parse_json(parse_json(Authorization)["evidence"])["roleAssignmentScope"]),
         roleDefinitionId = tostring(parse_json(parse_json(Authorization)["evidence"])["roleDefinitionId"]), scope = tostring(parse_json(Authorization)["scope"]),
         InitiatedBy = tostring(parse_json(Claims)["xms_mirid"])
| where principalType == "ServicePrincipal" and InitiatedBy contains "resourcegroups"
| project LocalTime, OperationNameValue, ActivityStatus, Caller, CategoryValue, EventCategory, Message, Resource, ResourceProvider, Action, PrincipalId, principalType,
          role, roleAssignmentScope, roleDefinitionId, scope, Entity, InitiatedBy
```


- This will filter out all the events where a Managed Identity accessed another resource.

![[MILateralMovement/Pictures/27.png]]



- Now we can use the Managed Identity ID from here and look into the Managed Identity Sign-in Logs

```sql
let MIActivityLogs = (AzureActivity 
| where TimeGenerated > ago(100m)
| extend LocalTime = datetime_utc_to_local(TimeGenerated, 'Asia/Kolkata')
| extend ServicePrincipalId = tostring(parse_json(Properties)["caller"]),
         Entity = tostring(parse_json(Properties)["entity"]),
         EventCategory = tostring(parse_json(Properties)["eventCategory"]),
         ActivityStatus = tostring(parse_json(Properties)["activityStatusValue"]),
         Message = tostring(parse_json(Properties)["message"]),
         Resource = tostring(parse_json(Properties)["resource"]),
         ResourceProvider = tostring(parse_json(Properties)["resourceProviderValue"]),
         Action = tostring(parse_json(Authorization)["action"]),
         PrincipalId = tostring(parse_json(parse_json(Authorization)["evidence"])["principalId"]),
         principalType = tostring(parse_json(parse_json(Authorization)["evidence"])["principalType"]),
         role = tostring(parse_json(parse_json(Authorization)["evidence"])["role"]),
         roleAssignmentScope = tostring(parse_json(parse_json(Authorization)["evidence"])["roleAssignmentScope"]),
         roleDefinitionId = tostring(parse_json(parse_json(Authorization)["evidence"])["roleDefinitionId"]),
         scope = tostring(parse_json(Authorization)["scope"]),
         InitiatedBy = tostring(parse_json(Claims)["xms_mirid"])
| where principalType == "ServicePrincipal" and InitiatedBy contains "resourcegroups"
| project LocalTime, OperationNameValue, ActivityStatus, ServicePrincipalId, CategoryValue, EventCategory, Message, Resource, ResourceProvider, Action, PrincipalId, principalType,
          role, roleAssignmentScope, roleDefinitionId, scope, Entity, InitiatedBy);
AADManagedIdentitySignInLogs
| extend LocalTime = datetime_utc_to_local(TimeGenerated, 'Asia/Kolkata')
| where TimeGenerated > ago(100m)
| join kind=inner MIActivityLogs on ServicePrincipalId
| project LocalTime, OperationName, ResultSignature, ResourceGroup, Category, ClientCredentialType, ResourceDisplayName, ResourceIdentity, ResourceServicePrincipalId, ServicePrincipalId, UserAgent, OperationNameValue, ActivityStatus, Message, Resource, ResourceProvider, Action, InitiatedBy
```


- Now if we see the User Agents carefully, we will find that this Managed Identity which also happens to belong to another Virtual Machine uses the `ImdsIdentityProvider`
	- This indicates that they have accessed the Managed Identity through the use of Metadata endpoint (which we did)

![[29.png]]

So we can add this as well in our detection

```sql
let MIActivityLogs = (AzureActivity 
| where TimeGenerated > ago(20m)
| extend LocalTime = datetime_utc_to_local(TimeGenerated, 'Asia/Kolkata')
| extend ServicePrincipalId = tostring(parse_json(Properties)["caller"]),
         Entity = tostring(parse_json(Properties)["entity"]),
         EventCategory = tostring(parse_json(Properties)["eventCategory"]),
         ActivityStatus = tostring(parse_json(Properties)["activityStatusValue"]),
         Message = tostring(parse_json(Properties)["message"]),
         Resource = tostring(parse_json(Properties)["resource"]),
         ResourceProvider = tostring(parse_json(Properties)["resourceProviderValue"]),
         Action = tostring(parse_json(Authorization)["action"]),
         PrincipalId = tostring(parse_json(parse_json(Authorization)["evidence"])["principalId"]),
         principalType = tostring(parse_json(parse_json(Authorization)["evidence"])["principalType"]),
         role = tostring(parse_json(parse_json(Authorization)["evidence"])["role"]),
         roleAssignmentScope = tostring(parse_json(parse_json(Authorization)["evidence"])["roleAssignmentScope"]),
         roleDefinitionId = tostring(parse_json(parse_json(Authorization)["evidence"])["roleDefinitionId"]),
         scope = tostring(parse_json(Authorization)["scope"]),
         InitiatedBy = tostring(parse_json(Claims)["xms_mirid"])
| where principalType == "ServicePrincipal" and InitiatedBy contains "resourcegroups"
| project LocalTime, OperationNameValue, ActivityStatus, ServicePrincipalId, CategoryValue, EventCategory, Message, Resource, ResourceProvider, Action, PrincipalId, principalType,
          role, roleAssignmentScope, roleDefinitionId, scope, Entity, InitiatedBy);
AADManagedIdentitySignInLogs
| extend LocalTime = datetime_utc_to_local(TimeGenerated, 'Asia/Kolkata')
| where TimeGenerated > ago(20m)
| join kind=inner MIActivityLogs on ServicePrincipalId
| where UserAgent contains "ImdsIdentityProvider"
| project LocalTime, OperationName, ResultSignature, ResourceGroup, Category, ClientCredentialType, ResourceDisplayName, ResourceIdentity, ResourceServicePrincipalId, ServicePrincipalId, UserAgent, OperationNameValue, ActivityStatus, Message, Resource, ResourceProvider, Action, InitiatedBy
```


- We can also look into the Managed Identity Logins by themselves and look for anything out of the ordinary

- Firstly we will find the User Agent with `ImdsIdentityProvider` which will indicate that the Managed Identity has been logged in through the use of the Metadata endpoint
- Next we will also look for logins where there are no location details, which is due to the the Managed Identity was directly used to perform logins

```sql
AADManagedIdentitySignInLogs
| extend LocalTime = datetime_utc_to_local(TimeGenerated, 'Asia/Kolkata')
| where TimeGenerated > ago(60m)
| extend Latitude = tostring(parse_json(parse_json(LocationDetails)["geoCoordinates"])["latitude"]),
         Longitude = tostring(parse_json(parse_json(LocationDetails)["geoCoordinates"])["longitude"])
| where Latitude == 0.0 and Longitude == 0.0
| where UserAgent contains "ImdsIdentityProvider"
| project LocalTime, OperationName, ResultSignature, ResourceGroup, Category, ClientCredentialType, ResourceDisplayName, ResourceIdentity, ResourceServicePrincipalId, ServicePrincipalId, UserAgent
```


# Conclusion

This research gives us an idea about how one can put some detection for some type of Managed Identity abuse. Since Managed Identities are very useful tools for the proper functioning of an Azure environment, it becomes difficult in case there are multiple resources attached to a single Managed Identity.

This can lead to the abuse of Managed Identities. Even though detection may vary depending on environment. For example, there might be some script which uses Managed Identities to access other resources like another Virtual Machine. Therefore, this detection is very generalised form of detecting some type of Managed Identity abuse.

