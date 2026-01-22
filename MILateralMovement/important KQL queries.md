
1. Query to separate out VM Custom Extension Operations

```sql
AzureActivity 
| where OperationNameValue has 'MICROSOFT.COMPUTE/VIRTUALMACHINES/EXTENSIONS/' or OperationNameValue has 'Microsoft.Compute/virtualMachines/' and Properties has 'CustomScriptExtension'
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
         roleDefinitionId = tostring(parse_json(parse_json(Authorization)["evidence"])["roleDefinitionId"]),
         scope = tostring(parse_json(Authorization)["scope"])
| project OperationNameValue, ActivityStatus, Caller, CategoryValue, EventCategory, Message, Resource, ResourceProvider, Action, PrincipalId, principalType,
          role, roleAssignmentScope, roleDefinitionId, scope, Entity
```



2. Get Managed Identity Signin Logs

```sql
AADManagedIdentitySignInLogs
| extend LocalTime = datetime_utc_to_local(TimeGenerated, 'Asia/Kolkata')
| project OperationName, ResultSignature, ResourceGroup, Category, ClientCredentialType, ResourceDisplayName, ResourceIdentity, ResourceServicePrincipalId, ServicePrincipalId, UserAgent, LocalTime
```