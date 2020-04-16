
REM installing ev2 powershell client
PS C:\gitroot\Ev2Quickstart\Ev2_PowerShell> .\AzureServiceDeployClient.ps1

REM deploy application with ev2
PS C:\gitroot\Ev2Quickstart\Ev2_QuickStart\HelloWorldDeploy> .\AzureServiceDeployQuickStart.ps1 -subscriptionId "65dbb2c4-1f8d-436f-a431-6b4b27e6a13c" -resourceGroupName "ogf-eastus2euap" -email "suwatch@microsoft.com"

Operating on subscription 65dbb2c4-1f8d-436f-a431-6b4b27e6a13c

REM $rollout = New-AzureServiceRollout -ServiceGroupRoot $PSScriptRoot\\ServiceGroupRoot -RolloutSpec RolloutSpec.json -RolloutInfra Test 
REM $rolloutId = $rollout.RolloutId


REM RolloutSpec.json
REM - serviceModel
REM - scopeBindings
REM - orchestratedsteps
REM   - targetType, targetName  (targetType: ServiceResource to lookup targetName in serviceModel description)

REM RolloutSpec.json
REM - serviceModel
REM - scopeBindings
REM - orchestratedsteps
REM   - targetType, targetName  (targetType: ServiceResource to lookup targetName in serviceModel' serviceResources description)


REM ServiceModel.json
REM - serviceMetadata (serviceGroup, environment)
REM - serviceResourceGroupDefinitions (groupname and serviceResourceDefinitions)
REM   - serviceResourceDefinitions (armtemplate/parameters and rollout parameters)
REM - serviceResourceGroup (instanceof serviceResourceGroupDefinitions)
REM   - scopeTags (name for ScopeBindings.json)
REM   - serviceResources (instanceof serviceResourceDefinitions)
REM     - scopeTags (name for ScopeBindings.json)


REM ScopeBindings.json
REM apply scope replacement to serviceResources' armtemplate/parameters and rollout parameters






