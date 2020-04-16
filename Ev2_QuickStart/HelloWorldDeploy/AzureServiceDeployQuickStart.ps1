<#
.SYNOPSIS
Sets up all the required resources for an Ev2 rollout and launches the rollout.
#>

param (
    [Parameter(Mandatory=$true)]
    [string] 
    $subscriptionId,

    [Parameter(Mandatory=$true)]
    [string] 
    $resourceGroupName,

    [Parameter(Mandatory=$true)]
    [string] 
    $email
)


$global:rolloutSpecRelTemplatePath = ".\ServiceGroupRoot\RolloutSpec.template.json"
$global:rolloutSpecRelPath = ".\ServiceGroupRoot\RolloutSpec.json"

$global:serviceModelRelTemplatePath = ".\ServiceGroupRoot\ServiceModel.template.json"
$global:serviceModelRelPath = ".\ServiceGroupRoot\ServiceModel.json"

$global:scopeBindingsRelTemplatePath = ".\ServiceGroupRoot\ScopeBindings.template.json"
$global:scopeBindingsRelPath = ".\ServiceGroupRoot\ScopeBindings.json"

$global:parametersPath = ".\ServiceGroupRoot\Parameters\WebApp.Parameters.json"
$global:templatePath = ".\ServiceGroupRoot\Templates\WebApp.Template.json" 
$global:appPackageRelativePath = ".\ServiceGroupRoot\bin\WebApp.zip"

$global:escapePattern = '[^a-z0-9 ]'

<#
.SYNOPSIS
Sets up all the required artifacts and DeploymentManager resources and launches a rollout.
#>
function Setup-EndToEnd
{
	param
	(
        $subscriptionId,
        $resourceGroupName,
        $siteName,
        $location,
        $email
    )

    $locationAbbr = $location -replace '[ ]'

    Replace-String "__SUBSCRIPTION_ID__" $subscriptionId $global:serviceModelRelTemplatePath $global:serviceModelRelPath
    Replace-String "__RESOURCE_GROUP_NAME__" $resourceGroupName $global:serviceModelRelPath $global:serviceModelRelPath
    Replace-String "__WEBAPP_NAME__" $siteName $global:serviceModelRelPath $global:serviceModelRelPath
    Replace-String "__LOCATION__" $location $global:serviceModelRelPath $global:serviceModelRelPath
    Replace-String "__LOCATION_ABBR__" $locationAbbr $global:serviceModelRelPath $global:serviceModelRelPath

    Replace-String "__SUBSCRIPTION_ID__" $subscriptionId $global:scopeBindingsRelTemplatePath $global:scopeBindingsRelPath
    Replace-String "__RESOURCE_GROUP_NAME__" $resourceGroupName $global:scopeBindingsRelPath $global:scopeBindingsRelPath
    Replace-String "__WEBAPP_NAME__" $siteName $global:scopeBindingsRelPath $global:scopeBindingsRelPath
    Replace-String "__LOCATION__" $location $global:scopeBindingsRelPath $global:scopeBindingsRelPath
    Replace-String "__LOCATION_ABBR__" $locationAbbr $global:scopeBindingsRelPath $global:scopeBindingsRelPath

    Replace-String "__LOCATION_ABBR__" $locationAbbr $global:rolloutSpecRelTemplatePath $global:rolloutSpecRelPath
    Replace-String "__EMAIL__" $email $global:rolloutSpecRelPath $global:rolloutSpecRelPath

    $rollout = New-AzureServiceRollout -ServiceGroupRoot $PSScriptRoot\\ServiceGroupRoot -RolloutSpec RolloutSpec.json -RolloutInfra Test 
    $rolloutId = $rollout.RolloutId
    Write-Host "`nCreated rollout with ID $rolloutId"

    #Replace-ServiceModelPlaceHolders $subscriptionId $resourceGroupName $siteName
    #Replace-ParametersPlaceHolders $resourceGroupName

    #Replace-RolloutPlaceholders $email
    #Setup-Rollout $subscriptionId $resourceGroupName $email
}

<#
.SYNOPSIS
Creates a rollout.
#>
function Setup-Rollout
{
    param
    (
        $subscriptionId
    )

    Write-Host "`nCreating rollout with service group root as $PSScriptRoot\ServiceGroupRoot and using the rollout spec RolloutSpec.json in it. The rollout spec defines the orchestration of the two WebApps that will be deployed."
    Write-Host "`n`nLogin using 2FA on the prompt with your Azure account that has access to the given subscription $subscriptionId. You need to have Contributor permissions on this subscription."
    Write-Host "`n`n`n---------"

    $rollout = New-AzureServiceRollout -ServiceGroupRoot $PSScriptRoot\\ServiceGroupRoot -RolloutSpec RolloutSpec.json -RolloutInfra Test 
    $rolloutId = $rollout.RolloutId

    Write-Host "---------`n`n`n"
    Write-Host "`nCreated rollout with ID $rolloutId"
    Write-Host "`nAs defined in the rollout spec, the rollout first deploys the app to the West US region, waits for 3 minutes per the wait step and then to the East US region."
    Write-Host "`nOpen the above link to the Ev2 portal in a browser and track the progress of the rollout."
    Write-Host "`n`n`n"
}

<#
.SYNOPSIS
Replaces the placeholders in the ARM parameters file with the inputs to the script and created dependent resource information. 
This parameters file is used to create the Ev2 ServiceModel and dependent resources.
function Replace-ServiceModelPlaceHolders
{
    param
    (
        $subscriptionId,
        $resourceGroupName,
        $siteName
    )

    Replace-String "__SUBSCRIPTION_ID__" $subscriptionId $global:serviceModelRelTemplatePath $global:serviceModelRelPath
    Replace-String "__RESOURCE_GROUP_NAME__" $resourceGroupName $global:serviceModelRelPath $global:serviceModelRelPath
    Replace-String "__WEBAPP_NAME__" $siteName $global:serviceModelRelPath $global:serviceModelRelPath
}
#>

<#
.SYNOPSIS
Replaces the placeholders in the ARM parameters file with the inputs to the script and created dependent resource information. 
This parameters file is used to create the Ev2 ServiceModel and dependent resources.
function Replace-ParametersPlaceHolders
{
    param
    (
        $namePrefix
    )

    $webAppResourcePrefix = $namePrefix + "WebApp"
    # no need to replace '[^a-z0-9 ]' with empty string
    # $webAppResourcePrefix = $webAppResourcePrefix -replace $global:escapePattern
    $webAppReplacementSymbol = "__WEBAPP_NAME__"

    Replace-String $webAppReplacementSymbol $webAppResourcePrefix $global:parametersPath
}
#>

<#
.SYNOPSIS
Replaces the placeholders in the ARM parameters file with the inputs to the script and created dependent resource information. 
This parameters file is used to create the Rollout.
function Replace-RolloutPlaceholders
{
    param
    (
        $email
    )

    Replace-String "__EMAIL__" $email $global:rolloutSpecRelTemplatePath $global:rolloutSpecRelTemplatePath
}
#>

<#
.SYNOPSIS
Replaces a string in a file with the given replacement value. 
#>
function Replace-String
{
    param 
    (
        $replacementSymbol,
        $replacementValue,
        $inputFile,
        $outputFile
    )

    $content = Get-Content($inputFile)
    $content = $content.replace($replacementSymbol, $replacementValue)
    $content | out-file $outputFile -encoding UTF8
}

try {
    Write-Host "Operating on subscription $subscriptionId"

    # no need to replace '[^a-z0-9 ]' with empty string
    # $resourceGroupName = $resourceGroupName -replace $global:escapePattern
    Setup-EndToEnd $subscriptionId $resourceGroupName "Ev2HelloWorld" "East US 2 EUAP" $email
}
catch {
    Write-Host "Error encountered."
    throw
}
