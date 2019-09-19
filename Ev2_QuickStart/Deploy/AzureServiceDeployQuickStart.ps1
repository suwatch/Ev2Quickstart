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
    $resourceGroupNamePrefix,

    [Parameter(Mandatory=$true)]
    [string] 
    $email
)

$global:rolloutSpecRelPath= ".\ServiceGroupRoot\RolloutSpec.json"
$global:serviceModelRelPath= ".\ServiceGroupRoot\ServiceModel.json"

$global:parametersEUSPath = ".\ServiceGroupRoot\Parameters\WebApp.EastUS.Parameters.json" 
$global:parametersWUSPath = ".\ServiceGroupRoot\Parameters\WebApp.WestUS.Parameters.json"
$global:templatePath = ".\ServiceGroupRoot\Templates\WebApp.Template.json" 
$global:appPackageRelativePath = ".\ServiceGroupRoot\bin\WebApp.zip"
$global:westUSLocation = "West US"
$global:eastUSLocation = "East US"

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
        $email
    )

    Replace-ServiceModelPlaceHolders $resourceGroupName $subscriptionId
    Replace-ParametersPlaceHolders $resourceGroupName
    Setup-Rollout $subscriptionId $resourceGroupName $location $email
}

<#
.SYNOPSIS
Creates a rollout.
#>
function Setup-Rollout
{
    param
    (
        $subscriptionId,
        $resourceGroupName,
        $location,
        $email
    )

    Replace-RolloutPlaceholders $email

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
#>
function Replace-ServiceModelPlaceHolders
{
    param
    (
        $namePrefix,
        $subscriptionId
    )

    Replace-String "__RESOURCE_GROUP_PREFIX__" $namePrefix $global:serviceModelRelPath
    Replace-String "__SUBSCRIPTION_ID__" $subscriptionId $global:serviceModelRelPath
}

<#
.SYNOPSIS
Replaces the placeholders in the ARM parameters file with the inputs to the script and created dependent resource information. 
This parameters file is used to create the Ev2 ServiceModel and dependent resources.
#>
function Replace-ParametersPlaceHolders
{
    param
    (
        $namePrefix
    )

    $webAppResourcePrefix = $resourceGroupName + "WebApp"
    $webAppResourcePrefix = $webAppResourcePrefix -replace $global:escapePattern
    $webAppReplacementSymbol = "__WEBAPP_PREFIX__"

    Replace-String $webAppReplacementSymbol $webAppResourcePrefix $global:parametersEUSPath
    Replace-String $webAppReplacementSymbol $webAppResourcePrefix $global:parametersWUSPath
}

<#
.SYNOPSIS
Replaces the placeholders in the ARM parameters file with the inputs to the script and created dependent resource information. 
This parameters file is used to create the Rollout.
#>
function Replace-RolloutPlaceholders
{
    param
    (
        $email
    )

    Replace-String "__EMAIL__" $email $global:rolloutSpecRelPath
}

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
        $file
    )

    $content = Get-Content($file)
    $content = $content.replace($replacementSymbol, $replacementValue)
    $content | out-file $file -encoding UTF8
}

try {
    Write-Host "Operating on subscription $subscriptionId"

    $resourceGroupNamePrefix = $resourceGroupNamePrefix -replace $global:escapePattern
    Setup-EndToEnd $subscriptionId $resourceGroupNamePrefix $email
}
catch {
    Write-Host "Error encountered."
    throw
}
