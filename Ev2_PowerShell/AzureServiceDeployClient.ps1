#-------------------------------------------------------------------------------------
# <copyright file="AzureServiceDeployClient.ps1" company="Microsoft">
#     Copyright (c) Microsoft Corporation.  All rights reserved.
# </copyright>
#
# <Summary>
#     AzureServiceDeploy Powershell command console startup script.
# </Summary>
#-------------------------------------------------------------------------------------
param(
    [bool]$fromShortcut
)

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$startupScriptSource = "https://msazure.pkgs.visualstudio.com/_packaging/ExpressV2/nuget/v3/index.json"
$waNugetDevSource = "https://msazure.pkgs.visualstudio.com/DefaultCollection/_apis/packaging/ManualMirror/nuget/index.json"
$waNugetOfficialSource = "https://msazure.pkgs.visualstudio.com/DefaultCollection/_apis/packaging/official/nuget/index.json"

$startupScriptPkgName = "Microsoft.Azure.AzureServiceDeployClientStartup"
$sdkPackageName = "Microsoft.Azure.AzureServiceDeployClient"

function CheckScriptUpdate
{
    try
    {
        $scriptPackagePath = Join-Path $azureServiceDeployClientPath "AzureServiceDeployClientStartup"
        $startupPkgVersionFile = Join-Path $azureServiceDeployClientPath "AzureServiceDeployClientStartup_version.txt"
        $found = $false

        EnsureDependencyPresence

        # Query latest version and check with the current version of the startup script.
        $latestPkgVer = GetLatestPackageVersion $startupScriptPkgName $startupScriptSource

        if (Test-Path $startupPkgVersionFile)
        {
            $installedVersion = Get-Content $startupPkgVersionFile
            $found = $installedVersion -eq $latestPkgVer
        }

        if (!$found)
        {
            Write-Host "Latest startup script not found. Downloading latest startup package $startupScriptPkgName."
            DownloadStartupScriptPackage $scriptPackagePath $latestPkgVer

            $scriptPackageLibPath = "$scriptPackagePath\$startupScriptPkgName.$latestPkgVer\lib\"

            # Update nuget.exe and credential provider exe from startup package path to the Startup-Script path
            $newNugetExePath = Join-Path $scriptPackageLibPath "Nuget.exe"
            if (Test-Path $newNugetExePath) {
                xcopy $newNugetExePath, $scriptPath /Y /C | Out-Null
            }

            $newCredManagerPath = Join-Path $scriptPackageLibPath "CredentialProvider.VSS.exe"
            if (Test-Path $newCredManagerPath) {
                xcopy $newCredManagerPath, $scriptPath /Y /C | Out-Null
            }

            $clientStartupPath = Join-Path $scriptPackageLibPath "AzureServiceDeployClient.ps1"
            if (Test-Path $clientStartupPath) {
                xcopy $clientStartupPath $scriptPath /Y /C | Out-Null

                Set-Content -Path $startupPkgVersionFile $latestPkgVer

                # Remove AzureServiceDeployClientStartup directory in %localappdata%
                Remove-Item $scriptPackagePath -Force -Recurse -Confirm:$false

                . "$scriptPath\AzureServiceDeployClient.ps1"

                return
            }
        }
    }
    catch
    {
        Write-Warning "Failed to update current script, continue to run the existing one"
    }

    if (Test-Path $scriptPackagePath)
    {
        Remove-Item $scriptPackagePath -Force -Recurse -Confirm:$false
    }

    LaunchCmdlet
}

function EnsureDependencyPresence
{
    if (!(Test-Path $nugetPath))
    {
        $appLocalNugetPath = Join-Path $azureServiceDeployClientPath "nuget.exe" 
        if (Test-Path $appLocalNugetPath)
        {
            xcopy $appLocalNugetPath, $scriptPath /Y /C | Out-Null
        }
        else {
            Write-Host "Required dependencies not found. Copy the latest Ev2 cmdlets and try again."
        }
    }

    $credManagerPath = Join-Path $scriptPath "CredentialProvider.VSS.exe"
    if (!(Test-Path $credManagerPath))
    {
        $appLocalCredMgrPath = Join-Path $azureServiceDeployClientPath "CredentialProvider.VSS.exe"
        if (Test-Path $appLocalCredMgrPath)
        {
            xcopy $appLocalCredMgrPath, $scriptPath /Y /C | Out-Null
        }
        else {
            Write-Host "Required dependencies not found. Copy the latest Ev2 cmdlets and try again."
        }
    }
}

function DownloadStartupScriptPackage($scriptPackagePath, $latestPkgVer)
{
    # Recreate AzureServiceDeployClientStartup directory before downloading the latest client startup package to that dir.
    if (Test-Path $scriptPackagePath)
    {
        Remove-Item -Path $scriptPackagePath -Force -Recurse -Confirm:$false
    }

    New-Item -ItemType Directory $scriptPackagePath | Out-Null
    & $nugetPath install $startupScriptPkgName -Prerelease -version $latestPkgVer -o $scriptPackagePath -ConfigFile "$azureServiceDeployClientPath\Nuget.config"
}

function write-header 
{
    param ([string]$s)
    $greeting = "`n*** $s ***`n"
    return $greeting
}

function SetupUI 
{
    write-host "Windows PowerShell"
    write-host "Copyright (C) 2017 Microsoft Corporation. All rights reserved."
    write-host 
    # available: "Black, DarkBlue, DarkGreen, DarkCyan, DarkRed, DarkMagenta, DarkYellow, Gray, DarkGray, Blue, Green, Cyan, Red, Magenta, Yellow, White
    $title = "Azure Service Deploy PowerShell"
    try
    {
        $Host.UI.RawUI.WindowTitle = $title
    }
    catch
    {
        # ignore error when Core language is not allowed in SAW machine
    }
    $msg = write-header "Welcome to $title"
    write-host $msg -foregroundcolor Cyan
}

function InstallLatestVersion($targetPath, $lastestPkg)
{
    if (!(Test-Path $targetPath))
    {
        New-Item -ItemType Directory $targetPath | Out-Null
    }

    $asdc = Join-Path $targetPath $lastestPkg 

    Write-Host "Fetching latest version $latestVStr of $sdkPackageName package"
    
    & $nugetPath install $sdkPackageName -Prerelease -version $latestVStr -o $targetPath -ConfigFile "$azureServiceDeployClientPath\Nuget.config"
    if (!(Test-Path "$targetPath\Microsoft.IdentityModel.Clients.ActiveDirectory.5.2.4"))
    {
        Remove-Item -Path "$targetPath\Microsoft.IdentityModel.Clients.ActiveDirectory*" -Force -Recurse -Confirm:$false
        & $nugetPath install "Microsoft.IdentityModel.Clients.ActiveDirectory" -version "5.2.4" -o $targetPath -ConfigFile "$azureServiceDeployClientPath\Nuget.config"
    }
    xcopy "$asdc\lib\*.*" $targetPath /Y /C | Out-Null
    $manifest = "$targetPath\AzureServiceDeployClient.manifest"
    if (Test-Path $manifest)
    {
        Get-Content $manifest | % {
            $parts = $_.Split(',');
            $path = (Get-ChildItem -Directory "$targetPath\$($parts[0]).*")[0].Name;
            xcopy "$targetPath\$path\$($parts[1])\*.*" $targetPath /Y /C | Out-Null
        }
    }
    else
    {
        # fallback when there is no manifest file in the package
        $path = (Get-ChildItem -Directory "$targetPath\Microsoft.IdentityModel.Clients.ActiveDirectory.*")[0].Name
        xcopy "$targetPath\$path\lib\net45\*.*" $targetPath /Y /C
        $path = (Get-ChildItem -Directory "$targetPath\WindowsAzure.Storage.*")[0].Name
        xcopy "$targetPath\$path\lib\net40\*.*" $targetPath /Y /C
        $path = (Get-ChildItem -Directory "$targetPath\Newtonsoft.Json.*")[0].Name
        xcopy "$targetPath\$path\lib\net40\*.*" $targetPath /Y /C
        $path = (Get-ChildItem -Directory "$targetPath\Microsoft.AspNet.WebApi.Client.*")[0].Name
        xcopy "$targetPath\$path\lib\net45\*.*" $targetPath /Y /C
        $path = (Get-ChildItem -Directory "$targetPath\Microsoft.AspNet.WebApi.Core.*")[0].Name
        xcopy "$targetPath\$path\lib\net45\*.*" $targetPath /Y /C
        $path = (Get-ChildItem -Directory "$targetPath\System.IdentityModel.Tokens.Jwt.*")[0].Name
        xcopy "$targetPath\$path\lib\net45\*.*" $targetPath /Y /C
        $path = (Get-ChildItem -Directory "$targetPath\System.ValueTuple.*")[0].Name
        xcopy "$targetPath\$path\lib\netstandard1.0\*.*" $targetPath /Y /C
    }

    Get-ChildItem -Directory -Exclude CmdLets,Samples,Schema $targetPath | %{ Remove-Item $_ -Force -Recurse -Confirm:$false }
}

function SetupNugetConfigFile
{
    $config = '<?xml version="1.0" encoding="utf-8"?>' +
        '<configuration>' +
            '<packageSources>' +
                '<add key="corext" value="https://msazure.pkgs.visualstudio.com/DefaultCollection/_apis/packaging/NugetMirror/nuget/index.json" />' +
                '<add key="WANugetOfficial" value="{0}" />' +
                '<add key="WANugetDev" value="{1}" />' +
                '<add key="ExpressV2" value="{2}" />' +
            '</packageSources>' + 
            '<activePackageSource>' +
                '<add key="WANugetOfficial" value="{0}" />' +
            '</activePackageSource>' +
        '</configuration>'
    $config -f $waNugetOfficialSource, $waNugetDevSource, $startupScriptSource | Out-File "$azureServiceDeployClientPath\Nuget.config" -Encoding ascii
}

function GetLatestPackageVersion($packageName, $source)
{
    $configFilePath = "$azureServiceDeployClientPath\Nuget.config"

    $packages = & $nugetPath list $packageName -Prerelease -Source $source -ConfigFile $configFilePath
    if (!($packages) -or ($packages -contains "No packages found.")) {
        # if no package found in the mirror source then throw
        throw
    }
  
    $versions = @()
    $vStrs = @()
    # Parsing all version string to version oject and get the latest
    foreach ($p in $packages) {
        if ($p.Contains($packageName)) {
            $vStr = $p.Split(' ')[1]
            $vStrs = $vStrs + $vStr
            $v = new-object Version($vstr.Split('-')[0])
            $versions = $versions + $v
        }
    }
    $latestVersion = ($versions | Sort -Descending)[0].ToString()
    $latestVStr = $vStrs | ? { $_.Contains($latestVersion) }

    return $latestVStr
}

function LaunchCmdlet
{
    try
    {
        # Check if any previous version already installed
        $versionFile = Join-Path $azureServiceDeployClientPath "versions.txt"
        $InstalledVersions = $null
        $prevVersion = $null
        $found = $false
        $latestVstr = $null
        if (Test-Path $versionFile)
        {
            $InstalledVersions = Get-Content $versionFile
            if ($InstalledVersions)
            {
                if ($InstalledVersions.GetType().Name -ieq "String")
                {
                    $prevVersion = $InstalledVersions
                }
                else
                {
                    $prevVersion = $InstalledVersions[$InstalledVersions.Length - 1]
                }
            }
        }

        # Ensuring dependency presence of nuget.exe and Cred Provider for back-compat
        EnsureDependencyPresence

        Write-Host "Checking for latest version of Azure Service Deploy cmdlets"
        # Query latest version

        $latestVstr = GetLatestPackageVersion $sdkPackageName $waNugetDevSource
        $lastestPkg = "$sdkPackageName.$latestVStr"
        if ($InstalledVersions)
        {
            $found = $InstalledVersions | ? { $_ -eq $latestVStr }    
        }

        if (!$found)
        {
            if ($prevVersion)
            {
                # try to delete all older version except n-1
                Get-ChildItem -Directory -Exclude $prevVersion $azureServiceDeployClientPath | %{ Remove-Item $_ -Force -Recurse -Confirm:$false -ErrorAction SilentlyContinue | Out-Null }
            }

            InstallLatestVersion -targetPath "$azureServiceDeployClientPath\$latestVStr" -lastestPkg $lastestPkg
            Set-Content -Path $versionFile $prevVersion
            Add-Content -Path $versionFile $latestVstr
            $scriptPath = Join-Path $azureServiceDeployClientPath $latestVstr
        }
        else
        {
            $scriptPath = Join-Path $azureServiceDeployClientPath $prevVersion
            $latestVStr = $prevVersion
        }

        cls
    }
    catch
    {
        if ($latestVstr)
        {
            Remove-Item (Join-Path $azureServiceDeployClientPath $latestVstr) -Force -Recurse -Confirm:$false
        }

        if ($prevVersion)
        {
            $scriptPath = Join-Path $azureServiceDeployClientPath $prevVersion
            $latestVStr = $prevVersion
        }
        else
        {
            Write-Error "Cannot access Nuget source to install the cmdlets at this time. Cannot fall back to a previously installed version either since none was found."
            Write-Warning "Please check network and try again."
            return
        }

        cls
        Write-Warning "Not able to fetch latest version of Azure Service Deploy cmdlets package"
        Write-Warning "Will continue to start with currently installed version of cmdlets if present."
    }

    SetupUI

    Write-Host "Using version $latestVStr"
    Write-Host "Load module from $scriptPath"

    $modulesToImport = @("Microsoft.Azure.Deployment.Express.Client" )

    foreach ($e in $modulesToImport) {
      Import-Module -global (Join-Path $scriptPath "$e.dll")
    }

    $cmdlets = $modulesToImport | %{ Get-Command -Module $_ } | %{$_.Name}
    $commands = ($cmdlets | Select -Unique | Sort)

    # Display the available cmdlets
    write-host "`n Commands:" -foregroundcolor Cyan
    $commands | %{write-host (' * {0}' -f $_) -foregroundcolor Cyan}

    write-Host
    write-host "For help on commands type Get-Help <command name>" -foregroundcolor Cyan
    write-Host

    try
    {
        $fileVersion = [System.Diagnostics.FileVersionInfo]::GetVersionInfo("$scriptPath\Microsoft.Azure.Deployment.Express.Client.dll").FileVersion
        $Host.UI.RawUI.WindowTitle += " $fileVersion ($latestVStr)"
    }
    catch
    {
        # ignore error when Core language is not allowed in SAW machine
    }
}

$scriptPath = Split-Path -Parent $PSCommandPath
$nugetPath = Join-Path $scriptPath "nuget.exe"
$azureServiceDeployClientPath = Join-Path $env:LOCALAPPDATA "Microsoft\AzureServiceDeployClient"

if (!(Test-Path $azureServiceDeployClientPath))
{
    New-Item -ItemType Directory $azureServiceDeployClientPath | Out-Null
}

SetupNugetConfigFile

if ($fromShortcut)
{
    CheckScriptUpdate
}
else
{
    LaunchCmdlet
}

# SIG # Begin signature block
# MIIjgwYJKoZIhvcNAQcCoIIjdDCCI3ACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBIUg7k7R1Ma4k6
# SMe/kOzS3odiTTOXQmBZESEdq0TkxqCCDYEwggX/MIID56ADAgECAhMzAAABUZ6N
# j0Bxow5BAAAAAAFRMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMTkwNTAyMjEzNzQ2WhcNMjAwNTAyMjEzNzQ2WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQCVWsaGaUcdNB7xVcNmdfZiVBhYFGcn8KMqxgNIvOZWNH9JYQLuhHhmJ5RWISy1
# oey3zTuxqLbkHAdmbeU8NFMo49Pv71MgIS9IG/EtqwOH7upan+lIq6NOcw5fO6Os
# +12R0Q28MzGn+3y7F2mKDnopVu0sEufy453gxz16M8bAw4+QXuv7+fR9WzRJ2CpU
# 62wQKYiFQMfew6Vh5fuPoXloN3k6+Qlz7zgcT4YRmxzx7jMVpP/uvK6sZcBxQ3Wg
# B/WkyXHgxaY19IAzLq2QiPiX2YryiR5EsYBq35BP7U15DlZtpSs2wIYTkkDBxhPJ
# IDJgowZu5GyhHdqrst3OjkSRAgMBAAGjggF+MIIBejAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUV4Iarkq57esagu6FUBb270Zijc8w
# UAYDVR0RBEkwR6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMRYwFAYDVQQFEw0yMzAwMTIrNDU0MTM1MB8GA1UdIwQYMBaAFEhu
# ZOVQBdOCqhc3NyK1bajKdQKVMFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY0NvZFNpZ1BDQTIwMTFfMjAxMS0w
# Ny0wOC5jcmwwYQYIKwYBBQUHAQEEVTBTMFEGCCsGAQUFBzAChkVodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY0NvZFNpZ1BDQTIwMTFfMjAx
# MS0wNy0wOC5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAWg+A
# rS4Anq7KrogslIQnoMHSXUPr/RqOIhJX+32ObuY3MFvdlRElbSsSJxrRy/OCCZdS
# se+f2AqQ+F/2aYwBDmUQbeMB8n0pYLZnOPifqe78RBH2fVZsvXxyfizbHubWWoUf
# NW/FJlZlLXwJmF3BoL8E2p09K3hagwz/otcKtQ1+Q4+DaOYXWleqJrJUsnHs9UiL
# crVF0leL/Q1V5bshob2OTlZq0qzSdrMDLWdhyrUOxnZ+ojZ7UdTY4VnCuogbZ9Zs
# 9syJbg7ZUS9SVgYkowRsWv5jV4lbqTD+tG4FzhOwcRQwdb6A8zp2Nnd+s7VdCuYF
# sGgI41ucD8oxVfcAMjF9YX5N2s4mltkqnUe3/htVrnxKKDAwSYliaux2L7gKw+bD
# 1kEZ/5ozLRnJ3jjDkomTrPctokY/KaZ1qub0NUnmOKH+3xUK/plWJK8BOQYuU7gK
# YH7Yy9WSKNlP7pKj6i417+3Na/frInjnBkKRCJ/eYTvBH+s5guezpfQWtU4bNo/j
# 8Qw2vpTQ9w7flhH78Rmwd319+YTmhv7TcxDbWlyteaj4RK2wk3pY1oSz2JPE5PNu
# Nmd9Gmf6oePZgy7Ii9JLLq8SnULV7b+IP0UXRY9q+GdRjM2AEX6msZvvPCIoG0aY
# HQu9wZsKEK2jqvWi8/xdeeeSI9FN6K1w4oVQM4Mwggd6MIIFYqADAgECAgphDpDS
# AAAAAAADMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0
# ZSBBdXRob3JpdHkgMjAxMTAeFw0xMTA3MDgyMDU5MDlaFw0yNjA3MDgyMTA5MDla
# MH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMT
# H01pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTEwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCr8PpyEBwurdhuqoIQTTS68rZYIZ9CGypr6VpQqrgG
# OBoESbp/wwwe3TdrxhLYC/A4wpkGsMg51QEUMULTiQ15ZId+lGAkbK+eSZzpaF7S
# 35tTsgosw6/ZqSuuegmv15ZZymAaBelmdugyUiYSL+erCFDPs0S3XdjELgN1q2jz
# y23zOlyhFvRGuuA4ZKxuZDV4pqBjDy3TQJP4494HDdVceaVJKecNvqATd76UPe/7
# 4ytaEB9NViiienLgEjq3SV7Y7e1DkYPZe7J7hhvZPrGMXeiJT4Qa8qEvWeSQOy2u
# M1jFtz7+MtOzAz2xsq+SOH7SnYAs9U5WkSE1JcM5bmR/U7qcD60ZI4TL9LoDho33
# X/DQUr+MlIe8wCF0JV8YKLbMJyg4JZg5SjbPfLGSrhwjp6lm7GEfauEoSZ1fiOIl
# XdMhSz5SxLVXPyQD8NF6Wy/VI+NwXQ9RRnez+ADhvKwCgl/bwBWzvRvUVUvnOaEP
# 6SNJvBi4RHxF5MHDcnrgcuck379GmcXvwhxX24ON7E1JMKerjt/sW5+v/N2wZuLB
# l4F77dbtS+dJKacTKKanfWeA5opieF+yL4TXV5xcv3coKPHtbcMojyyPQDdPweGF
# RInECUzF1KVDL3SV9274eCBYLBNdYJWaPk8zhNqwiBfenk70lrC8RqBsmNLg1oiM
# CwIDAQABo4IB7TCCAekwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFEhuZOVQ
# BdOCqhc3NyK1bajKdQKVMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1Ud
# DwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFHItOgIxkEO5FAVO
# 4eqnxzHRI4k0MFoGA1UdHwRTMFEwT6BNoEuGSWh0dHA6Ly9jcmwubWljcm9zb2Z0
# LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcmwwXgYIKwYBBQUHAQEEUjBQME4GCCsGAQUFBzAChkJodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcnQwgZ8GA1UdIASBlzCBlDCBkQYJKwYBBAGCNy4DMIGDMD8GCCsGAQUFBwIB
# FjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2RvY3MvcHJpbWFyeWNw
# cy5odG0wQAYIKwYBBQUHAgIwNB4yIB0ATABlAGcAYQBsAF8AcABvAGwAaQBjAHkA
# XwBzAHQAYQB0AGUAbQBlAG4AdAAuIB0wDQYJKoZIhvcNAQELBQADggIBAGfyhqWY
# 4FR5Gi7T2HRnIpsLlhHhY5KZQpZ90nkMkMFlXy4sPvjDctFtg/6+P+gKyju/R6mj
# 82nbY78iNaWXXWWEkH2LRlBV2AySfNIaSxzzPEKLUtCw/WvjPgcuKZvmPRul1LUd
# d5Q54ulkyUQ9eHoj8xN9ppB0g430yyYCRirCihC7pKkFDJvtaPpoLpWgKj8qa1hJ
# Yx8JaW5amJbkg/TAj/NGK978O9C9Ne9uJa7lryft0N3zDq+ZKJeYTQ49C/IIidYf
# wzIY4vDFLc5bnrRJOQrGCsLGra7lstnbFYhRRVg4MnEnGn+x9Cf43iw6IGmYslmJ
# aG5vp7d0w0AFBqYBKig+gj8TTWYLwLNN9eGPfxxvFX1Fp3blQCplo8NdUmKGwx1j
# NpeG39rz+PIWoZon4c2ll9DuXWNB41sHnIc+BncG0QaxdR8UvmFhtfDcxhsEvt9B
# xw4o7t5lL+yX9qFcltgA1qFGvVnzl6UJS0gQmYAf0AApxbGbpT9Fdx41xtKiop96
# eiL6SJUfq/tHI4D1nvi/a7dLl+LrdXga7Oo3mXkYS//WsyNodeav+vyL6wuA6mk7
# r/ww7QRMjt/fdW1jkT3RnVZOT7+AVyKheBEyIXrvQQqxP/uozKRdwaGIm1dxVk5I
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIVWDCCFVQCAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAVGejY9AcaMOQQAAAAABUTAN
# BglghkgBZQMEAgEFAKCBrjAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgn2pkp8/d
# qlSxODlygGizsNtu5VQ4S5JXyyXqDjxwRGcwQgYKKwYBBAGCNwIBDDE0MDKgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRqAGGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbTAN
# BgkqhkiG9w0BAQEFAASCAQBQoqNTKpb27bRKkV3+LeN2qPkdGSMyYPZnYAm6OYgF
# uS5L1u3F8IrY/njqN3FdEgfKZXpuUt/yZJshBWhwnbTEzcSfJuvThumhOhz2MAVT
# 61UeR2zt3vNToZ+VmuJKj1fWYO9T/LBIpGNP1IaviDLUJfrlE1MAetg+kyTL3wkW
# D52xHX+nsjL9Jovq/cV5+gEtxDQctacjgMLBQELYmvr0FT/kVPBeNG3v3MVjk82l
# cTQk4g3bHRr/uCEF/1IMu5zy/LFuSBgHNGPpe3UoQ9bNXnXYLejJ7lJSoKxJLnUa
# EQ6kx4y+ZzsXnHIgoOx6z162nIpHzfv3g2op6SrgH7N5oYIS4jCCEt4GCisGAQQB
# gjcDAwExghLOMIISygYJKoZIhvcNAQcCoIISuzCCErcCAQMxDzANBglghkgBZQME
# AgEFADCCAVEGCyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEEAYRZCgMB
# MDEwDQYJYIZIAWUDBAIBBQAEIA5lov1sGDKUHhaJ/xHjFtF+xB0RA0/gsRKEUzFy
# 7za4AgZdwsFlxpgYEzIwMTkxMjAzMTExNzU2LjMzM1owBIACAfSggdCkgc0wgcox
# CzAJBgNVBAYTAlVTMQswCQYDVQQIEwJXQTEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQg
# SXJlbGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1Mg
# RVNOOkZGMDYtNEJDMy1COURBMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFt
# cCBTZXJ2aWNloIIOOTCCBPEwggPZoAMCAQICEzMAAAEUNSdF6rbIbE8AAAAAARQw
# DQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcN
# MTkxMDIzMjMxOTM3WhcNMjEwMTIxMjMxOTM3WjCByjELMAkGA1UEBhMCVVMxCzAJ
# BgNVBAgTAldBMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlv
# bnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046RkYwNi00QkMzLUI5
# REExJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggEiMA0G
# CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCdvi0k88S1dkCr0Rb9Vgwts1CaVvWj
# i4j8Z6oJteo97xmiVPQbsXEbI7B8SEULpdsTxnLpWlk0lfGayBLb6mqwYyqS+e1i
# Skkl6pOdFuh00sfjHmOGhKhww2Tyx4NpoHBnAc/qbL4YATCnVrywYDOzs27m67Mv
# lKLiL9KHovfG1r7FHzyp1tbKQhctJWk8QEwSPUZGZt5MDTpd1Dh1z5zVQ2gz2A5I
# TBvVMWOoNY3L6co/9NVg4FoGrU9CT45rbX8d2x+DRXLSluVNn5CYse/fEhRVrZO6
# UiMKYMfTFsNWk5gf/0Bfr5IMCpfKdAltdzcMjqG2+OfDwURGNJmbfIz/AgMBAAGj
# ggEbMIIBFzAdBgNVHQ4EFgQUUFSPcOb+hJN3LEanWWXcI4uJPAIwHwYDVR0jBBgw
# FoAU1WM6XIoxkPNDe3xGG8UzaFqFbVUwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDov
# L2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljVGltU3RhUENB
# XzIwMTAtMDctMDEuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0
# cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNUaW1TdGFQQ0FfMjAx
# MC0wNy0wMS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDCDAN
# BgkqhkiG9w0BAQsFAAOCAQEAGSKMNfc4B8frM9Abi+4YqtynPH8Q8GppZluhR0AH
# 3mPEUPfiKWGM4nxWqr9VgJIFmgCh5hm/ssthGNHpnwVDWHe387yhXMIFFafhZJqf
# FnOk02md5bK6sNVQTdgq1pW/E7lEIaWFTE+O8WkNYg+hZEunA5G+zfam+dO1gE0g
# eM303kGkS5PsbGRdnhqxddE+0S/+qhgC6d2Nvu0NYU3zc9WF5wp7esRcYCCJz+OD
# TrPecbLtawY0u7EwelI+eUx76jFg8+Er7x+USdAPDhHeGLItI0nDf9zyxFrzvChq
# aNnbbHFK8kkCqVZb+570CBJTP6HPUblA/QN8rqhnplTnGjCCBnEwggRZoAMCAQIC
# CmEJgSoAAAAAAAIwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRp
# ZmljYXRlIEF1dGhvcml0eSAyMDEwMB4XDTEwMDcwMTIxMzY1NVoXDTI1MDcwMTIx
# NDY1NVowfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwggEiMA0GCSqGSIb3
# DQEBAQUAA4IBDwAwggEKAoIBAQCpHQ28dxGKOiDs/BOX9fp/aZRrdFQQ1aUKAIKF
# ++18aEssX8XD5WHCdrc+Zitb8BVTJwQxH0EbGpUdzgkTjnxhMFmxMEQP8WCIhFRD
# DNdNuDgIs0Ldk6zWczBXJoKjRQ3Q6vVHgc2/JGAyWGBG8lhHhjKEHnRhZ5FfgVSx
# z5NMksHEpl3RYRNuKMYa+YaAu99h/EbBJx0kZxJyGiGKr0tkiVBisV39dx898Fd1
# rL2KQk1AUdEPnAY+Z3/1ZsADlkR+79BL/W7lmsqxqPJ6Kgox8NpOBpG2iAg16Hgc
# sOmZzTznL0S6p/TcZL2kAcEgCZN4zfy8wMlEXV4WnAEFTyJNAgMBAAGjggHmMIIB
# 4jAQBgkrBgEEAYI3FQEEAwIBADAdBgNVHQ4EFgQU1WM6XIoxkPNDe3xGG8UzaFqF
# bVUwGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGGMA8GA1Ud
# EwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9lJBb186aGMQwVgYD
# VR0fBE8wTTBLoEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwv
# cHJvZHVjdHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3JsMFoGCCsGAQUFBwEB
# BE4wTDBKBggrBgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9j
# ZXJ0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcnQwgaAGA1UdIAEB/wSBlTCB
# kjCBjwYJKwYBBAGCNy4DMIGBMD0GCCsGAQUFBwIBFjFodHRwOi8vd3d3Lm1pY3Jv
# c29mdC5jb20vUEtJL2RvY3MvQ1BTL2RlZmF1bHQuaHRtMEAGCCsGAQUFBwICMDQe
# MiAdAEwAZQBnAGEAbABfAFAAbwBsAGkAYwB5AF8AUwB0AGEAdABlAG0AZQBuAHQA
# LiAdMA0GCSqGSIb3DQEBCwUAA4ICAQAH5ohRDeLG4Jg/gXEDPZ2joSFvs+umzPUx
# vs8F4qn++ldtGTCzwsVmyWrf9efweL3HqJ4l4/m87WtUVwgrUYJEEvu5U4zM9GAS
# inbMQEBBm9xcF/9c+V4XNZgkVkt070IQyK+/f8Z/8jd9Wj8c8pl5SpFSAK84Dxf1
# L3mBZdmptWvkx872ynoAb0swRCQiPM/tA6WWj1kpvLb9BOFwnzJKJ/1Vry/+tuWO
# M7tiX5rbV0Dp8c6ZZpCM/2pif93FSguRJuI57BlKcWOdeyFtw5yjojz6f32WapB4
# pm3S4Zz5Hfw42JT0xqUKloakvZ4argRCg7i1gJsiOCC1JeVk7Pf0v35jWSUPei45
# V3aicaoGig+JFrphpxHLmtgOR5qAxdDNp9DvfYPw4TtxCd9ddJgiCGHasFAeb73x
# 4QDf5zEHpJM692VHeOj4qEir995yfmFrb3epgcunCaw5u+zGy9iCtHLNHfS4hQEe
# gPsbiSpUObJb2sgNVZl6h3M7COaYLeqN4DMuEin1wC9UJyH3yKxO2ii4sanblrKn
# QqLJzxlBTeCG+SqaoxFmMNO7dDJL32N79ZmKLxvHIa9Zta7cRDyXUHHXodLFVeNp
# 3lfB0d4wwP3M5k37Db9dT+mdHhk4L7zPWAUu7w2gUDXa7wknHNWzfjUeCLraNtvT
# X4/edIhJEqGCAsswggI0AgEBMIH4oYHQpIHNMIHKMQswCQYDVQQGEwJVUzELMAkG
# A1UECBMCV0ExEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjEtMCsGA1UECxMkTWljcm9zb2Z0IElyZWxhbmQgT3BlcmF0aW9u
# cyBMaW1pdGVkMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjpGRjA2LTRCQzMtQjlE
# QTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcG
# BSsOAwIaAxUA4ATkl0QTu3uFAmVR+pqOPC6L4GeggYMwgYCkfjB8MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQg
# VGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUFAAIFAOGQLwcwIhgPMjAx
# OTEyMDMwODQ3MDNaGA8yMDE5MTIwNDA4NDcwM1owdDA6BgorBgEEAYRZCgQBMSww
# KjAKAgUA4ZAvBwIBADAHAgEAAgIgJTAHAgEAAgISOzAKAgUA4ZGAhwIBADA2Bgor
# BgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAID
# AYagMA0GCSqGSIb3DQEBBQUAA4GBAFUGaKV3xFNedL16WUMZCml5XVMXn3bmcEtp
# LNlBPYkh6rzim8EM05mwKLuFf2chdeDMwv7xRqEbPcbnyZnTOba8joVdx6frKYUQ
# 4MkWmQXGbA7PYdit1ebGTvTjuTRLYziRyiLkvfmiUXxsp4B5+50SSlVtgVZykD6k
# IZBnIGDcMYIDDTCCAwkCAQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIw
# MTACEzMAAAEUNSdF6rbIbE8AAAAAARQwDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqG
# SIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQg19ZpLOAkwLvq
# j7SeOp5fMFZfHTAMlBeoFPSndREOAbEwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHk
# MIG9BCBMEX+t50VMGPQQXEsFWfGBi8gat6mIS7jV9Lz5rc3rOjCBmDCBgKR+MHwx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1p
# Y3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABFDUnReq2yGxPAAAAAAEU
# MCIEICvF4pAfZAyEleU60MHaZwF4uYFEZJDkPN65I85+V4w9MA0GCSqGSIb3DQEB
# CwUABIIBACmf290RIcR9CmCHxUOQDXVrdNQk7ZPtSAi1/OVyMuPtU317SxEaC3nQ
# hqO19BiwVuw5pMUWYsydF0exv2TdUc88OKXEt6r/WkaNATJcrnK40mWXSIHp/2RJ
# PfZMz0DOIGJcA8g0NY1390N8qnnPW37nmjKqgYaWTgOMGkugAshO0wD2ISKuuhPb
# /oer2a/kATWXM3XFlSM3tbtYx0DZHjeBiw4Zf65Squr1zYpwGejbAE6uAiqp84FX
# uu0dxgAooIxEw181XvZBxbbksL+LyW7i3UUnhux6iYAJNelfORNzzV+qetegOXoi
# eOBW4zEK2mhE9awAQlBZ5b4OOYj7XnQ=
# SIG # End signature block
