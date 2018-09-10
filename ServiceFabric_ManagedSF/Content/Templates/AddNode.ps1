[CmdletBinding(DefaultParametersetName="Unsecure")] 
param (
    [Parameter(ParameterSetName="Unsecure", Mandatory=$true)]
    [Parameter(ParameterSetName="Certificate", Mandatory=$true)]
    [string] $NodeName,

    [Parameter(ParameterSetName="Unsecure", Mandatory=$true)]
    [Parameter(ParameterSetName="Certificate", Mandatory=$true)]
    [string] $NodeType,

    [Parameter(ParameterSetName="Unsecure", Mandatory=$true)]
    [Parameter(ParameterSetName="Certificate", Mandatory=$true)]
    [string] $NodeIpAddressOrFQDN,

    [Parameter(ParameterSetName="Unsecure", Mandatory=$true)]
    [Parameter(ParameterSetName="Certificate", Mandatory=$true)]
    [string] $ExistingClientConnectionEndpoint,

    [Parameter(ParameterSetName="Unsecure", Mandatory=$true)]
    [Parameter(ParameterSetName="Certificate", Mandatory=$true)]
    [string] $UpgradeDomain,

    [Parameter(ParameterSetName="Unsecure", Mandatory=$true)]
    [Parameter(ParameterSetName="Certificate", Mandatory=$true)]
    [string] $FaultDomain,

    [Parameter(ParameterSetName="Unsecure", Mandatory=$false)]
    [Parameter(ParameterSetName="Certificate", Mandatory=$false)]
    [switch] $AcceptEULA,

    [Parameter(ParameterSetName="Unsecure", Mandatory=$false)]
    [Parameter(ParameterSetName="Certificate", Mandatory=$false)]
    [string] $FabricRuntimePackagePath,
    
    [Parameter(ParameterSetName="Certificate", Mandatory=$true)]
    [switch] $X509Credential,

    [Parameter(ParameterSetName="Certificate", Mandatory=$true)]
    [string] $ServerCertThumbprint,

    [Parameter(ParameterSetName="Certificate", Mandatory=$true)]
    [string] $StoreLocation,

    [Parameter(ParameterSetName="Certificate", Mandatory=$true)]
    [string] $StoreName,

    [Parameter(ParameterSetName="Certificate", Mandatory=$true)]
    [string] $FindValueThumbprint
)

$Identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = New-Object System.Security.Principal.WindowsPrincipal($Identity)
$IsAdmin = $Principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

if(!$IsAdmin)
{
    Write-host "Please run the script with administrative privileges." -ForegroundColor "Red"
    exit 1
}

if(!$AcceptEULA.IsPresent)
{
    $EulaAccepted = Read-Host 'Do you accept the license terms for using Microsoft Azure Service Fabric located in the root of your package download? If you do not accept the license terms you may not use the software.
[Y] Yes  [N] No  [?] Help (default is "N")'
    if($EulaAccepted -ne "y" -and $EulaAccepted -ne "Y")
    {
        Write-host "You need to accept the license terms for using Microsoft Azure Service Fabric located in the root of your package download before you can use the software." -ForegroundColor "Red"
        exit 1
    }
}

$ThisScriptPath = $(Split-Path -parent $MyInvocation.MyCommand.Definition)
$DeployerBinPath = Join-Path $ThisScriptPath -ChildPath "DeploymentComponents"
if(!(Test-Path $DeployerBinPath))
{
    $DCAutoExtractorPath = Join-Path $ThisScriptPath "DeploymentComponentsAutoextractor.exe"
    if(!(Test-Path $DCAutoExtractorPath)) 
    {
        Write-Host "Standalone package DeploymentComponents and DeploymentComponentsAutoextractor.exe are not present local to the script location."
        exit 1
    }

    #Extract DeploymentComponents
    $DCExtractArguments = "/E /Y /L `"$ThisScriptPath`""
    $DCExtractOutput = cmd.exe /c "$DCAutoExtractorPath $DCExtractArguments && exit 0 || exit 1"
    if($LASTEXITCODE -eq 1)
    {
        Write-Host "Extracting DeploymentComponents Cab ran into an issue."
        Write-Host $DCExtractOutput
        exit 1
    }
    else
    {
        Write-Host "DeploymentComponents extracted."
    }
}

$SystemFabricModulePath = Join-Path $DeployerBinPath -ChildPath "System.Fabric.dll"
if(!(Test-Path $SystemFabricModulePath)) 
{
    Write-Host "Run the script local to the Standalone package directory."
    exit 1
}

$MicrosoftServiceFabricCabFileAbsolutePath = $null
if($FabricRuntimePackagePath)
{
    $MicrosoftServiceFabricCabFileAbsolutePath = Resolve-Path $FabricRuntimePackagePath
    if(!(Test-Path $MicrosoftServiceFabricCabFileAbsolutePath)) 
    {
        Write-Host "Microsoft Service Fabric Runtime package not found in the specified directory : $FabricRuntimePackagePath"
        exit 1
    }
}
else
{
    $RuntimeBinPath = Join-Path $ThisScriptPath -ChildPath "DeploymentRuntimePackages"
    if(!(Test-Path $RuntimeBinPath)) 
    {
        Write-Host "No directory exists for Runtime packages. Creating a new directory."
        md $RuntimeBinPath | Out-Null
        Write-Host "Done creating $RuntimeBinPath"
    }
}

$ServiceFabricPowershellModulePath = Join-Path $DeployerBinPath -ChildPath "ServiceFabric.psd1"

# Invoke in separate AppDomain
if($X509Credential)
{
    $argList = @($DeployerBinPath, $ExistingClientConnectionEndpoint, $ServiceFabricPowershellModulePath, $NodeName, $NodeType, $NodeIpAddressOrFQDN, $UpgradeDomain, $FaultDomain, $MicrosoftServiceFabricCabFileAbsolutePath, $true, $ServerCertThumbprint, $StoreLocation, $StoreName, $FindValueThumbprint)
}
else
{
    $argList = @($DeployerBinPath, $ExistingClientConnectionEndpoint, $ServiceFabricPowershellModulePath, $NodeName, $NodeType, $NodeIpAddressOrFQDN, $UpgradeDomain, $FaultDomain, $MicrosoftServiceFabricCabFileAbsolutePath )
}

Powershell -Command {
    param (
        [Parameter(Mandatory=$true)]
        [string] $DeployerBinPath,
        
        [Parameter(Mandatory=$true)]
        [string] $ExistingClientConnectionEndpoint,

        [Parameter(Mandatory=$true)]
        [string] $ServiceFabricPowershellModulePath,

        [Parameter(Mandatory=$true)]
        [string] $NodeName,

        [Parameter(Mandatory=$true)]
        [string] $NodeType,

        [Parameter(Mandatory=$true)]
        [string] $NodeIpAddressOrFQDN,

        [Parameter(Mandatory=$true)]
        [string] $UpgradeDomain,

        [Parameter(Mandatory=$true)]
        [string] $FaultDomain,

        [Parameter(Mandatory=$false)]
        [string] $MicrosoftServiceFabricCabFileAbsolutePath,

        [Parameter(Mandatory=$false)]
        [bool] $X509Credential,

        [Parameter(Mandatory=$false)]
        [string] $ServerCertThumbprint,

        [Parameter(Mandatory=$false)]
        [string] $StoreLocation,

        [Parameter(Mandatory=$false)]
        [string] $StoreName,

        [Parameter(Mandatory=$false)]
        [string] $FindValueThumbprint
    )
    
    #Add FabricCodePath Environment Path
    $env:path = "$($DeployerBinPath);" + $env:path

    #Import Service Fabric Powershell Module
    Import-Module $ServiceFabricPowershellModulePath

    Try
    {
        # Connect to the existing cluster
        if($X509Credential)
        {
            Connect-ServiceFabricCluster -ConnectionEndpoint $ExistingClientConnectionEndpoint -X509Credential -ServerCertThumbprint $ServerCertThumbprint -StoreLocation $StoreLocation -StoreName $StoreName -FindValue $FindValueThumbprint -FindType FindByThumbprint
        }
        else
        {
            Connect-ServiceFabricCluster $ExistingClientConnectionEndpoint
        }
        
        if(!$MicrosoftServiceFabricCabFileAbsolutePath)
        {				
            # Get runtime package details
            $UpgradeStatus = Get-ServiceFabricClusterUpgrade
            if($UpgradeStatus.UpgradeState -ne "RollingForwardCompleted" -And $UpgradeStatus.UpgradeState -ne "RollingBackCompleted")
            {		
                Write-Host "New node cannot be added to the cluster while upgrade is in progress or before cluster has finished bootstrapping. To monitor upgrade state run Get-ServiceFabricClusterUpgrade and wait till UpgradeState switches to either RollingForwardCompleted or RollingBackCompleted." -ForegroundColor Red
                exit 1
            }
            $RuntimeCabFilename = "MicrosoftAzureServiceFabric." + $UpgradeStatus.TargetCodeVersion + ".cab"
            $DeploymentPackageRoot = Split-Path -parent $DeployerBinPath
            $RuntimeBinPath = Join-Path $DeploymentPackageRoot -ChildPath "DeploymentRuntimePackages"
            $MicrosoftServiceFabricCabFilePath = Join-Path $RuntimeBinPath -ChildPath $RuntimeCabFilename
            if(!(Test-Path $MicrosoftServiceFabricCabFilePath)) 
            {
                $RuntimePackageDetails = Get-ServiceFabricRuntimeSupportedVersion
                $RequiredPackage = $RuntimePackageDetails.RuntimePackages | where { $_.Version -eq $UpgradeStatus.TargetCodeVersion }
                if($RequiredPackage -eq $null)
                {
                    Write-Host "The required runtime version is no longer supported. Please upgrade your cluster to the latest version before adding a node." -ForegroundColor Red
                    exit 1
                }
                    $Version = $UpgradeStatus.TargetCodeVersion
                    Write-Host "Runtime package version $Version was not found in DeploymentRuntimePackages folder and needed to be downloaded."
                    (New-Object System.Net.WebClient).DownloadFile($RuntimePackageDetails.GoalRuntimeLocation, $MicrosoftServiceFabricCabFilePath)
                    Write-Host "Runtime package has been successfully downloaded to $MicrosoftServiceFabricCabFilePath."
            }
            $MicrosoftServiceFabricCabFileAbsolutePath = Resolve-Path $MicrosoftServiceFabricCabFilePath
        }
    }
    Catch
    {
        Write-Host "Runtime package cannot be downloaded. Check you internet connectivity. If the cluster is not connected to the internet run Get-ServiceFabricClusterUpgrade and note the TargetCodeVersion. Run Get-ServiceFabricRuntimeSupportedVersion from a machine connected to the internet to get the download links for all supported fabric versions. Download the package corresponding to your TargetCodeVersion. Pass -FabricRuntimePackageOutputDirectory <Path to runtime package> to AddNode.ps1 in addition to other parameters. Exception thrown : $($_.Exception.ToString())" -ForegroundColor Red
        exit 1
    }

    #Add Node to an existing cluster
    Try
    {
        Get-ServiceFabricNode | ft
        Add-ServiceFabricNode -NodeName $NodeName -NodeType $NodeType -IpAddressOrFQDN $NodeIpAddressOrFQDN -UpgradeDomain $UpgradeDomain -FaultDomain $FaultDomain -FabricRuntimePackagePath $MicrosoftServiceFabricCabFileAbsolutePath -Verbose

        Start-Sleep -s 30
        Get-ServiceFabricNode |ft
    }
    Catch
    {
        Write-Host "Add node to existing cluster failed with exception: $($_.Exception.ToString())" -ForegroundColor Red
        exit 1
    }
    
} -args $argList -OutputFormat Text

$env:Path = [System.Environment]::GetEnvironmentVariable("path","Machine")
