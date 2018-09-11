
param
(
        [parameter(Mandatory = $true)]
        [System.UInt32]
        $DeploymentNodeIndex,

        [parameter(Mandatory = $true)]
        [System.String]
        $ClusterName,

        [parameter(Mandatory = $true)]
        [System.String]
        $VMNodeTypePrefix,

        [parameter(Mandatory = $true)]
        [System.UInt32[]]
        $VMNodeTypeInstanceCounts,

        [parameter(Mandatory = $true)]
        [System.UInt32]
        $CurrentVMNodeTypeIndex,

        [parameter(Mandatory = $true)]
        [System.String] $SubnetIPFormat,

        [parameter(Mandatory = $true)]
        [System.UInt32] $NodeTypeCount,

        [parameter(Mandatory = $true)]
        [System.String]
        $ClientConnectionEndpointPort,

        [parameter(Mandatory = $true)]
        [System.String]
        $HTTPGatewayEndpointPort,

        [parameter(Mandatory = $true)]
        [System.String]
        $ReverseProxyEndpointPort,

        [parameter(Mandatory = $true)]
        [System.String]
        $EphemeralStartPort,

        [parameter(Mandatory = $true)]
        [System.String]
        $EphemeralEndPort,

        [parameter(Mandatory = $true)]
        [System.String]
        $ApplicationStartPort,

        [parameter(Mandatory = $true)]
        [System.String]
        $ApplicationEndPort,

        [parameter(Mandatory = $true)]
        [System.String]
        $ConfigPath,

        [parameter(Mandatory = $true)]
        [System.String]
        $ServiceFabricUrl,

        [parameter(Mandatory = $true)]
        [System.String]
        $ServiceFabricRuntimeUrl,

        [parameter(Mandatory = $true)]
        [System.String]
        $DiagStoreAccountName,

        [parameter(Mandatory = $true)]
        [System.String]
        $DiagStoreAccountKey,

        [parameter(Mandatory = $true)]
        [System.String]
        $DiagStoreAccountBlobUri,

        [parameter(Mandatory = $true)]
        [System.String]
        $DiagStoreAccountTableUri,

        [parameter(Mandatory = $true)]
        [System.String]
        $ClientConnectionEndpoint,

        [parameter(Mandatory = $true)]
        [System.String]
        $CertificateStoreValue,

        [parameter(Mandatory = $false)]
        [System.String]
        $DNSService = "No",

        [parameter(Mandatory = $false)]
        [System.String]
        $RepairManager = "No"
 )

# Static certificate Common Names for Service Fabric deployment
$subjectNames = @{  "ClusterCert" = "CN=SFClusterCertificate";
                    "ServerCert" = "CN=SFServerCertificate";
                    "ReverseProxyCert" = "CN=SFReverseProxyCertificate";
                    "AdminClientCert" = "CN=SFAdminClientCertificate";
                    "NonAdminClientCert" = "CN=SFNonAdminClientCertificate"
                    }

# SF deployment workflow Step 1: Provision 
#     Running on every node, preparing environment for service fabric installnation. 

$ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop
$VerbosePreference = "Continue"

# Enable File and Printer Sharing for Network Discovery (Port 445)
Write-Verbose "Opening TCP firewall port 445 for networking."
Set-NetFirewallRule -Name 'FPS-SMB-In-TCP' -Enabled True
Get-NetFirewallRule -DisplayGroup 'Network Discovery' | Set-NetFirewallRule -Profile 'Private, Public' -Enabled true

# Add remote IP addresse for 'Windows Remote Management (HTTP-In)'
# This enables every node have access to the nodes behind different sub domains
# IP range got from paramater should have a format of 10.0.[].0/24
Write-Verbose "Add remote IP addresses for Windows Remote Management (HTTP-In) for different sub domain."
$IParray = @()
for($i = 0; $i -lt $NodeTypeCount; $i ++)
{
    $IParray += $SubnetIPFormat.Replace("[]", $i)
}
Set-NetFirewallRule -Name 'WINRM-HTTP-In-TCP-PUBLIC' -RemoteAddress $IParray
Write-Verbose "Subnet IPs enabled in WINRM-HTTP-In-TCP-PUBLIC: $IParray"

# As per Service fabric documentation at: 
# https://docs.microsoft.com/en-us/azure/service-fabric/service-fabric-windows-cluster-x509-security#install-the-certificates
# set the access control on this certificate so that the Service Fabric process, which runs under the Network Service account
Write-Verbose "Granting Network access to SF Cluster Certificate" -Verbose
Grant-CertAccess -subjectName $subjectNames.ClusterCert -serviceAccount "Network Service"

Write-Verbose "Granting Network access to SF Server Certificate" -Verbose
Grant-CertAccess -subjectName $subjectNames.ServerCert -serviceAccount "Network Service"

try {
    Write-Verbose "Granting Network access to SF ReverseProxy Certificate" -Verbose
    Grant-CertAccess -subjectName $subjectNames.ReverseProxyCert -serviceAccount "Network Service"
}
catch {
    Write-Verbose $_
}

# Provision util functions
function Grant-CertAccess
{
    param
    (
    [Parameter(Position=1, Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$subjectName,

    [Parameter(Position=2, Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$serviceAccount
    )

    $cert = Get-ChildItem -Path cert:\LocalMachine\My | Where-Object -FilterScript { $PSItem.SubjectName.Name -eq $subjectName; }
    if ($cert.Count -ne 1)
    {
        Write-Error -Exception "$($cert.Count) certificate(s) with $subjectName found. Expecting only one"
        throw
    }
    # Specify the user, the permissions, and the permission type
    $permission = "$($serviceAccount)","FullControl","Allow"
    $accessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $permission

    # Location of the machine-related keys
    $keyPath = Join-Path -Path $env:ProgramData -ChildPath "\Microsoft\Crypto\RSA\MachineKeys"
    $keyName = $cert.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName
    $keyFullPath = Join-Path -Path $keyPath -ChildPath $keyName

    # Get the current ACL of the private key
    $acl = (Get-Item $keyFullPath).GetAccessControl('Access')

    # Add the new ACE to the ACL of the private key
    $acl.SetAccessRule($accessRule)

    # Write back the new ACL
    Set-Acl -Path $keyFullPath -AclObject $acl -ErrorAction Stop

    # Observe the access rights currently assigned to this certificate
    get-acl $keyFullPath| fl
}


# SF deployment workflow Step 2: Deployment 
#     For new SF deployment, running from the 'master' node. For scaling out scenario, running from the target node. 

$ErrorActionPreference = "Stop"

$vmNodeTypeName = "$VMNodeTypePrefix$CurrentVMNodeTypeIndex"

# Get the decimal based index of the VM machine name (VM Scale set name the machines in the format {Prefix}{Suffix}
# where Suffix is a 6 digit base36 number starting from 000000 to zzzzzz.
# Get the decimal index of current node and match it with the index of required deployment node.
$scaleSetDecimalIndex = ConvertFrom-Base36 -base36Num ($env:COMPUTERNAME.Substring(($vmNodeTypeName).Length))

# TODO: Do this in prepare step as its needed for all the nodes now.

# Store setup files on Temp disk.
$setupDir = "D:\SFSetup"
New-Item -Path $setupDir -ItemType Directory -Force
cd $setupDir
Write-Verbose "Downloading Service Fabric deployment package from: '$serviceFabricUrl'"
Invoke-WebRequest -Uri $serviceFabricUrl -OutFile (Join-Path -Path $setupDir -ChildPath ServiceFabric.zip) -UseBasicParsing
Expand-Archive (Join-Path -Path $setupDir -ChildPath ServiceFabric.zip) -DestinationPath (Join-Path -Path $setupDir -ChildPath ServiceFabric) -Force

$ClusterCertificateThumbprint = Get-CertThumbPrint -subjectName $subjectNames.ClusterCert
$ServerCertificateThumbprint = Get-CertThumbPrint -subjectName $subjectNames.ServerCert
$ReverseProxyCertificateThumbprint = Get-CertThumbPrint -subjectName $subjectNames.ReverseProxyCert
$AdminClientCertificateThumbprint = Get-CertThumbPrint -subjectName $subjectNames.AdminClientCert
$NonAdminClientCertificateThumbprint = Get-CertThumbPrint -subjectName $subjectNames.NonAdminClientCert

# For scale-up scenario as there is no sequencing of extensions provided by VMSS, 
# execution need to wait till the Script based extension completes imporing of neccessary certificates and granting required permissions.
# For first time deployment this will just pass through as the certs are already there and access have already been granted.
# Refer: https://msftstack.wordpress.com/2016/05/12/extension-sequencing-in-azure-vm-scale-sets/

Wait-ForCertInstall -ClusterCertificateThumbprint $ClusterCertificateThumbprint -ServerCertificateThumbprint $ServerCertificateThumbprint -ReverseProxyCertificateThumbprint $ReverseProxyCertificateThumbprint

# Check if Cluster already exists on Master node and if this is a addNode scenario.
$clusterExists = $false
$addNode = $false

# Unpack and install Service fabric cmdlets to be able to connect to public cluster endpoint in order to determine if already a cluster exists.
$DeployerBinPath = Join-Path $setupDir -ChildPath "ServiceFabric\DeploymentComponents"
$sfModulePath = Get-ServiceFabricModulePath -SetupDir $setupDir

# Execute the commands in a seperate powershell process to avoid any loaded dll collision with the Service fabric runtime installation later.
$localSession = New-PSSession -ComputerName localhost    
Write-Verbose "Local PS session created: $localSession"

try
{
    [ScriptBlock] $sb = {

            #Add FabricCodePath Environment Path
            $env:path = "$($Using:DeployerBinPath);" + $env:path

            #Import Service Fabric Powershell Module
            Import-Module $Using:sfModulePath -Verbose:$false

            # Connecting to secure cluster: 
            # https://docs.microsoft.com/en-us/azure/service-fabric/service-fabric-connect-to-secure-cluster#connect-to-a-secure-cluster-using-a-client-certificate
            $connection = Connect-ServiceFabricCluster -X509Credential `
                                        -ConnectionEndpoint $Using:ClientConnectionEndpoint `
                                        -ServerCertThumbprint $ServerCertificateThumbprint `
                                        -StoreLocation "LocalMachine" `
                                        -StoreName "My" `
                                        -FindValue $ServerCertificateThumbprint `
                                        -FindType FindByThumbprint

            $connection
    }

    try
    {   
        $connection = Invoke-Command -Session $localSession -ScriptBlock $sb
    }
    catch
    {
        # Dont throw because we are only interested in knowing if cluster exists or not.
        Write-Verbose "$_"
    }

    $clusterExists = $connection -and $connection[0]

    if($clusterExists)
    {
        # If cluster already exists, check if current node already exists in cluster.
        Write-Verbose "Service Fabric cluster already exists. Checking if '$($env:COMPUTERNAME)' already a member node."

        $sfNodes = Invoke-Command -Session $localSession -ScriptBlock { Get-ServiceFabricNode | % {$_.NodeName} }
        if($sfNodes -contains $env:COMPUTERNAME)
        {
            # If current node already part of the cluster - Do nothing.
            Write-Verbose "Current node is already a part of the cluster. No action needed."
            return
        }
        
        # If Cluster exists and current node is not part of the cluster then add the new node.
        Write-Verbose "Current node is not part of the cluster. Adding node: '$($env:COMPUTERNAME)'."
        $addNode = $true
    }
}
finally
{
   Remove-PSSession -Session $localSession
}

if($addNode)
{
    # Prepare cluster configration to make sure new nodetype add before add new node
    Write-Verbose "Adding new node... Preparing cluster configration..."
    Prepare-NodeType -setupDir $setupDir `
                     -VMNodeTypePrefix $VMNodeTypePrefix `
                     -CurrentVMNodeTypeIndex $CurrentVMNodeTypeIndex `
                     -ClientConnectionEndpointPort $ClientConnectionEndpointPort `
                     -HTTPGatewayEndpointPort $HTTPGatewayEndpointPort `
                     -ReverseProxyEndpointPort $ReverseProxyEndpointPort `
                     -EphemeralStartPort $EphemeralStartPort `
                     -EphemeralEndPort $EphemeralEndPort `
                     -ApplicationStartPort $ApplicationStartPort `
                     -ApplicationEndPort $ApplicationEndPort

    # Collect Node details
    Write-Verbose "Adding new node - Collect Node details"
    $nodeName = $env:COMPUTERNAME
    $nodeIpAddressLable = (Get-NetIPAddress).IPv4Address | ? {$_ -ne "" -and $_ -ne "127.0.0.1"}
    $nodeIpAddress = [IPAddress](([String]$nodeIpAddressLable).Trim(' '))
    Write-Verbose "Node IPAddress: '$nodeIpAddress'"

    $fdIndex = $scaleSetDecimalIndex + 1
    $faultDomain = "fd:/dc$fdIndex/r0"
    $upgradeDomain = "UD$scaleSetDecimalIndex"

    Write-Verbose "Adding new node - Start adding new node"
    New-ServiceFabricNode -setupDir $setupDir `
                          -ServiceFabricUrl $ServiceFabricUrl `
                          -NodeName $nodeName `
                          -VMNodeTypeName $VMNodeTypeName `
                          -NodeIpAddress $nodeIpAddress `
                          -UpgradeDomain $upgradeDomain `
                          -FaultDomain $faultDomain `
                          -ClientConnectionEndpoint $ClientConnectionEndpoint `
                          -ConfigPath $ConfigPath `
                          -ServerCertThumbprint $ServerCertificateThumbprint `
                          -FindValueThumbprint $ServerCertificateThumbprint

    # Initial configration after adding new node
    Write-Verbose "Adding new node - Initial cluster configration"
    Initial-ServiceFabricClusterConfiguration -setupDir $setupDir

    Write-Verbose "Successfully add new node."
    return
}

# If no cluster exists, it is fresh deployment
# Check if current Node is master node.
$isMasterNode = $scaleSetDecimalIndex -eq $DeploymentNodeIndex -and $CurrentVMNodeTypeIndex -eq 0

# Return in case the current node is not the 'master' node (deployment node), else continue with SF deployment on deployment node.
if(-not $isMasterNode)
{
    Write-Verbose "Service Fabric deployment runs on Node with index: '$DeploymentNodeIndex'."
    return
}

# Deploy Service Fabric. Following logic only runs on 'master' node.
Write-Verbose "Starting service fabric deployment on Node: '$env:COMPUTERNAME'."

# Waiting for all other nodes are ready.
Write-Verbose "Checking all other nodes..."

Wait-ForAllNodesReadiness -InstanceCounts $VMNodeTypeInstanceCounts `
                          -VMNodeTypePrefix $VMNodeTypePrefix `
                          -ClusterCertificateThumbprint $ClusterCertificateThumbprint `
                          -ServerCertificateThumbprint $ServerCertificateThumbprint `
                          -ReverseProxyCertificateThumbprint $ReverseProxyCertificateThumbprint


# Get Service fabric configuration file locally for update.
Write-Verbose "Get Service fabric configuration from '$ConfigPath'"
$request = Invoke-WebRequest $ConfigPath -UseBasicParsing
$configContent = ConvertFrom-Json  $request.Content
$ConfigFilePath = Join-Path -Path $setupDir -ChildPath 'ClusterConfig.json'
Write-Verbose "Creating service fabric config file at: '$ConfigFilePath'"
$configContent = ConvertTo-Json $configContent -Depth 99
$configContent | Out-File $ConfigFilePath

# Add Nodes configuration.
Add-ServiceFabricNodeConfiguration -ConfigFilePath $ConfigFilePath `
                                   -ClusterName $ClusterName `
                                   -InstanceCounts $VMNodeTypeInstanceCounts `
                                   -VMNodeTypePrefix $VMNodeTypePrefix `
                                   -SubnetIPFormat $SubnetIPFormat

# Add NodeType configuration.
Add-ServiceFabricNodeTypeConfiguration -ConfigFilePath $ConfigFilePath `
                                       -VMNodeTypePrefix $VMNodeTypePrefix `
                                       -NodeTypeCounts $VMNodeTypeInstanceCounts.Count`
                                       -ClientConnectionEndpointPort $ClientConnectionEndpointPort `
                                       -HTTPGatewayEndpointPort $HTTPGatewayEndpointPort `
                                       -ReverseProxyEndpointPort $ReverseProxyEndpointPort `
                                       -EphemeralStartPort $EphemeralStartPort `
                                       -EphemeralEndPort $EphemeralEndPort `
                                       -ApplicationStartPort $ApplicationStartPort `
                                       -ApplicationEndPort $ApplicationEndPort

# Add Deiagnostics configuration.
Add-ServiceFabricDiagnosticsConfiguration -ConfigFilePath $ConfigFilePath `
                                          -DiagStoreAccountName $DiagStoreAccountName `
                                          -DiagStoreAccountKey $DiagStoreAccountKey `
                                          -DiagStoreAccountBlobUri $DiagStoreAccountBlobUri `
                                          -DiagStoreAccountTableUri $DiagStoreAccountTableUri

# Add Security configuration.
Add-ServiceFabricSecurityConfiguration -ConfigFilePath $ConfigFilePath `
                                       -CertificateStoreValue $CertificateStoreValue `
                                       -ClusterCertificateThumbprint $ClusterCertificateThumbprint `
                                       -ServerCertificateThumbprint $ServerCertificateThumbprint `
                                       -ReverseProxyCertificateStoreValue $CertificateStoreValue `
                                       -ReverseProxyCertificateThumbprint $ReverseProxyCertificateThumbprint `
                                       -AdminClientCertificateThumbprint $AdminClientCertificateThumbprint `
                                       -NonAdminClientCertificateThumbprint $NonAdminClientCertificateThumbprint

# Add Optional Features (if Any)
Add-OptionalFeaturesConfiguration -ConfigFilePath $ConfigFilePath -DNSService $DNSService -RepairManager $RepairManager

# Validate and Deploy Service Fabric Configuration
New-ServiceFabricDeployment -setupDir $setupDir -ConfigFilePath $ConfigFilePath -ServiceFabricUrl $ServiceFabricUrl -ServiceFabricRuntimeUrl $ServiceFabricRuntimeUrl

# Validations
Write-Verbose "Validating Service Fabric deployment."

Test-ServiceFabricDeployment -setupDir $setupDir


# Deployment util functions

function ConvertFrom-Base36
{
    param
    (
        [String] $base36Num
    )

    $alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"

    $inputarray = $base36Num.tolower().tochararray()
    [array]::reverse($inputarray)
                
    [long]$decimalIndex=0
    $pos=0

    foreach ($c in $inputarray)
    {
        $decimalIndex += $alphabet.IndexOf($c) * [long][Math]::Pow(36, $pos)
        $pos++
    }

    return $decimalIndex
}

function convertTo-Base36
{
    [CmdletBinding()]
    param ([int]$decNum="")

    $alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"

    do
    {
        $remainder = ($decNum % 36)
        $char = $alphabet.substring($remainder,1)
        $base36Num = "$char$base36Num"
        $decNum = ($decNum - $remainder) / 36
    }
    while ($decNum -gt 0)

    return $base36Num
}

function Add-ServiceFabricNodeConfiguration
{
    param
    (
        [String] $ConfigFilePath,

        [String] $ClusterName,

        [System.UInt32[]] $InstanceCounts,

        [String] $VMNodeTypePrefix,

        [String] $SubnetIPFormat
    )

    $ErrorActionPreference = "Stop"

    [String] $content = Get-Content -Path $ConfigFilePath
    $configContent = ConvertFrom-Json  $content

    $configContent.name = "$ClusterName"

    # Adding Nodes to the configuration.
    $sfnodes = @()
    $tagIpFormat =  $SubnetIPFormat.Substring(0,$SubnetIPFormat.IndexOf('[')) + '*'
    try
    {
        Set-Item WSMan:\localhost\Client\TrustedHosts -Value * -Force

        for($j = 0; $j -lt $InstanceCounts.Count; $j++)
        {
            $InstanceCount = $InstanceCounts[$j]
            $VMNodeTypeName = "$VMNodeTypePrefix$j"
            
            for($i = 0; $i -lt $InstanceCount; $i++)
            {
                [String] $base36Index = (convertTo-Base36 -decNum $i)

                $nodeName = $VMNodeTypeName + $base36Index.PadLeft(6, "0")
            
                Write-Verbose "Retriving ip for $nodeName ..."

                $ip = Invoke-Command -ScriptBlock {
                                        $nodeIpAddressLable = (Get-NetIPAddress).IPv4Address | ? {$_ -like $Using:tagIpFormat}
                                        $nodeIpAddress = ([String]$nodeIpAddressLable).Trim(' ')
                                        return $nodeIpAddress
                                    } -ComputerName $nodeName

                Write-Verbose "IP for Node '$nodeName' is: '$($ip.ToString())'"
            
                $nodeScaleSetDecimalIndex = $i

                $fdIndex = $nodeScaleSetDecimalIndex + 1

                $node = New-Object PSObject
                $node | Add-Member -MemberType NoteProperty -Name "nodeName" -Value $nodeName
                $node | Add-Member -MemberType NoteProperty -Name "iPAddress" -Value $($ip.ToString())
                $node | Add-Member -MemberType NoteProperty -Name "nodeTypeRef" -Value "$VMNodeTypeName"
                $node | Add-Member -MemberType NoteProperty -Name "faultDomain" -Value "fd:/dc$fdIndex/r0"
                $node | Add-Member -MemberType NoteProperty -Name "upgradeDomain" -Value "UD$nodeScaleSetDecimalIndex"

                Write-Verbose "Adding Node to configuration: '$nodeName'"
                $sfnodes += $node
            }
        }
    }
    finally
    {
        Set-Item WSMan:\localhost\Client\TrustedHosts -Value "" -Force
    }

    $configContent.nodes = $sfnodes

    $configContent = ConvertTo-Json $configContent -Depth 99
    $configContent | Out-File $ConfigFilePath
}

function Add-ServiceFabricNodeTypeConfiguration
{
    param
    (
        [System.String]
        $ConfigFilePath,

        [System.String]
        $VMNodeTypePrefix,

        [System.UInt32] $NodeTypeCounts,

        [System.String]
        $ClientConnectionEndpointPort,

        [System.String]
        $HTTPGatewayEndpointPort,

        [System.String]
        $ReverseProxyEndpointPort,

        [System.String]
        $EphemeralStartPort,

        [System.String]
        $EphemeralEndPort,

        [System.String]
        $ApplicationStartPort,

        [System.String]
        $ApplicationEndPort
    )

    $ErrorActionPreference = "Stop"

    [String] $content = Get-Content -Path $ConfigFilePath
    $configContent = ConvertFrom-Json  $content

    # Adding Node Type to the configuration.
    Write-Verbose "Creating node type."
    $nodeTypes =@()

    for($i=0; $i -lt $NodeTypeCounts; $i++)
    {
        $VMNodeTypeName = "$VMNodeTypePrefix$i"
        $nodeType = New-Object PSObject
        $nodeType | Add-Member -MemberType NoteProperty -Name "name" -Value "$VMNodeTypeName"
        $nodeType | Add-Member -MemberType NoteProperty -Name "clientConnectionEndpointPort" -Value "$ClientConnectionEndpointPort"
        $nodeType | Add-Member -MemberType NoteProperty -Name "clusterConnectionEndpointPort" -Value "19001"
        $nodeType | Add-Member -MemberType NoteProperty -Name "leaseDriverEndpointPort" -Value "19002"
        $nodeType | Add-Member -MemberType NoteProperty -Name "serviceConnectionEndpointPort" -Value "19003"
        $nodeType | Add-Member -MemberType NoteProperty -Name "httpGatewayEndpointPort" -Value "$HTTPGatewayEndpointPort"
        $nodeType | Add-Member -MemberType NoteProperty -Name "reverseProxyEndpointPort" -Value "$ReverseProxyEndpointPort"

        $applicationPorts = New-Object PSObject
        $applicationPorts | Add-Member -MemberType NoteProperty -Name "startPort" -Value "$ApplicationStartPort"
        $applicationPorts | Add-Member -MemberType NoteProperty -Name "endPort" -Value "$ApplicationEndPort"

        $ephemeralPorts = New-Object PSObject
        $ephemeralPorts | Add-Member -MemberType NoteProperty -Name "startPort" -Value "$EphemeralStartPort"
        $ephemeralPorts | Add-Member -MemberType NoteProperty -Name "endPort" -Value "$EphemeralEndPort"

        $nodeType | Add-Member -MemberType NoteProperty -Name "applicationPorts" -Value $applicationPorts
        $nodeType | Add-Member -MemberType NoteProperty -Name "ephemeralPorts" -Value $ephemeralPorts

        if($i -eq 0)
        {
            $nodeType | Add-Member -MemberType NoteProperty -Name "isPrimary" -Value $true
        }
        else
        {
            $nodeType | Add-Member -MemberType NoteProperty -Name "isPrimary" -Value $false
        }

        Write-Verbose "Adding Node Type to configuration."
        $nodeTypes += $nodeType
    }

    $configContent.properties.nodeTypes = $nodeTypes

    $configContent = ConvertTo-Json $configContent -Depth 99
    $configContent | Out-File $ConfigFilePath
}

function Add-ServiceFabricDiagnosticsConfiguration
{
    param
    (
        [System.String]
        $ConfigFilePath,

        [System.String]
        $DiagStoreAccountName,

        [System.String]
        $DiagStoreAccountKey,

        [System.String]
        $DiagStoreAccountBlobUri,

        [System.String]
        $DiagStoreAccountTableUri
    )
    
    $ErrorActionPreference = "Stop"

    [String] $content = Get-Content -Path $ConfigFilePath
    $configContent = ConvertFrom-Json  $content

    # Adding Diagnostics store settings to the configuration.
    $diagStoreConnectinString = "xstore:DefaultEndpointsProtocol=https;AccountName=$DiagStoreAccountName;AccountKey=$DiagStoreAccountKey;BlobEndpoint=$DiagStoreAccountBlobUri;TableEndpoint=$DiagStoreAccountTableUri"

    Write-Verbose "Setting diagnostics store to: '$diagStoreConnectinString'"
    $configContent.properties.diagnosticsStore.connectionstring = $diagStoreConnectinString

    $configContent = ConvertTo-Json $configContent -Depth 99
    $configContent | Out-File $ConfigFilePath
}

function Add-ServiceFabricSecurityConfiguration
{
    param
    (
        [System.String]
        $ConfigFilePath,

        [System.String]
        $CertificateStoreValue,

        [System.String]
        $ClusterCertificateThumbprint,

        [System.String]
        $ServerCertificateThumbprint,

        [System.String]
        $ReverseProxyCertificateThumbprint,

        [System.String[]]
        $AdminClientCertificateThumbprint,

        [System.String[]]
        $NonAdminClientCertificateThumbprint
    )

    $ErrorActionPreference = "Stop"

    [String] $content = Get-Content -Path $ConfigFilePath
    $configContent = ConvertFrom-Json  $content

    # Adding Security settings to the configuration.
    Write-Verbose "Adding security settings for Service Fabric Configuration."
    $configContent.properties.security.CertificateInformation.ClusterCertificate.Thumbprint = $ClusterCertificateThumbprint
    $configContent.properties.security.CertificateInformation.ClusterCertificate.X509StoreName = $certificateStoreValue

    $configContent.properties.security.CertificateInformation.ServerCertificate.Thumbprint = $ServerCertificateThumbprint
    $configContent.properties.security.CertificateInformation.ServerCertificate.X509StoreName = $certificateStoreValue

    if(-not [string]::IsNullOrEmpty($ReverseProxyCertificateThumbprint))
    {
        $configContent.properties.security.CertificateInformation.ReverseProxyCertificate.Thumbprint = $ReverseProxyCertificateThumbprint
        $configContent.properties.security.CertificateInformation.ReverseProxyCertificate.X509StoreName = $CertificateStoreValue
    }
    else
    {
        $configContent.properties.security.CertificateInformation.ReverseProxyCertificate = $null
    }

    Write-Verbose "Creating Client Certificate Thumbprint data."
    $ClientCertificateThumbprints = @()

    $AdminClientCertificateThumbprint | % {
            $thumbprint = $_.Trim()
            if(-not [String]::IsNullOrEmpty($thumbprint))
            {
                $adminClientCertificate = New-Object PSObject
                $adminClientCertificate | Add-Member -MemberType NoteProperty -Name "CertificateThumbprint" -Value "$thumbprint"
                $adminClientCertificate | Add-Member -MemberType NoteProperty -Name "IsAdmin" -Value $true
                $ClientCertificateThumbprints += $adminClientCertificate    
            }
        }

    $NonAdminClientCertificateThumbprint | % {
            $thumbprint = $_.Trim()
            if(-not [String]::IsNullOrEmpty($thumbprint))
            {
                $nonAdminClientCertificate = New-Object PSObject
                $nonAdminClientCertificate | Add-Member -MemberType NoteProperty -Name "CertificateThumbprint" -Value "$thumbprint"
                $nonAdminClientCertificate | Add-Member -MemberType NoteProperty -Name "IsAdmin" -Value $false
                $ClientCertificateThumbprints += $nonAdminClientCertificate
            }
        }

    if($ClientCertificateThumbprints.Length -eq 0)
    {
        $configContent.properties.security.CertificateInformation.ClientCertificateThumbprints = $null
    }
    else
    {
        $configContent.properties.security.CertificateInformation.ClientCertificateThumbprints = $ClientCertificateThumbprints
    }

    $configContent = ConvertTo-Json $configContent -Depth 99
    $configContent | Out-File $ConfigFilePath
}

function Add-OptionalFeaturesConfiguration
{
    param
    (
        [System.String]
        $ConfigFilePath,

        [System.String]
        $DNSService,

        [System.String]
        $RepairManager
    )

    $ErrorActionPreference = "Stop"

    [String] $content = Get-Content -Path $ConfigFilePath
    $configContent = ConvertFrom-Json  $content

    # Adding Optional Add-On feature to the configuration.
    Write-Verbose "Adding Optional Add-On feature for Service Fabric Configuration."

    $addOnFeatures = @()

    if($DNSService -eq "Yes")
    {
        $addOnFeatures += "DnsService"
    }

    if($RepairManager -eq "Yes")
    {
        $addOnFeatures += "RepairManager"
    }

    if($addOnFeatures.Length -eq 0)
    {
        $configContent.properties.addOnFeatures = $null
    }
    else
    {
        $configContent.properties.addOnFeatures = $addOnFeatures
    }

    $configContent = ConvertTo-Json $configContent -Depth 99
    $configContent | Out-File $ConfigFilePath
}

function New-ServiceFabricDeployment
{
    param
    (
        [System.String]
        $setupDir,

        [System.String]
        $ConfigFilePath,

        [System.String]
        $ServiceFabricUrl,

        [System.String]
        $ServiceFabricRuntimeUrl
    )
    
    $ErrorActionPreference = "Stop"

    # Deployment
    Write-Verbose "Validating Service Fabric input configuration"
    $output = .\ServiceFabric\TestConfiguration.ps1 -ClusterConfigFilePath $ConfigFilePath -Verbose

    $passStatus = $output | % {if($_ -like "Passed*"){$_}}
    $del = " ", ":"
    $configValidationresult = ($passStatus.Split($del, [System.StringSplitOptions]::RemoveEmptyEntries))[1]

    if($configValidationresult -ne "True")
    {
        throw ($output | Out-String)
    }

    # For a given ServiceFabricRuntimeUrl, download the runtime cab file
    Write-Verbose "Input runtime $ServiceFabricRuntimeUrl"
    if($ServiceFabricRuntimeUrl -eq 'N/A')
    {
        Write-Verbose "Starting Service Fabric runtime deployment with latest version..."
        $output = .\ServiceFabric\CreateServiceFabricCluster.ps1 -ClusterConfigFilePath $ConfigFilePath -AcceptEULA -Verbose
        Write-Verbose ($output | Out-String)
    }
    else
    {
        Write-Verbose "Downloading specified service fabric runtime...$ServiceFabricRuntimeUrl"
        $sfRunTimeDir = "D:\SFSetup\SFRunTime"
        New-Item -Path $sfRunTimeDir -ItemType Directory -Force

        $sfRunTimePkg = Join-Path -Path $sfRunTimeDir -ChildPath (Split-Path $ServiceFabricRuntimeUrl -Leaf)
        Invoke-WebRequest -Uri $ServiceFabricRuntimeUrl -OutFile $sfRunTimePkg -UseBasicParsing
        Write-Verbose "Download finished, runtime package path: $sfRunTimePkg"

        Write-Verbose "Starting Service Fabric runtime deployment with the given version..."
        $output = .\ServiceFabric\CreateServiceFabricCluster.ps1 -ClusterConfigFilePath $ConfigFilePath -FabricRuntimePackagePath $sfRunTimePkg -AcceptEULA -Verbose
        Write-Verbose ($output | Out-String)
    }

    Write-Verbose "Done with Fabric runtime deployment."
}

function Test-ServiceFabricDeployment
{
    param
    (
        [System.String]
        $setupDir
    )

    $ErrorActionPreference = "Stop"

    # Test Connection

    $timeoutTime = (Get-Date).AddMinutes(5)
    $connectSucceeded = $false
    $lastException

    while(-not $connectSucceeded -and (Get-Date) -lt $timeoutTime)
    {
        try
        {   
            Import-Module ServiceFabric -ErrorAction SilentlyContinue -Verbose:$false
            $connection = Connect-ServiceFabricCluster
            if($connection -and $connection[0])
            {
                Write-Verbose "Service Fabric connection successful." 
                $connectSucceeded = $true
            }
            else
            {
                throw "Could not connect to service fabric cluster."
            }
        }
        catch
        {
            $lastException = $_.Exception
            Write-Verbose "Connection failed because: $lastException. Retrying until $timeoutTime."
            Write-Verbose "Waiting for 60 seconds..."
            Start-Sleep -Seconds 60
        }
    }

    if(-not $connectSucceeded)
    {
        throw "Cluster validation failed with error: $lastException.`n Please check the detailed DSC logs and Service fabric deployment traces at: '$setupDir\ServiceFabric\DeploymentTraces' on the VM: '$env:ComputerName'."
    }

    
    # Test Cluster health

    $timeoutTime = (Get-Date).AddMinutes(5)
    $isHealthy = $false

    while((-not $isHealthy) -and ((Get-Date) -lt $timeoutTime))
    {
        $Error.Clear()
        $healthReport = Get-ServiceFabricClusterHealth #Get-ServiceFabricClusterHealth ToString is bugged, so calling twice
        $healthReport = Get-ServiceFabricClusterHealth
        if(($healthReport.HealthEvents.Count > 0) -or ($healthReport.UnhealthyEvaluations.Count > 0))
        {
            Write-Verbose "Cluster health events were raised. Retrying until $timeoutTime."
            Start-Sleep -Seconds 60
        }
        else
        {
            Write-Verbose "Service Fabric cluster is healthy." 
            $isHealthy = $true
        }
    }

    if(-not $isHealthy)
    {
        throw "Cluster validation failed with error: Cluster unhealthy.`n Please check the detailed DSC logs and Service fabric deployment traces at: '$setupDir\ServiceFabric\DeploymentTraces' on the VM: '$env:ComputerName'."
    }

    # Test Cluster upgrade status
    [string[]] $nodes = Get-ServiceFabricNode | % {$_.NodeName}
    $minutesToWait = 5 * ($nodes.Count)
    $timeoutTime = (Get-Date).AddMinutes($minutesToWait)
    $upgradeComplete = $false
    $lastException

    while((-not $upgradeComplete) -and ((Get-Date) -lt $timeoutTime))
    {
        try
        {
            $upgradeStatus = (Get-ServiceFabricClusterConfigurationUpgradeStatus).UpgradeState

            if($upgradeStatus -eq "RollingForwardCompleted")
            {
                Write-Verbose "Expected service Fabric upgrade status '$upgradeStatus' set." 
                $upgradeComplete = $true
            }
            else
            {
                throw "Unexpected Upgrade status: '$upgradeStatus'."
            }
        }
        catch
        {
            $lastException = $_.Exception
            Write-Verbose "Upgrade status check failed because: $lastException. Retrying until $timeoutTime."
            Write-Verbose "Waiting for 60 seconds..."
            Start-Sleep -Seconds 60
        }
    }

    if(-not $upgradeComplete)
    {
        throw "Cluster validation failed with error: $lastException.`n Please check the detailed DSC logs and Service fabric deployment traces at: '$setupDir\ServiceFabric\DeploymentTraces' on the VM: '$env:ComputerName'."
    }
}

function Get-CertThumbPrint
{
    param
    (
        [System.String]
        $subjectName
    )
    return (Get-ChildItem -Path cert:\LocalMachine\My | Where-Object { $_.SubjectName.Name -eq $subjectName }).Thumbprint
}

function Wait-ForCertInstall
{
    param
    (
        [System.String]
        $ClusterCertificateThumbprint,
        
        [System.String]
        $ServerCertificateThumbprint,

        [System.String]
        $ReverseProxyCertificateThumbprint
    )

    $allCerts = @()

    if(-not [string]::IsNullOrEmpty($ClusterCertificateThumbprint))
    {
        $allCerts += $ClusterCertificateThumbprint
    }

    if(-not [string]::IsNullOrEmpty($ServerCertificateThumbprint))
    {
        $allCerts += $ServerCertificateThumbprint
    }

    if(-not [string]::IsNullOrEmpty($ReverseProxyCertificateThumbprint))
    {
        $allCerts += $ReverseProxyCertificateThumbprint
    }

    $timeoutTime = (Get-Date).AddMinutes(10)

    do{
        $isExpectedPermission = $true
        $allCerts | % {
            $certThumbprint = $_
            $cert = dir Cert:\LocalMachine\My\ | ? {$_.Thumbprint -eq "$certThumbprint"}
            $rsaFile = $cert.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName
            $keyPath = "C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys\"
            $fullPath = Join-Path $keyPath $rsaFile
            $acl = Get-Acl -Path $fullPath -ErrorAction SilentlyContinue
            $permission = ($acl.Access | ? {$_.IdentityReference -eq "NT AUTHORITY\NETWORK SERVICE"}).FileSystemRights
            $isExpectedPermission = $isExpectedPermission -and ($permission -eq "FullControl")
        }

        if(-not $isExpectedPermission)
        {
            Write-Verbose "Waiting for all certificates to be imported and permission granted. Waiting for 60 seconds..."
            sleep -Seconds 60
        }

    }While(-not $isExpectedPermission -and ((Get-Date) -lt $timeoutTime))

    if(-not $isExpectedPermission)
    {
        throw "Timed out while waiting for certificates to be imported on node '$env:COMPUTERNAME'"
    }
}

function Wait-ForAllNodesReadiness
{
    param
    (
        [System.UInt32[]] $InstanceCounts,

        [String] $VMNodeTypePrefix,

        [System.String]
        $ClusterCertificateThumbprint,
        
        [System.String]
        $ServerCertificateThumbprint,

        [System.String]
        $ReverseProxyCertificateThumbprint
    )

    # Wait till all other nodes are ready.
    $allCerts = @()

    if(-not [string]::IsNullOrEmpty($ClusterCertificateThumbprint))
    {
        $allCerts += $ClusterCertificateThumbprint
    }

    if(-not [string]::IsNullOrEmpty($ServerCertificateThumbprint))
    {
        $allCerts += $ServerCertificateThumbprint
    }

    if(-not [string]::IsNullOrEmpty($ReverseProxyCertificateThumbprint))
    {
        $allCerts += $ReverseProxyCertificateThumbprint
    }

    $tagIpFormat =  $SubnetIPFormat.Substring(0,$SubnetIPFormat.IndexOf('[')) + '*'
    try
    {
        Set-Item WSMan:\localhost\Client\TrustedHosts -Value * -Force

        # Waiting time is calculated based the cluster size
        # Waiting time = NodeCounts(from each nodetype) * 5 times * 3 minutes interval 
        $totalNodeCounts = 0
        for($j = 0; $j -lt $InstanceCounts.Count; $j++)
        {
            $totalNodeCounts = $totalNodeCounts + $InstanceCounts[$j]
        }

        $timeoutTime = (Get-Date).AddMinutes($totalNodeCounts*15)

        # Monitoring
        do
        {
            $areAllNodesReady = $true
            for($j = 0; $j -lt $InstanceCounts.Count; $j++)
            {
                $InstanceCount = $InstanceCounts[$j]
                $VMNodeTypeName = "$VMNodeTypePrefix$j"
                
                for($i = 0; $i -lt $InstanceCount; $i++)
                {
                    [String] $base36Index = (convertTo-Base36 -decNum $i)
                    $nodeName = $VMNodeTypeName + $base36Index.PadLeft(6, "0")
                
                    Write-Verbose "Checking node $nodeName ..."
                    try
                    {
                        $nodeIsReady = Invoke-Command -ScriptBlock {
                                                    $isExpectedPermission = $true
                                                    $Using:allCerts | % {
                                                            $certThumbprint = $_
                                                            $cert = dir Cert:\LocalMachine\My\ | ? {$_.Thumbprint -eq "$certThumbprint"}
                                                            $rsaFile = $cert.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName
                                                            $keyPath = "C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys\"
                                                            $fullPath = Join-Path $keyPath $rsaFile
                                                            $acl = Get-Acl -Path $fullPath -ErrorAction SilentlyContinue
                                                            $permission = ($acl.Access | ? {$_.IdentityReference -eq "NT AUTHORITY\NETWORK SERVICE"}).FileSystemRights
                                                            $isExpectedPermission = $isExpectedPermission -and ($permission -eq "FullControl")
                                                    }
                                                    return $isExpectedPermission
                                        } -ComputerName $nodeName -ErrorAction Stop
                        
                        if($nodeIsReady)
                        {
                            Write-Verbose "Node '$nodeName' is ready."
                        }

                        $areAllNodesReady =  $areAllNodesReady -and $nodeIsReady
                    }
                    catch
                    {
                        Write-Verbose "Failed to checking node '$nodeName'. The host maybe is not ready. Continue monitoring..."
                        $nodeIsReady = $false
                    }
                }
            }

            if(-not $areAllNodesReady)
            {
                Write-Verbose "Waiting for all other nodes. Waiting for 3 minutes..."
                sleep -Seconds 180
            }    

        }while($areAllNodesReady -and ((Get-Date) -lt $timeoutTime))

        if(-not $isExpectedPermission)
        {
            throw "Timed out while waiting for other nodes."
        }
    }
    finally
    {
        Set-Item WSMan:\localhost\Client\TrustedHosts -Value "" -Force
    }
}



function New-ServiceFabricNode
{
    param
    (
        # TODO: Remove this temporary logic until the AddNode.ps1 gets updated in ServiceFabric build.
        [System.String]
        $ConfigPath,

        [System.String]
        $setupDir,

        [System.String]
        $ServiceFabricUrl,

        [System.String]
        $NodeName,

        [System.String]
        $VMNodeTypeName,

        [System.String]
        $NodeIpAddress,

        [System.String]
        $ClientConnectionEndpoint,

        [System.String]
        $UpgradeDomain,

        [System.String]
        $FaultDomain,

        [System.String]
        $ServerCertThumbprint,

        [System.String]
        $FindValueThumbprint
    )

    $ErrorActionPreference = "Stop"

    # TODO: Remove this temporary logic until the AddNode.ps1 gets updated in ServiceFabric build.
    
    $AddNodeScriptUrl = $ConfigPath.TrimEnd("ClusterConfig.X509.MultiMachine.json") + "AddNode.ps1"
    Write-Verbose "Get AddNode.ps1 script from '$AddNodeScriptUrl'"
    $request = Invoke-WebRequest $AddNodeScriptUrl -UseBasicParsing

    if(($request.Content.GetType()).Name -eq "Byte[]")
    {
        $scriptContent = [System.Text.ASCIIEncoding]::ASCII.GetString($request.Content)
    }
    else
    {
        $scriptContent = $request.Content
    }
    
    $AddNodeScriptLocalPath = Join-Path -Path $setupDir -ChildPath 'ServiceFabric\AddNode.ps1'
    $scriptContent | Out-File $AddNodeScriptLocalPath -Force
    

    # Adding the Node
    # Refer: https://docs.microsoft.com/en-us/azure/service-fabric/service-fabric-cluster-windows-server-add-remove-nodes
    Write-Verbose "Adding node '$NodeName' to Service fabric Cluster."
    $output = .\ServiceFabric\AddNode.ps1 -NodeName $NodeName `
                                          -NodeType $VMNodeTypeName `
                                          -NodeIPAddressorFQDN $nodeIpAddress `
                                          -ExistingClientConnectionEndpoint $ClientConnectionEndpoint `
                                          -UpgradeDomain $UpgradeDomain `
                                          -FaultDomain $FaultDomain `
                                          -AcceptEULA `
                                          -ServerCertThumbprint $ServerCertThumbprint `
                                          -FindValueThumbprint $FindValueThumbprint `
                                          -StoreLocation "LocalMachine" `
                                          -StoreName "My" `
                                          -X509Credential

    Write-Verbose ($output | Out-String)

    # Validate add
    Write-Verbose "Done with adding new node. Validating cluster to make sure new node exists"
    
    Import-Module $sfModulePath -ErrorAction SilentlyContinue -Verbose:$false
    $connection = Connect-ServiceFabricCluster -X509Credential `
                            -ConnectionEndpoint $ClientConnectionEndpoint `
                            -ServerCertThumbprint $ServerCertThumbprint `
                            -StoreLocation "LocalMachine" `
                            -StoreName "My" `
                            -FindValue $FindValueThumbprint `
                            -FindType FindByThumbprint

    $sfNodes = Get-ServiceFabricNode | % {$_.NodeName}

    if($sfNodes -contains $env:COMPUTERNAME)
    {
        Write-Verbose "Node '$NodeName' succesfully added to the Service Fabric cluster."
    }
    else
    {
        throw "Service fabric node '$NodeName' could not be added. `n Please check the detailed DSC logs and Service fabric deployment traces at: '$setupDir\ServiceFabric\DeploymentTraces' on the VM: '$nodeName'."
    }
}

function Get-ServiceFabricModulePath
{
    param 
    (
        [string] $SetupDir
    )

    <#
    $Identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal = New-Object System.Security.Principal.WindowsPrincipal($Identity)
    $IsAdmin = $Principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

    if(!$IsAdmin)
    {
        throw "Please run the command with administrative privileges."
    }
    #>
    $serviceFabricDir = Join-Path $SetupDir -ChildPath "ServiceFabric"
    $DeployerBinPath = Join-Path $serviceFabricDir -ChildPath "DeploymentComponents"
    if(!(Test-Path $DeployerBinPath))
    {
        $DCAutoExtractorPath = Join-Path $serviceFabricDir "DeploymentComponentsAutoextractor.exe"
        if(!(Test-Path $DCAutoExtractorPath)) 
        {
            throw "Standalone package DeploymentComponents and DeploymentComponentsAutoextractor.exe are not present local to the script location."
        }

        #Extract DeploymentComponents
        $DCExtractArguments = "/E /Y /L `"$serviceFabricDir`""
        $DCExtractOutput = cmd.exe /c "$DCAutoExtractorPath $DCExtractArguments && exit 0 || exit 1"
        if($LASTEXITCODE -eq 1)
        {
            throw "Extracting DeploymentComponents Cab ran into an issue: $DCExtractOutput"
        }
        else
        {
            Write-Verbose "DeploymentComponents extracted."
        }
    }

    $SystemFabricModulePath = Join-Path $DeployerBinPath -ChildPath "System.Fabric.dll"
    if(!(Test-Path $SystemFabricModulePath)) 
    {
        throw "Could not find System.Fabric.dll at path: '$SystemFabricModulePath'."
    }

    $ServiceFabricPowershellModulePath = Join-Path $DeployerBinPath -ChildPath "ServiceFabric.psd1"

    return $ServiceFabricPowershellModulePath
    
}

function Prepare-NodeType
{
    param
    (
        [System.String] 
        $setupDir,

        [System.String] 
        $VMNodeTypePrefix,

        [System.String] 
        $CurrentVMNodeTypeIndex,

        [System.String]
        $ClientConnectionEndpointPort,

        [System.String]
        $HTTPGatewayEndpointPort,

        [System.String]
        $ReverseProxyEndpointPort,

        [System.String]
        $EphemeralStartPort,

        [System.String]
        $EphemeralEndPort,

        [System.String]
        $ApplicationStartPort,

        [System.String]
        $ApplicationEndPort
    )

    Import-Module $sfModulePath -ErrorAction SilentlyContinue -Verbose:$false
    Connect-ServiceFabricCluster -X509Credential `
                                 -ConnectionEndpoint $ClientConnectionEndpoint `
                                 -ServerCertThumbprint $ServerCertificateThumbprint `
                                 -StoreLocation "LocalMachine" `
                                 -StoreName "My" `
                                 -FindValue $ServerCertificateThumbprint `
                                 -FindType FindByThumbprint

    # Check node type existance
    Write-Verbose "Get current cluster configuration ..."

    $clusterConfig = Get-ServiceFabricClusterConfiguration | ConvertFrom-Json
    $nodeTypeNames = $clusterConfig.Properties.NodeTypes | select -Property Name

    Write-Verbose "Current node types: $nodeTypeNames"

    $VMNodeTypeName = "$VMNodeTypePrefix$CurrentVMNodeTypeIndex"
    if(-not ($nodeTypeNames -match $VMNodeTypeName))
    {
        # if current configuration don't have this nodetype, add a new node type
        Write-Verbose "Nodetype $VMNodeTypeName does not exist, updating cluster configuration..."
        Write-Verbose "Generating new config file - Updating node type ..."

        $nodeType = New-Object PSObject
        $nodeType | Add-Member -MemberType NoteProperty -Name "name" -Value "$VMNodeTypeName"
        $nodeType | Add-Member -MemberType NoteProperty -Name "clientConnectionEndpointPort" -Value "$ClientConnectionEndpointPort"
        $nodeType | Add-Member -MemberType NoteProperty -Name "clusterConnectionEndpointPort" -Value "19001"
        $nodeType | Add-Member -MemberType NoteProperty -Name "leaseDriverEndpointPort" -Value "19002"
        $nodeType | Add-Member -MemberType NoteProperty -Name "serviceConnectionEndpointPort" -Value "19003"
        $nodeType | Add-Member -MemberType NoteProperty -Name "httpGatewayEndpointPort" -Value "$HTTPGatewayEndpointPort"
        $nodeType | Add-Member -MemberType NoteProperty -Name "reverseProxyEndpointPort" -Value "$ReverseProxyEndpointPort"

        $applicationPorts = New-Object PSObject
        $applicationPorts | Add-Member -MemberType NoteProperty -Name "startPort" -Value "$ApplicationStartPort"
        $applicationPorts | Add-Member -MemberType NoteProperty -Name "endPort" -Value "$ApplicationEndPort"

        $ephemeralPorts = New-Object PSObject
        $ephemeralPorts | Add-Member -MemberType NoteProperty -Name "startPort" -Value "$EphemeralStartPort"
        $ephemeralPorts | Add-Member -MemberType NoteProperty -Name "endPort" -Value "$EphemeralEndPort"

        $nodeType | Add-Member -MemberType NoteProperty -Name "applicationPorts" -Value $applicationPorts
        $nodeType | Add-Member -MemberType NoteProperty -Name "ephemeralPorts" -Value $ephemeralPorts
        $nodeType | Add-Member -MemberType NoteProperty -Name "isPrimary" -Value $false

        $clusterConfig.properties.nodeTypes = $clusterConfig.properties.nodeTypes + $nodeType

        # For x509 remove windows Identity. (This is a issue in SF, should resolve this after new SF version comes)
        Write-Verbose "Generating new config file - Updating node type: Removing Windows Identity...(This step will be removed when new SF releases)"
        $secObj = New-Object -TypeName PSCustomObject -Property @{'$id' = $clusterConfig.Properties.Security.'$id'; `
                                                                  CertificateInformation=$clusterConfig.Properties.Security.CertificateInformation; `
                                                                  ClusterCredentialType=$clusterConfig.Properties.Security.ClusterCredentialType; `
                                                                  ServerCredentialType=$clusterConfig.Properties.Security.ServerCredentialType}
        $clusterConfig.Properties.Security = $secObj

        # update version 
        $ver=[version]$clusterConfig.ClusterConfigurationVersion
        $newVer = "{0}.{1}.{2}" -f $ver.Major, $ver.Minor, ($ver.Build + 1)
        $clusterConfig.ClusterConfigurationVersion = $newVer
        Write-Verbose "Generating new config file - Updating node type: Updating config version from $ver to $newVer"

        # out put to local file
        $updatedConfigFilePath = Join-Path -Path $setupDir -ChildPath "UpdatedConfig.json"
        $configContent = ConvertTo-Json $clusterConfig -Depth 99
        $configContent | Out-File $updatedConfigFilePath
        Write-Verbose "Generating new config file - Updating node type: Out put latest config file to $updatedConfigFilePath"

        Write-Verbose "Start updating cluster configuration..."
        Start-ServiceFabricClusterConfigurationUpgrade -ClusterConfigPath $updatedConfigFilePath

        Monitor-UpdateServiceFabricConfiguration
    }

    Write-Verbose "Cluster configration is ready for new nodetype."
}

function Monitor-UpdateServiceFabricConfiguration
{
    # Wait 1 minutes to let the cluster start updating.
    Write-Verbose "Job submitted, waiting for 60 seconds before monitoring to let the upgrade task start..."
    Start-Sleep -Seconds 60

    # Monitoring status. Reference: https://docs.microsoft.com/en-us/rest/api/servicefabric/sfclient-model-upgradestate
    Write-Verbose "Start monitoring cluster configration update..."
    while ($true)
    {
        $udStatus = Get-ServiceFabricClusterUpgrade
        Write-Verbose "Current status $udStatus"

        if($udStatus.UpgradeState -eq 'RollingForwardInProgress')
        {
            # Continue if it is RollingForwardInProgress
            Write-Verbose "Waiting for 60 seconds..."
            Start-Sleep -Seconds 60
            continue
        }

        if($udStatus.UpgradeState -eq 'RollingForwardCompleted')
        {
            # Teminate monitoring if update complate.
            Write-Verbose "Cluster configration update completed"
            break
        }

        # Other situations will be considered as failure
        Write-Verbose "Cluster configration update running into unexpected state!"
        throw "Failed in updating Service Fabric cluster configuration."
    }
    Write-Verbose "Update cluster configration finished."
}

function Initial-ServiceFabricClusterConfiguration
{
 param
    (
        [string] $setupDir
    )

    Import-Module $sfModulePath -ErrorAction SilentlyContinue -Verbose:$false

    Connect-ServiceFabricCluster -X509Credential `
                                 -ConnectionEndpoint $ClientConnectionEndpoint `
                                 -ServerCertThumbprint $ServerCertificateThumbprint `
                                 -StoreLocation "LocalMachine" `
                                 -StoreName "My" `
                                 -FindValue $ServerCertificateThumbprint `
                                 -FindType FindByThumbprint

    $clusterConfig = Get-ServiceFabricClusterConfiguration | ConvertFrom-Json

    # For x509 remove windows Identity. (This is a issue in SF, should resolve this after new SF version comes)
    Write-Verbose "Generating new config file - Updating node type: Removing Windows Identity...(This step will be removed when new SF releases)"
    $secObj = New-Object -TypeName PSCustomObject -Property @{'$id' = $clusterConfig.Properties.Security.'$id'; `
                                                              CertificateInformation=$clusterConfig.Properties.Security.CertificateInformation; `
                                                              ClusterCredentialType=$clusterConfig.Properties.Security.ClusterCredentialType; `
                                                              ServerCredentialType=$clusterConfig.Properties.Security.ServerCredentialType}
    $clusterConfig.Properties.Security = $secObj

    # update version
    $ver=[version]$clusterConfig.ClusterConfigurationVersion
    $newVer = "{0}.{1}.{2}" -f $ver.Major, $ver.Minor, ($ver.Build + 1)
    $clusterConfig.ClusterConfigurationVersion = $newVer
    Write-Verbose "Generating new config file - Updating node type: Updating config version from $ver to $newVer"

    $iniedConfigFilePath = Join-Path -Path $setupDir -ChildPath "IniedConfig.json"
    $configContent = ConvertTo-Json $clusterConfig -Depth 99
    $configContent | Out-File $iniedConfigFilePath

    Write-Verbose "Start updating cluster configuration..."
    Start-ServiceFabricClusterConfigurationUpgrade -ClusterConfigPath $iniedConfigFilePath

    Monitor-UpdateServiceFabricConfiguration
}
