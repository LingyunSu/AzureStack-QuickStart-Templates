function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [parameter(Mandatory = $true)]
        [System.UInt32]
        $DeploymentNodeIndex,

        [parameter(Mandatory = $true)]
        [System.UInt32]
        $InstanceCount,

        [parameter(Mandatory = $true)]
        [System.String]
        $ClusterName,

        [parameter(Mandatory = $true)]
        [System.String]
        $VMNodeTypeName,

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

        [parameter(Mandatory = $true)]
        [System.String]
        $CertificateThumbprint
    )
}

function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory = $true)]
        [System.UInt32]
        $DeploymentNodeIndex,

        [parameter(Mandatory = $true)]
        [System.UInt32]
        $InstanceCount,

        [parameter(Mandatory = $true)]
        [System.String]
        $ClusterName,

        [parameter(Mandatory = $true)]
        [System.String]
        $VMNodeTypeName,

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

        [parameter(Mandatory = $true)]
        [System.String]
        $CertificateThumbprint,

        [parameter(Mandatory = $false)]
        [System.String]
        $ReverseProxyCertificateThumbprint,

        [parameter(Mandatory = $false)]
        [System.String]
        $DNSService = "No",

        [parameter(Mandatory = $false)]
        [System.String]
        $RepairManager = "No",

        [parameter(Mandatory = $false)]
        [System.String[]]
        $AdminClientCertificateThumbprint = @(),

        [parameter(Mandatory = $false)]
        [System.String[]]
        $NonAdminClientCertificateThumbprint = @()
    )

    $ErrorActionPreference = "Stop"

    # Enable File and Printer Sharing and Network Discovery (Port 445)
    Enable-NetworkDiscovery

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
    
    # For scale-up scenario as there is no sequencing of extensions provided by VMSS, 
    # execution need to wait till Wait till the Script based extension completes imporing of neccessary certificates and granting required permissions.
    # For first time deployment this will just pass through as the certs are already there and access have already been granted.
    # Refer: https://msftstack.wordpress.com/2016/05/12/extension-sequencing-in-azure-vm-scale-sets/
    
    Wait-ForCertInstall -CertificateThumbprint $CertificateThumbprint -ReverseProxyCertificateThumbprint $ReverseProxyCertificateThumbprint

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
                                            -ServerCertThumbprint $Using:CertificateThumbprint `
                                            -StoreLocation "LocalMachine" `
                                            -StoreName "My" `
                                            -FindValue $Using:CertificateThumbprint `
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
            # Collect Node details
            $nodeName = $env:COMPUTERNAME
            $nodeIpAddressLable = (Get-NetIPAddress).IPv4Address | ? {$_ -ne "" -and $_ -ne "127.0.0.1"}
            $nodeIpAddress = [IPAddress](([String]$nodeIpAddressLable).Trim(' '))
            Write-Verbose "Node IPAddress: '$nodeIpAddress'"

            $fdIndex = $scaleSetDecimalIndex + 1
            $faultDomain = "fd:/dc$fdIndex/r0"

            $upgradeDomain = "UD$scaleSetDecimalIndex"

            New-ServiceFabricNode -setupDir $setupDir `
                                 -ServiceFabricUrl $ServiceFabricUrl `
                                -NodeName $nodeName `
                                -VMNodeTypeName $VMNodeTypeName `
                                -NodeIpAddress $nodeIpAddress `
                                -UpgradeDomain $upgradeDomain `
                                -FaultDomain $faultDomain `
                                -ClientConnectionEndpoint $ClientConnectionEndpoint `
                                -ConfigPath $ConfigPath `
                                -ServerCertThumbprint $CertificateThumbprint `
                                -FindValueThumbprint $CertificateThumbprint

            return
    }

    # If no cluster exists, First time deployment in progress.

    # Check if current Node is master node.
    $isMasterNode = $scaleSetDecimalIndex -eq $DeploymentNodeIndex

    # Return in case the current node is not the deployment node, else continue with SF deployment on deployment node.
    if(-not $isMasterNode)
    {
        Write-Verbose "Service Fabric deployment runs on Node with index: '$DeploymentNodeIndex'."
        return
    }

    Write-Verbose "Starting service fabric deployment on Node: '$env:COMPUTERNAME'."


    # Get Service fabric configuration file locally for update.
    Write-Verbose "Get Service fabric configuration from '$ConfigPath'"
    $request = Invoke-WebRequest $ConfigPath -UseBasicParsing
    $configContent = ConvertFrom-Json  $request.Content
    $ConfigFilePath = Join-Path -Path $setupDir -ChildPath 'ClusterConfig.json'
    Write-Verbose "Creating service fabric config file at: '$ConfigFilePath'"
    $configContent = ConvertTo-Json $configContent -Depth 99
    $configContent | Out-File $ConfigFilePath

    # Add Nodes configuration.
    Add-ServiceFabricNodeConfiguration -ConfigFilePath $ConfigFilePath -ClusterName $ClusterName -InstanceCount $InstanceCount -VMNodeTypeName $VMNodeTypeName

    # Add NodeType configuration.
    Add-ServiceFabricNodeTypeConfiguration -ConfigFilePath $ConfigFilePath `
                                            -VMNodeTypeName $VMNodeTypeName `
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
                                            -CertificateThumbprint $CertificateThumbprint `
                                            -ReverseProxyCertificateStoreValue $CertificateStoreValue `
                                            -ReverseProxyCertificateThumbprint $ReverseProxyCertificateThumbprint `
                                            -AdminClientCertificateThumbprint $AdminClientCertificateThumbprint `
                                            -NonAdminClientCertificateThumbprint $NonAdminClientCertificateThumbprint

    # Add Optional Features (if Any)
    Add-OptionalFeaturesConfiguration -ConfigFilePath $ConfigFilePath -DNSService $DNSService -RepairManager $RepairManager

    # Validate and Deploy Service Fabric Configuration
    New-ServiceFabricDeployment -setupDir $setupDir -ConfigFilePath $ConfigFilePath -ServiceFabricUrl $ServiceFabricUrl

    # Validations
    Write-Verbose "Validating Service Fabric deployment."

    Test-ServiceFabricDeployment -setupDir $setupDir
}

function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [parameter(Mandatory = $true)]
        [System.UInt32]
        $DeploymentNodeIndex,

        [parameter(Mandatory = $true)]
        [System.UInt32]
        $InstanceCount,

        [parameter(Mandatory = $true)]
        [System.String]
        $ClusterName,

        [parameter(Mandatory = $true)]
        [System.String]
        $VMNodeTypeName,

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

        [parameter(Mandatory = $true)]
        [System.String]
        $CertificateThumbprint,

        [System.String]
        $ReverseProxyCertificateThumbprint,

        [System.String]
        $DNSService,

        [System.String]
        $RepairManager,

        [System.String[]]
        $AdminClientCertificateThumbprint,

        [System.String[]]
        $NonAdminClientCertificateThumbprint
    )

    return $false
}

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

function Enable-NetworkDiscovery
{
    param()
    
    $ErrorActionPreference = "Stop"

    Write-Verbose "Opening TCP firewall port 445 for networking."
    Set-NetFirewallRule -Name 'FPS-SMB-In-TCP' -Enabled True
    Get-NetFirewallRule -DisplayGroup 'Network Discovery' | Set-NetFirewallRule -Profile 'Private, Public' -Enabled true
}

function Add-ServiceFabricNodeConfiguration
{
    param
    (
        [String] $ConfigFilePath,

        [String] $ClusterName,

        [System.UInt32] $InstanceCount,

        [String] $VMNodeTypeName
    )

    $ErrorActionPreference = "Stop"

    [String] $content = Get-Content -Path $ConfigFilePath
    $configContent = ConvertFrom-Json  $content

    $configContent.name = "$ClusterName"

    # Getting the IP address of the first node with index 0 to start counting Node IPs from this address.
    $startNodeIpAddressLable = (Get-NetIPAddress).IPv4Address | ? {$_ -ne "" -and $_ -ne "127.0.0.1"}
    $startNodeIpAddress = [IPAddress](([String]$startNodeIpAddressLable).Trim(' '))

    Write-Verbose "Start node IPAddress: '$startNodeIpAddress'"

    # Adding Nodes to the configuration.
    $i = 0
    $sfnodes = @()

    try
    {
        Set-Item WSMan:\localhost\Client\TrustedHosts -Value * -Force

        while($i -lt $InstanceCount)
        {
            $IpStartBytes = $startNodeIpAddress.GetAddressBytes()
            $IpStartBytes[3] = $IpStartBytes[3] + $i
            $ip = [IPAddress]($IpStartBytes)
            $nodeName = Invoke-Command -ScriptBlock {hostname} -ComputerName "$($ip.IPAddressToString)"

            # Get the decimal based index of the VM machine name (VM Scale set name the machines in the format {Prefix}{Suffix}
            # where Suffix is a 6 digit base36 number starting from 000000 to zzzzzz.
            # Getting the decimal equivalent of the index to use it in the FD and UD name.
            $nodeScaleSetDecimalIndex = ConvertFrom-Base36 -base36Num ($nodeName.ToString().Substring(($VMNodeTypeName).Length))

            $fdIndex = $nodeScaleSetDecimalIndex + 1

            $node = New-Object PSObject
            $node | Add-Member -MemberType NoteProperty -Name "nodeName" -Value $($nodeName).ToString()
            $node | Add-Member -MemberType NoteProperty -Name "iPAddress" -Value $ip.IPAddressToString
            $node | Add-Member -MemberType NoteProperty -Name "nodeTypeRef" -Value "$VMNodeTypeName"
            $node | Add-Member -MemberType NoteProperty -Name "faultDomain" -Value "fd:/dc$fdIndex/r0"
            $node | Add-Member -MemberType NoteProperty -Name "upgradeDomain" -Value "UD$nodeScaleSetDecimalIndex"

            Write-Verbose "Adding Node to configuration: '$nodeName'"
            $sfnodes += $node
            $i++
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
        $VMNodeTypeName,

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

    $nodeType | Add-Member -MemberType NoteProperty -Name "isPrimary" -Value $true

    Write-Verbose "Adding Node Type to configuration."
    $nodeTypes += $nodeType
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
        $CertificateThumbprint,

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
    $configContent.properties.security.CertificateInformation.ClusterCertificate.Thumbprint = $certificateThumbprint
    $configContent.properties.security.CertificateInformation.ClusterCertificate.X509StoreName = $certificateStoreValue

    $configContent.properties.security.CertificateInformation.ServerCertificate.Thumbprint = $certificateThumbprint
    $configContent.properties.security.CertificateInformation.ServerCertificate.X509StoreName = $certificateStoreValue

    if(-not [string]::IsNullOrEmpty($reverseProxyCertificateThumbprint))
    {
        $configContent.properties.security.CertificateInformation.ReverseProxyCertificate.Thumbprint = $reverseProxyCertificateThumbprint
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
        $ServiceFabricUrl
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

    Write-Verbose "Starting Service Fabric runtime deployment"
    $output = .\ServiceFabric\CreateServiceFabricCluster.ps1 -ClusterConfigFilePath $ConfigFilePath -AcceptEULA -Verbose
    Write-Verbose ($output | Out-String)
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

function Wait-ForCertInstall
{
    param
    (
        [System.String]
        $CertificateThumbprint,

        [System.String]
        $ReverseProxyCertificateThumbprint
    )

    $allCerts = @()

    if(-not [string]::IsNullOrEmpty($CertificateThumbprint))
    {
        $allCerts += $CertificateThumbprint
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
    Connect-ServiceFabricCluster
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

Export-ModuleMember -Function *-TargetResource

