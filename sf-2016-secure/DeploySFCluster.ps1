Configuration InstallServiceFabricConfiguration
{
    param
    (
    [Parameter(Mandatory = $false)]
    [Int] $DeploymentNodeIndex = 0,

    [Parameter(Mandatory = $true)]
    [int] $InstanceCount,

    [Parameter(Mandatory = $true)]
    [string] $ClusterName,

    [Parameter(Mandatory = $true)]
    [string] $vmNodeTypeName,

    [Parameter(Mandatory = $true)]
    [string] $clientConnectionEndpointPort,

    [Parameter(Mandatory = $true)]
    [string] $httpGatewayEndpointPort,

    [Parameter(Mandatory = $true)]
    [string] $reverseProxyEndpointPort,

    [Parameter(Mandatory = $true)]
    [string] $ephemeralStartPort,

    [Parameter(Mandatory = $true)]
    [string] $ephemeralEndPort,

    [Parameter(Mandatory = $true)]
    [string] $applicationStartPort,

    [Parameter(Mandatory = $true)]
    [string] $applicationEndPort,

    [Parameter(Mandatory = $true)]
    [string] $ConfigPath,

    [Parameter(Mandatory = $false)]
    [string] $serviceFabricUrl = "http://go.microsoft.com/fwlink/?LinkId=730690",

    [Parameter(Mandatory = $true)]
    [PSCredential] $Credential,

    [Parameter(Mandatory = $true)]
    [string] $DiagStoreAccountName,

    [Parameter(Mandatory = $true)]
    [string] $DiagStoreAccountKey,

    [Parameter(Mandatory = $true)]
    [string] $DiagStoreAccountBlobUri,

    [Parameter(Mandatory = $true)]
    [string] $DiagStoreAccountTableUri,

    [Parameter(Mandatory = $true)]
    [string] $certificateStoreValue,

    [Parameter(Mandatory = $true)]
    [string] $certificateThumbprint,

    [Parameter(Mandatory = $false)]
    [string] $reverseProxyCertificateThumbprint = "",

    [Parameter(Mandatory = $false)]
    [string] $DNSService = "No",

    [Parameter(Mandatory = $false)]
    [string] $RepairManager = "No",

    [Parameter(Mandatory = $false)]
    [string[]] $adminClientCertificateThumbprint = @(),

    [Parameter(Mandatory = $false)]
    [string[]] $nonAdminClientCertificateThumbprint = @(),

    [Parameter(Mandatory = $true)]
    [string] $ClientConnectionEndpoint
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration, xServiceFabricSecureCluster

    Node localhost {

        xServiceFabricSecureClusterDeployment DeployServiceFabricSecureConfiguration
        {
            DeploymentNodeIndex = $DeploymentNodeIndex
            InstanceCount = $InstanceCount
            ClusterName = $ClusterName
            VMNodeTypeName = $vmNodeTypeName
            ClientConnectionEndpointPort = $clientConnectionEndpointPort
            HTTPGatewayEndpointPort = $httpGatewayEndpointPort
            ReverseProxyEndpointPort = $reverseProxyEndpointPort
            EphemeralStartPort = $ephemeralStartPort
            EphemeralEndPort = $ephemeralEndPort
            ApplicationStartPort = $applicationStartPort
            ApplicationEndPort = $applicationEndPort
            ConfigPath = $ConfigPath
            ServiceFabricUrl = $serviceFabricUrl
            DiagStoreAccountName = $DiagStoreAccountName
            DiagStoreAccountKey = $DiagStoreAccountKey
            DiagStoreAccountBlobUri = $DiagStoreAccountBlobUri
            DiagStoreAccountTableUri = $DiagStoreAccountTableUri
            CertificateStoreValue = $certificateStoreValue
            CertificateThumbprint = $certificateThumbprint
            ReverseProxyCertificateThumbprint = $reverseProxyCertificateThumbprint
            AdminClientCertificateThumbprint = $adminClientCertificateThumbprint
            NonAdminClientCertificateThumbprint = $nonAdminClientCertificateThumbprint
            ClientConnectionEndpoint = $ClientConnectionEndpoint
            PsDscRunAsCredential = $Credential
            DNSService = $DNSService
            RepairManager = $RepairManager
        }

        LocalConfigurationManager 
        {
            ConfigurationMode = 'ApplyOnly'
        }
    }
}