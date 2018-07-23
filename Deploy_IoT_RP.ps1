<#
 .SYNOPSIS
    Deploys IOT RP on Azurestack

 .DESCRIPTION
    Deploys IOT RP on Azurestack

 .PARAMETER parametersFilePath
    The input parameters.json file path

#>
param(
 [Parameter(Mandatory=$false)]
 [string]
 $parametersFilePath="./parameters.json")
 function New-SslCert([string]$cn, [string]$keyVaultName, [string]$outputFolder, [string]$certificateName, [bool]$jsonFormatForVM )
 {
 
     #New-Item -Path $tempFolder -ItemType Directory -Force | Out-Null
     $keyVaultSecretName = $certificateName
 
     if(!(Test-Path $outputFolder))
     {
         New-Item -Path $outputFolder -ItemType Directory -Force | Out-Null
     }
 
     $cerFile = Join-Path -Path $outputFolder -ChildPath "${keyVaultSecretName}.cer"
     
     #Get the intermediate certificate CA
     #TODO: parameterize cn?
     $root = Get-ChildItem Cert:\LocalMachine\CA | Where-Object Subject -eq "cn=AzureStackSelfSignedRootCert"
 
     #create the self signed certificate
     $certificateObject = New-SelfSignedCertificate -KeyAlgorithm RSA -KeyLength 4096 -CertStoreLocation Cert:\LocalMachine\My -DnsName $cn -Signer $root -Provider "Microsoft Strong Cryptographic Provider" -HashAlgorithm "SHA256"
 
     $certBypes = $certificateObject.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12)

     
     Write-Host *************$keyVaultSecretName Details: $certificateObject
 
     # Export the cer certificate
     Export-Certificate -Cert $certificateObject -FilePath $cerFile
 
     $pfxAsBase64EncodedString = [System.Convert]::ToBase64String($certBypes)
  
      if ($jsonFormatForVM)
      {
         Write-Host "***JSON formatted cert***"
         $jsonObject = ConvertTo-Json -Depth 10 ([pscustomobject]@{
                   data     = $pfxAsBase64EncodedString
                   dataType = 'pfx'
                   password = ''
               })
  
         $jsonObjectBytes = [System.Text.Encoding]::UTF8.GetBytes($jsonObject)
         $jsonEncoded = [System.Convert]::ToBase64String($jsonObjectBytes)
         $secret = ConvertTo-SecureString -String $jsonEncoded -AsPlainText -Force
     }
     else
     {
         Write-Host "***non-JSON formatted cert***"
         $secret = ConvertTo-SecureString -String $pfxAsBase64EncodedString -AsPlainText -Force
     }
 
         # Upload cert to KeyVault in your Azure Stack admin Subscription.
         Write-Host "--------->Uploading cert: KeyVaultName: $keyVaultName SecretName: $keyVaultSecretName"
        
         AzureRM.KeyVault\Set-AzureKeyVaultSecret -VaultName $keyVaultName -Name $keyVaultSecretName -SecretValue $secret
         $thumbprintSecretName = $keyVaultSecretName + "-thumbprint" 
         $thumbprintSecured = ConvertTo-SecureString $certificateObject.Thumbprint -AsPlainText -Force
         AzureRM.KeyVault\Set-AzureKeyVaultSecret -VaultName $keyVaultName -Name $thumbprintSecretName -SecretValue $thumbprintSecured
 }
 
 function printToConsole([string] $output) {
     Write-Host ****************************************************************
     Write-Host ****************************************************************
     Write-Host ***************************************************************
     Write-Host $output
     Write-Host ****************************************************************
     Write-Host ****************************************************************
     Write-Host ****************************************************************
 }

$parameters = Get-Content -Raw -Path $parametersFilePath | ConvertFrom-Json
$currentDirectory = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent
$keyVaultDnsSuffix = "adminvault."+$parameters.ExternalDomainFQDN
Add-AzureRMEnvironment -Name $parameters.EnvironmentName -ArmEndpoint $parameters.ARMEndpointURI -AzureKeyVaultDnsSuffix $keyVaultDnsSuffix

$rminfo = Login-AzureRmAccount -Environment $parameters.EnvironmentName -TenantId $parameters.AADTenantID

Select-AzureRmSubscription -SubscriptionName $parameters.SubscriptionName
$env = Set-AzureRmEnvironment -Name $parameters.EnvironmentName 
printToConsole -output "1. Logged in successfully"

if(-not ($resourceGroup = get-AzureRmResourceGroup -Name $parameters.SecretsResourceGroup -ErrorAction SilentlyContinue)) {
    $resourceGroup = New-AzureRmResourceGroup -Name $parameters.SecretsResourceGroup -Location $parameters.Location 
}

printToConsole -output "2. Secrets Resource Group created successfully"

if(-not ($kv = Get-AzureRmKeyVault -VaultName $parameters.KeyvaultName -ResourceGroupName $parameters.SecretsResourceGroup -ErrorAction SilentlyContinue)) {
    $kv = New-AzureRmKeyVault -VaultName $parameters.KeyvaultName -ResourceGroupName $parameters.SecretsResourceGroup -Location $parameters.Location -EnabledForDeployment -EnabledForTemplateDeployment -EnabledForDiskEncryption
}

printToConsole -output "3. Secrets Keyvault created successfully"



New-SslCert -cn $('ssl-rp.mgmtiothub.'+ $parameters.ExternalDomainFQDN) -certificateName "ih-ssl-rp-pfx" -outputFolder $currentDirectory -keyVaultName $parameters.KeyvaultName -jsonFormatForVM $true
New-SslCert -cn $('fabric.mgmtiothub.'+ $parameters.ExternalDomainFQDN) -certificateName "ih-fabric-pfx" -outputFolder $currentDirectory -keyVaultName $parameters.KeyvaultName -jsonFormatForVM $true
New-SslCert -cn $('*.mgmtiothub.'+ $parameters.ExternalDomainFQDN) -certificateName "ih-ssl-pfx" -outputFolder $currentDirectory -keyVaultName $parameters.KeyvaultName -jsonFormatForVM $true


$armCertPath = $currentDirectory + "\ih-fabric-pfx.cer"
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate  
$cert.Import($armCertPath)
$binCert = $cert.GetRawCertData()  
$credValue = [System.Convert]::ToBase64String($binCert);  
printToConsole -output "4. New Secrets created successfully and pushed to keyvault"

 
$applicationDisplayName = 'iothubapp2'
$homePage = 'https://iothubapp2'
$identifierUris = 'https://iothubapp2'
$azureAdApplicationDeployment = Get-AzureRmADApplication -IdentifierUri $identifierUris
if($azureAdApplicationDeployment -eq $null)
{
    $azureAdApplicationDeployment = New-AzureRmADApplication -DisplayName $applicationDisplayName -HomePage $homePage -IdentifierUris $identifierUris -CertValue $credValue -EndDate $cert.GetExpirationDateString()
    Start-Sleep -Seconds 30
    $servicePrincipal = New-AzureRmADServicePrincipal -ApplicationId $azureAdApplicationDeployment.ApplicationId
    Start-Sleep -Seconds 30
    New-AzureRmRoleAssignment -RoleDefinitionName Contributor -ServicePrincipalName $azureAdApplicationDeployment.ApplicationId
    Start-Sleep -Seconds 30
}
New-AzureRmADAppCredential -ApplicationId $azureAdApplicationDeployment.ApplicationId -CertValue $credValue -EndDate $cert.GetExpirationDateString()

printToConsole -output "5. Service principal created and role assigned with cert access"


$sourceVaultValue = $kv.ResourceId
$fabricCert = AzureRM.KeyVault\Get-AzureKeyVaultSecret -VaultName $parameters.KeyvaultName -Name "ih-fabric-pfx"

$clusterCertificateUrlValue = $fabricCert.Id
$fabricCertThumbprint = AzureRM.KeyVault\Get-AzureKeyVaultSecret -VaultName $parameters.KeyvaultName -Name "ih-fabric-pfx-thumbprint"
$certificateThumbprint = $fabricCertThumbprint.SecretValueText
$adminClientCertificateThumbprints = $certificateThumbprint


Get-AzureRmResourceGroup -Name $parameters.SFClusterResourceGroup | Remove-AzureRmResourceGroup -Verbose -Force
printToConsole -output "6. Cleaning Up Existing Clusters"

$resourceGroupName = $parameters.SFClusterResourceGroup
$resourceGroupDeploymentName = "$($resourceGroupName)Deployment"
 
# Create a resource group:
New-AzureRmResourceGroup -Name $parameters.SFClusterResourceGroup -Location $parameters.Location

# Read Parameters.json
$TemplateParameters = Get-Content -Raw -Path $currentDirectory\Template.Parameters.json | ConvertFrom-Json
# Modify Parameters

$TemplateParameters.parameters.sourceVaultValue.value = $kv.ResourceId
$TemplateParameters.parameters.clusterCertificateUrlValue.value = $fabricCert.Id
$TemplateParameters.parameters.certificateThumbprint.value = $fabricCertThumbprint.SecretValueText
$TemplateParameters.parameters.adminClientCertificateThumbprints.value = $certificateThumbprint


# Save as new Parameters.json

$TemplateParameters | ConvertTo-Json -depth 100 | Out-File $currentDirectory\ModTemplate.Parameters.json
printToConsole -output "7. Existing Template Modified with new secrets"

New-AzureRmResourceGroupDeployment  -Name $resourceGroupDeploymentName -ResourceGroupName $resourceGroupName -TemplateFile $currentDirectory\SFTemplate.json -TemplateParameterFile $currentDirectory\ModTemplate.Parameters.json -Verbose
printToConsole -output "8. Deployed New Cluster"