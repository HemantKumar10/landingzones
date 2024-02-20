<#
    PowerShell script to bootstrap/configure Power Platform from the North Star Reference Implementation. (aka.ms/ppnorthstar)
    Note: The script is designed and optimized to run as a deploymentScript invoked from Azure Resource Manager.
    Refer to https://github.com/microsoft/industry/blob/main/foundations/powerPlatform/referenceImplementation/auxiliary/powerPlatform/ppDeploymentScript.json for details around the input parameters.
#>
[CmdletBinding()]
param (
    #Security, govarnance and compliance
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPGuestMakerSetting,
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPAppSharingSetting,
    #Admin environment and settings
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPEnvCreationSetting,
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPTrialEnvCreationSetting,
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPEnvCapacitySetting,
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPTenantIsolationSetting,
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPTenantDLP,   
    #Landing Zones
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPDefaultRenameText,
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPDefaultDLP,
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPDefaultManagedEnv,
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPDefaultManagedSharing,
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPCitizen,    
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPCitizenNaming,
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPCitizenRegion,
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPCitizenDlp,    
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPCitizenManagedEnv,
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPCitizenAlm,    
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPCitizenCurrency,
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPCitizenLanguage,     
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$ppD365SalesApp,
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$ppD365CustomerServiceApp,
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$ppD365FieldServiceApp        
)

$DeploymentScriptOutputs = @{}
#Install required modules
Install-Module -Name PowerOps -AllowPrerelease -Force

#region Entra Groups
# TO DO - Install module to create Entra Security and M365 Groups.
# TO DO - get the IDs for the created security groups, and set them to the parameters below. 

# Install-module Microsoft.Graph  
# Connect-MgGraph -Scopes "Group.ReadWrite.All"

# Define the details for the Security Groups and the Makers Microsoft 365 Group
#    $devSecurityGroup = @{
#     description="Security Group used for Power Platform - Development environment"
#     displayName="entra_powerplatform_development"
#     mailEnabled=$false
#     securityEnabled=$true
#     mailNickname="PowerPlatformDevelopmentGroup"
#    }

#    $testSecurityGroup = @{
#     description="Security Group used for Power Platform - Test environment"
#     displayName="entra_powerplatform_test"
#     mailEnabled=$false
#     securityEnabled=$true
#     mailNickname="PowerPlatformTestGroup"
#    }

#    $productionSecurityGroup = @{
#     description="Security Group used for Power Platform - Production environment"
#     displayName="entra_powerplatform_production"
#     mailEnabled=$false
#     securityEnabled=$true
#     mailNickname="PowerPlatformProductionGroup"
#    }

#    $adminSecurityGroup = @{
#     description="Security Group used for Power Platform - Admin environment"
#     displayName="entra_powerplatform_admin"
#     mailEnabled=$false
#     securityEnabled=$true
#     mailNickname="PowerPlatformAdminGroup"
#    }

#    $makersM365Group = @{
#     description="Microsoft 365 Group used for Power Platform Makers"
#     displayName="entra_powerplatform_makers"
#     GroupTypes="Unified"
#     mailEnabled=$true
#     securityEnabled=$true
#     mailNickname="Makers"
#    }

#    $usersM365Group = @{
#     description="Microsoft 365 Group used for Power Platform Users"
#     displayName="entra_powerplatform_users"
#     GroupTypes="Unified"
#     mailEnabled=$true
#     securityEnabled=$true
#     mailNickname="Users"
#    }

#    $adminsM365Group = @{
#     description="Microsoft 365 Group used for Power Platform Admins"
#     displayName="entra_powerplatform_admins"
#     GroupTypes="Unified"
#     mailEnabled=$true
#     securityEnabled=$true
#     mailNickname="Admins"
#    }
   
   # Create the Security Groups for Dev/Test/Prod/Admin and the Makers M365 Group
#    New-MgGroup @devSecurityGroup
#    New-MgGroup @testSecurityGroup
#    New-MgGroup @productionSecurityGroup
#    New-MgGroup @adminSecurityGroup
#    New-MgGroup @makersM365Group
#    New-MgGroup @usersM365Group
#    New-MgGroup @adminsM365Group
   
#Get the created groups IDs
$devSecurityGroupId = '2f178b09-3e99-4f68-b3dc-177daa6d662f'
$testSecurityGroupId = 'eae9814e-26cf-43f5-a7be-f08c5b5b0a50'
$prodSecurityGroupId = ''
$adminSecurityGroupId = ''

#endregion Entra Groups

#region Dynamics 365 Applications
# TO DO - Install PowerApp.Administation module and pass the managed identity ID 
# TO DO - modify the sample below to create the 4 environments, including (or not) the templates for D365 Apps. 

# Install-Module -Name Microsoft.PowerApps.Administration.PowerShell -Identity -ClientId "5d09226d-8c9e-41b4-893e-231e0f7d285a" 
# Import-Module -Name Microsoft.PowerApps.Administration.PowerShell
# New-AdminPowerAppEnvironment -DisplayName 'BC-ANS-RND-PS' -Location unitedkingdom -RegionName uksouth -CurrencyName GBP -EnvironmentSku Sandbox -Templates "D365_Sales" -WaitUntilFinished $true -DomainName BCANSRNDPS -LanguageName 1033 -ProvisionDatabase

#endregion Dynamics 365 Applications


#Default ALM environment tiers
$envTiers = 'dev', 'test', 'prod', 'admin'

$Global:envAdminName = ''
#region supporting functions
function New-EnvironmentCreationObject {
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'ARMInputString')]$ARMInputString,
        [Parameter(Mandatory = $true, ParameterSetName = 'EnvCount')][int]$EnvCount,
        [Parameter(Mandatory = $true, ParameterSetName = 'EnvCount')]$EnvNaming,
        [Parameter(Mandatory = $true, ParameterSetName = 'EnvCount')]$EnvRegion,
        [Parameter(Mandatory = $true, ParameterSetName = 'EnvCount')]$EnvLanguage,
        [Parameter(Mandatory = $true, ParameterSetName = 'EnvCount')]$EnvCurrency,
        [Parameter(Mandatory = $true, ParameterSetName = 'EnvCount')]$EnvDescription,
        [Parameter(Mandatory = $false)][switch]$EnvALM,
        [Parameter(Mandatory = $false, ParameterSetName = 'EnvCount')][switch]$EnvDataverse
    )
    if (-not [string]::IsNullOrEmpty($ARMInputString)) {      
        foreach ($env in ($ARMInputString -split 'ppEnvName:')) {
            if ($env -match ".") {
                $environment = $env.TrimEnd(',')
                if ($EnvALM) {
                    foreach ($envTier in $envTiers) {
                        [PSCustomObject]@{
                            envRegion      = ($environment -split (','))[2].Split(':')[1]
                            envLanguage    = ($environment -split (','))[3].Split(':')[1]
                            envCurrency    = ($environment -split (','))[4].Split(':')[1]
                            envDescription = ($environment -split (','))[1].Split(':')[1]
                            envRbac        = ($environment -split (','))[5].Split(':')[1]
                            envName        = '{0}-{1}' -f ($environment -split (','))[0], $envTier
                        }
                    }
                }
                else {
                    [PSCustomObject]@{
                        envName        = ($environment -split (','))[0]
                        envRegion      = ($environment -split (','))[2].Split(':')[1]
                        envLanguage    = ($environment -split (','))[3].Split(':')[1]
                        envCurrency    = ($environment -split (','))[4].Split(':')[1]
                        envDescription = ($environment -split (','))[1].Split(':')[1]
                        envRbac        = ($environment -split (','))[5].Split(':')[1]
                    }
                }
            }
        }
    }
    else {         
        1..$EnvCount | ForEach-Object -Process {
            $environmentName = $EnvNaming
            $securityGroupId = ''      
            $envSku = 'Sandbox'     
            if ($true -eq $EnvALM) {
                foreach ($envTier in $envTiers) { 
                    if($envTier -eq 'dev'){
                        <# $sgId = New-CreateSecurityGroup -EnvironmentType dev
                        $securityGroupId = $sgId #>
                        $envSku = 'Sandbox'  
                    }
                    if ( $envTier -eq 'test' ){
                        <# $sgId = New-CreateSecurityGroup -EnvironmentType test
                        $securityGroupId = $sgId #>
                        $envSku = 'Sandbox'  
                    }
                    if ( $envTier -eq 'prod' ){
                        <# $sgId = New-CreateSecurityGroup -EnvironmentType prod
                        $securityGroupId = $sgId #>
                        $envSku ='Production'                     
                    }
                    if ( $envTier -eq 'admin' ){
                        <#$sgId = New-CreateSecurityGroup -EnvironmentType admin
                        $securityGroupId = $sgId #>
                        $Global:envAdminName =  "{0}-{1}" -f $environmentName, $envTier                   
                        $envSku ='Production'
                    }

                    [PSCustomObject]@{
                        envName        = "{0}-{1}" -f $environmentName, $envTier
                        envRegion      = $EnvRegion
                        envDataverse   = $EnvDataverse
                        envLanguage    = $envLanguage
                        envCurrency    = $envCurrency
                        envDescription = $envDescription
                        envRbac        = $securityGroupId
                        envSku         = $envSku
                    }
                }
            }
            else {
              
                [PSCustomObject]@{
                    envName        = $environmentName
                    envRegion      = $EnvRegion
                    envDataverse   = $EnvDataverse
                    envLanguage    = $envLanguage
                    envCurrency    = $envCurrency
                    envDescription = $envDescription
                    envRbac        = ''
                    envSku         = $envSku
                }
            }
        }
    }
}


function New-CreateSecurityGroup {
    param (      
        [Parameter(Mandatory = $true)][string]$EnvironmentType
    )
    
        $devSecurityGroup = @{
            description="Security Group used for Power Platform - Development environment"
            displayName="entra_powerplatform_development"
            mailEnabled=$false
            securityEnabled=$true
            mailNickname="PowerPlatformDevelopmentGroup"
           }
        
          $testSecurityGroup = @{
            description="Security Group used for Power Platform - Test environment"
             displayName="entra_powerplatform_test"
            mailEnabled=$false
             securityEnabled=$true
             mailNickname="PowerPlatformTestGroup"
            }
        
            $productionSecurityGroup = @{
            description="Security Group used for Power Platform - Production environment"
             displayName="entra_powerplatform_production"
             mailEnabled=$false
             securityEnabled=$true
             mailNickname="PowerPlatformProductionGroup"
            }
        
            $adminSecurityGroup = @{
             description="Security Group used for Power Platform - Admin environment"
             displayName="entra_powerplatform_admin"
             mailEnabled=$false
             securityEnabled=$true
             mailNickname="PowerPlatformAdminGroup"
            }
        
            $makersM365Group = @{
             description="Microsoft 365 Group used for Power Platform Makers"
             displayName="entra_powerplatform_makers"
             GroupTypes="Unified"
             mailEnabled=$true
             securityEnabled=$true
             mailNickname="Makers"
            }
        
            $usersM365Group = @{
             description="Microsoft 365 Group used for Power Platform Users"
             displayName="entra_powerplatform_users"
             GroupTypes="Unified"
             mailEnabled=$true
             securityEnabled=$true
             mailNickname="Users"
            }
        
           $adminsM365Group = @{
             description="Microsoft 365 Group used for Power Platform Admins"
             displayName="entra_powerplatform_admins"
             GroupTypes="Unified"
             mailEnabled=$true
             securityEnabled=$true
             mailNickname="Admins"
            }
            $Value =''
            # Code Begins
            # Get token to authenticate to Power Platform
           <# $Token = (Get-AzAccessToken -ResourceTypeName MSGraph).Token  #>
            
            $Token = (Get-AzAccessToken -ResourceUrl " https://graph.microsoft.com/.default").Token 
            <# try{
                $tokenx =  Get-AzAccessToken -ResourceUrl 'https://graph.microsoft.com' [-Permission 'Group.ReadWrite.All']              
                $tokeny =  Get-AzAccessToken -Scopes 'Group.ReadWrite.All'
                Connect-AzAccount -Identity
                $token = Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com"
                Install-module Microsoft.Graph 
                Connect-MgGraph -AccessToken $token.Token
            }
            catch{              
                Write-Error "AccessTokeny- $($tokeny) failed`r`n$_"              
            }         
            
            Write-Output "Bearer $($tokeny)" #> 
            $Token = (Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com/v1.0/groups").Token     
        
            # Power Platform HTTP Post Group Uri
            $PostGroups = 'https://graph.microsoft.com/v1.0/groups'
            
            # Declare Rest headers
            $Headers = @{
                "Content-Type"  = "application/json"
                "Authorization" = "Bearer $($Token)"
            }
           # Declaring the HTTP Post request
            $PostBody = @{             
            }
            if ($EnvironmentType -eq "dev") {          
                $PostBody = $devSecurityGroup   
            }
           elseif ($EnvironmentType -eq "test") {          
                $PostBody = $testSecurityGroup   
            }
            elseif ($EnvironmentType -eq "prod") {          
                $PostBody = $productionSecurityGroup   
            }
            elseif ($EnvironmentType -eq "admin") {          
                $PostBody = $adminSecurityGroup   
            }           
        
            $PostParameters = @{
                "Uri"         = "$($PostGroups)"
                "Method"      = "Post"
                "Headers"     = $headers
                "Body"        = $postBody | ConvertTo-json -Depth 100
                "ContentType" = "application/json"
            }        
            Write-Output "Invoking the request to create Security Group: $($postBody.displayName)"        
            try {
                $response = Invoke-RestMethod @PostParameters               
                $Value  = $response.id                
                Write-Output "Security Group Created $($response.displayName) is being created..."
            }
            catch {            
                Write-Error "AccessToken- $($Token) failed`r`n$_"
                throw "REST API call failed drastically"
            }  
            return $Value
}


function New-InstallPackaggeToEnvironment {
    param (      
        [Parameter(Mandatory = $true)][string]$EnvironmentId,
        [Parameter(Mandatory = $true)][string]$PackageName
    ) 
            # Code Begins
            # Get token to authenticate to Power Platform


            <# $Token = (Get-AzAccessToken).Token 
            $TokenGraph = (Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com/Group.ReadWrite.All").Token
               Write-Output "Token Graph $($Token1) "
            $Token1 = (Get-AzAccessToken -ResourceUrl "https://api.powerplatform.com/AppManagement.ApplicationPackages.Install").Token            
            Write-Output "Token1 $($TokenGraph) "
            Import-Module MSAL.PS
            $AuthResult = Get-MsalToken -ClientId '49676daf-ff23-4aac-adcc-55472d4e2ce0' -Scope 'https://api.powerplatform.com/.default'   
            Write-Output "TokenX $($AuthResult.AccessToken) " #>

            $TokenGraph = (Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com/").Token
           

            $Token = (Get-AzAccessToken -ResourceUrl "https://api.powerplatform.com/").Token
            # Power Platform HTTP Post Environment Uri
            $PostEnvironment = "https://api.powerplatform.com/appmanagement/environments/$($EnvironmentId)/applicationPackages/$($PackageName)/install?api-version=2022-03-01-preview"           
            
            # Declare Rest headers
            $Headers = @{
                "Content-Type"  = "application/json"
                "Authorization" = "Bearer $($Token)"
            }
           # Declaring the HTTP Post request
                     
        
            $PostParameters = @{
                "Uri"         = "$($PostEnvironment)"
                "Method"      = "Post"
                "Headers"     = $headers
                "ContentType" = "application/json"
            }  
            try {
                Invoke-RestMethod @PostParameters  
                Write-Output "Application Installtion $($PackageName) is being done..."
            }
            catch {            
                Write-Error "$($PackageName) Installtion EnvironmentId $($EnvironmentId) failed`r`n$_"               
            }  
          
}


function New-DLPAssignmentFromEnv {
    param (
        [Parameter(Mandatory = $true)][string[]]$Environments,
        [Parameter(Mandatory = $true)][string]$EnvironmentDLP
    )
    #DLP Template references
    $dlpPolicies = @{
        baseUri          = 'https://raw.githubusercontent.com/HemantKumar10/landingzones/main/foundations/powerPlatform/referenceImplementation/auxiliary/powerPlatform/'
        tenant           = @{
            low    = 'lowTenantDlpPolicy.json'
            medium = 'mediumTenantDlpPolicy.json'
            high   = 'highTenantDlpPolicy.json'
        }
        defaultEnv       = 'defaultEnvDlpPolicy.json'
        adminEnv         = 'adminEnvDlpPolicy.json'
        citizenDlpPolicy = 'citizenDlpPolicy.json'
        proDlpPolicy     = 'proDlpPolicy.json'
    }

    # Get base template from repo
    $templateFile = if ($EnvironmentDLP -in 'low', 'medium', 'high') { $dlpPolicies['tenant'].$EnvironmentDLP } else { $dlpPolicies["$EnvironmentDLP"] }
    if ([string]::IsNullOrEmpty($templateFile)) {
        throw "Cannot find DLP template $EnvironmentDLP"
    }
    try {
        $template = (Invoke-WebRequest -Uri ($dlpPolicies['BaseUri'] + $templateFile)).Content | ConvertFrom-Json -Depth 100
        Write-Output "Using base DLP template $templatefile"
    }
    catch {
        throw "Failed to get template $templatefile from $($dlpPolicies['baseUri'])"
    }

    # Handle environment inclusion
    if (($Environments -contains 'AllEnvironments' -and $Environments.count -gt 1) -or ($Environments -ne 'AllEnvironments')) {
        $environmentsToIncludeorExclude = $Environments | Where-Object { $_ -notlike 'AllEnvironments' } | ForEach-Object -Process {
            $envDisplayName = $_
            $envDetails = ''
            $envDetails = Get-PowerOpsEnvironment | Where-Object { $_.properties.displayName -eq $envDisplayName }
            [PSCustomObject]@{
                id   = $envDetails.id
                name = $envDetails.name
                type = 'Microsoft.BusinessAppPlatform/scopes/environments'
            }
        }
        if ($environmentsToIncludeorExclude.count -eq 1) {
            $template.environments | Add-Member -Type NoteProperty -Name id -Value $environmentsToIncludeorExclude.id -Force
            $template.environments | Add-Member -Type NoteProperty -Name name -Value $environmentsToIncludeorExclude.name -Force
        }
        else {
            $template.environments = $environmentsToIncludeorExclude
        }
        if ($Environments -contains 'AllEnvironments') {
            $template.environmentType = 'ExceptEnvironments'
        }
        else {
            $template.environmentType = 'OnlyEnvironments'
        }
    }
    # Convert template back to json and
    $template | ConvertTo-Json -Depth 100 -EnumsAsStrings | Set-Content -Path $templateFile -Force
    try {
        $null = New-PowerOpsDLPPolicy -TemplateFile $templateFile -Name $template.displayName -ErrorAction Stop
        Write-Output "Created Default $EnvironmentDLP DLP Policy"
    }
    catch {
        Write-Warning "Created Default $EnvironmentDLP DLP Policy`r`n$_"
    }
}



#endregion supporting functions

#region set tenant settings
# Only change tenant settings if "Setting" parameters have been provided
if ($PSBoundParameters.Keys -match "Setting") {
    # Get existing tenant settings
    #TODO - add condition so script can be used without changing tenant settings
    $existingTenantSettings = Get-PowerOpsTenantSettings
    # Update tenant settings
    $tenantSettings = $existingTenantSettings
    $tenantSettings.disableTrialEnvironmentCreationByNonAdminUsers = $PPTrialEnvCreationSetting -eq 'Yes'
    $tenantSettings.powerPlatform.powerApps.enableGuestsToMake = $PPGuestMakerSetting -eq 'No'
    $tenantSettings.powerPlatform.powerApps.disableShareWithEveryone = $PPAppSharingSetting -eq 'Yes'
    $tenantSettings.disableEnvironmentCreationByNonAdminUsers = $PPEnvCreationSetting -eq 'Yes'
    $tenantSettings.disableCapacityAllocationByEnvironmentAdmins = $PPEnvCapacitySetting -eq 'Yes'

    # Update tenant settings

    try {
        $tenantRequest = @{
            Path        = '/providers/Microsoft.BusinessAppPlatform/scopes/admin/updateTenantSettings'
            Method      = 'Post'
            RequestBody = ($tenantSettings | ConvertTo-Json -Depth 100)
        }
        $null = Invoke-PowerOpsRequest @tenantRequest
        Write-Output "Updated tenant settings"
    }
    catch {
        throw "Failed to set tenant settings"
    }
}

# Tenant Isolation settings
if ($PPTenantIsolationSetting -in 'inbound', 'outbound', 'both') {
    $tenantIsolationSettings = @{
        Enabled = $true
    }
            
    if ($PPTenantIsolationSetting -eq 'both') {
        $tenantIsolationSettings.AllowedDirection = 'InboundAndOutbound'
    }
    else {
        $tenantIsolationSettings.AllowedDirection = $PPTenantIsolationSetting
    }    

    try {
        Set-PowerOpsTenantIsolation @tenantIsolationSettings
        Write-Output "Updated tenant isolation settings with $PPTenantIsolationSetting"
    }
    catch {
        throw "Failed to update tenant isolation settings"
    }
}
#endregion set tenant settings

#region default environment
# Get default environment
# Retry logic to handle green field deployments
$defaultEnvAttempts = 0
do {
    $defaultEnvAttempts++
    $defaultEnvironment = Get-PowerOpsEnvironment | Where-Object { $_.Properties.environmentSku -eq "Default" }
    if (-not ($defaultEnvironment)) {
        Write-Output "Getting default environment - attempt $defaultEnvAttempts"
        Start-Sleep -Seconds 15
    }
} until ($defaultEnvironment -or $defaultEnvAttempts -eq 15)

# Rename default environment if parameter provided
if (-not [string]::IsNullOrEmpty($PPDefaultRenameText)) {
    # Get old default environment name
    $oldDefaultName = $defaultEnvironment.properties.displayName
    if ($PPDefaultRenameText -ne $oldDefaultName) {
        $defaultEnvironment.properties.displayName = $PPDefaultRenameText
        $defaultEnvRequest = @{
            Path        = '/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments/{0}' -f $defaultEnvironment.name
            Method      = 'Patch'
            RequestBody = ($defaultEnvironment | ConvertTo-Json -Depth 100)
        }
        try {
            Invoke-PowerOpsRequest @defaultEnvRequest
            Write-Output "Renamed default environment from $oldDefaultName to $PPDefaultRenameText"
        }
        catch {
            Write-Warning "Failed to rename Default Environment`r`n$_"
        }
    }
}
# Create DLP policy for default environment
if ($PPDefaultDLP -eq 'Yes') {
    # Get default recommended DLP policy from repo
    try {
        New-DLPAssignmentFromEnv -Environments $defaultEnvironment.properties.displayName -EnvironmentDLP 'defaultEnv'
    }
    catch {
        Write-Warning "Failed to create Default Environment DLP Policy`r`n$_"
    }
}
# Enable managed environment for default environment
if ($defaultEnvironment.properties.governanceConfiguration.protectionLevel -ne 'Standard' -and $PPDefaultManagedEnv -eq 'Yes') {
    try {
        Write-Output "Enabling managed environment for the default environment"
        Enable-PowerOpsManagedEnvironment -EnvironmentName $defaultEnvironment.name -GroupSharingDisabled ($PPDefaultManagedSharing -eq 'Yes')
    }
    catch {
        Write-Warning "Failed to enable managed environment for default environment"
    }
}
#endregion default environment


#region create default tenant dlp policies
if ($PPTenantDLP -in 'low', 'medium', 'high') {
    try {
        $null = New-DLPAssignmentFromEnv -Environments $defaultEnvironment.properties.displayName -EnvironmentDLP $PPTenantDLP
        Write-Output "Created Default Tenant DLP Policy - $PPTenantDLP"
    }
    catch {
        Write-Warning "Failed to create Default Tenant DLP Policy`r`n$_"
    }
}
#endregion create default tenant dlp policies

#region create landing zones for citizen devs
$PPCitizenCount = 1
$PPCitizenConfiguration = '';
if ($PPCitizen -in "yes", "half" -and $PPCitizenCount -ge 1 -or $PPCitizen -eq 'custom') {
    if ($PPCitizenConfiguration -ne '') {
        try {
            $environmentsToCreate = New-EnvironmentCreationObject -ARMInputString ($PPCitizenConfiguration -join ',') -EnvALM:($PPCitizenAlm -eq 'Yes')
        }
        catch {
            throw "Failed to create environment object. Input data is malformed. '`r`n$_'"
        }
    }
    else {
        try {
            $envHt = @{
                EnvCount       = $PPCitizenCount
                EnvNaming      = $PPCitizenNaming
                EnvRegion      = $PPCitizenRegion
                envLanguage    = $PPCitizenLanguage
                envCurrency    = $PPCitizenCurrency
                envDescription = ''
                EnvALM         = $PPCitizenAlm -eq 'Yes'
                EnvDataverse   = $PPCitizen -eq 'Yes'
            }
            $environmentsToCreate = New-EnvironmentCreationObject @envHt
        }
        catch {
            throw "Failed to create environment object. Input data is malformed. '`r`n$_'"
        }
    }
    foreach ($environment in $environmentsToCreate) {
        
        try {
            $envCreationHt = @{
                Name               = $environment.envName
                Location           = $environment.envRegion
                Dataverse          = $true
                ManagedEnvironment = $PPCitizenManagedEnv -eq 'Yes'
                Description        = $environment.envDescription
                LanguageName       = $environment.envLanguage
                Currency           = $environment.envCurrency
                SecurityGroupId    = $environment.envRbac  
                EnvSku             = $environment.envSKu                                           
            }   
            
            # Starts Here: Code to create Group
            #New-AzADGroup -DisplayName 'Test' -MailEnabled $False -MailNickName 'PowerPlatformDevelopmentGroup' -SecurityEnabled $True -Description 'Security Group used for Power Platform - Development environment'
            #New-AzADGroup -DisplayName 'PowerPlatformDevelopmentGroup' -MailNickName 'PowerPlatformDevelopmentGroup' 
            # Ends Here:  Code to create group 
            
            
            # Code Begins
            # Get token to authenticate to Power Platform
            
            $Token = (Get-AzAccessToken).Token
            
            # Power Platform API base Uri
            $BaseUri = "https://api.bap.microsoft.com"
            
            # Power Plaform HTTP Get Environment Uri
            $GetEnvironment = '/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments?$expand=permissions&api-version=2016-11-01'
            
            # Power Platform HTTP Post Environment Uri
            $PostEnvironment = '/providers/Microsoft.BusinessAppPlatform/environments?api-version=2019-05-01&ud=/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments'
            
            # Power Platform HTTP Get DLP Policy Uri // Coming soon
            # $GetPolicies = "https://api.bap.microsoft.com/providers/Microsoft.BusinessAppPlatform/scopes/admin/apiPolicies?api-version=2016-11-01"
            
            # Declare Rest headers
            $Headers = @{
                "Content-Type"  = "application/json"
                "Authorization" = "Bearer $($Token)"
            }
      
            Write-Output "Creating Environment: $($envCreationHt.Name)"
            
            # Form the request body to create new Environments in Power Platform           

            $templates = @()
            if ($ppD365SalesApp -eq 'true' -and $envCreationHt.Name -ne $Global:envAdminName ) {          
                $templates += 'D365_Sales'   
            }
            if ($ppD365CustomerServiceApp -eq 'true' -and $envCreationHt.Name -ne $Global:envAdminName ) {          
                $templates += 'D365_CustomerService'   
            }
            if ($ppD365FieldServiceApp -eq 'true' -and $envCreationHt.Name -ne $Global:envAdminName ) { 
                $templates += 'D365_FieldService'   
            }
            
           # "securityGroupId"= "$($envCreationHt.SecurityGroupId)"
            
        # Declaring the HTTP Post request
            $PostBody = @{
                "properties" = @{
                    "linkedEnvironmentMetadata" = @{
                        "baseLanguage" = "$($envCreationHt.LanguageName)"
                        "domainName"   = "$($envCreationHt.Name)"
                        "templates"    =  $templates
                        
                    }
                    "databaseType"   = "CommonDataService"
                    "displayName"    = "$($envCreationHt.Name)"
                    "environmentSku" = "$($envCreationHt.EnvSku)"                 
                }
                "location"   = "$($environment.envRegion)"
            }
        
            $PostParameters = @{
                "Uri"         = "$($baseUri)$($postEnvironment)"
                "Method"      = "Post"
                "Headers"     = $headers
                "Body"        = $postBody | ConvertTo-json -Depth 100
                "ContentType" = "application/json"
            }
        
            Write-Output "Invoking the request to create Environment: $($envCreationHt.Name)"
        
            try {
                $response = Invoke-RestMethod @PostParameters               
                Write-Output "Citizen Environment $($envCreationHt.Name) is being created..."
            }
            catch {
                Write-Error "Creation of citizen Environment $($envCreationHt.Name) failed`r`n$_"
                throw "REST API call failed drastically"
            }  




           #Starts Install Power Platform Pipeline App in Admin Envrionemnt
           Write-Output "Admin Envrionement Name $($Global:envAdminName)."
           If($envCreationHt.Name -eq $Global:envAdminName ){
            Start-Sleep -Seconds 120           
            foreach ($envTier in $envTiers) {
                try {          
                          $adminEnvironment = Get-PowerOpsEnvironment | Where-Object { $_.Properties.displayName -eq $envAdminName }
                          New-InstallPackaggeToEnvironment -EnvironmentId $($adminEnvironment.name) -PackageName 'msdyn_AppDeploymentAnchor'
                }
                catch {
                    Write-Warning "Error installing App`r`n$_"
                }
            }
           }
            #Ends Install Power Platform Pipeline App in Admin Envrionemnt

            # Get newly created environments
           <# $GetParameters = @{
                "Uri"         = "$($BaseUri)$($GetEnvironment)"
                "Method"      = "Get"
                "Headers"     = $headers
                "ContentType" = "application/json"
            }   #>       
            
           #Start-Sleep -Seconds 120    
            try {
                <# New-InstallPackaggeToEnvironment -EnvironmentId '32512600-a32e-e22f-85f0-c7168370b4a5' -PackageName 'msdyn_AppDeploymentAnchor' #>
                <#$response = Invoke-RestMethod @GetParameters #>
                #Write-Host ($response | Format-List | Out-String)
            }
            catch {
                Write-Output "Retrieving the environment failed.`r`n$_"              
            }          
            <# $response.value | Where-Object { $_.properties.displayName -eq $($envCreationHt.Name) } | Foreach-Object -Process {  
                Write-Output "$($envCreationHt.Name): Installation of App Power Platform Pipeline started "          
                  New-InstallPackaggeToEnvironment -EnvironmentId $($_.name) -PackageName 'msdyn_AppDeploymentAnchor'
                    Write-Output "$($envCreationHt.Name): Installation of App Power Platform Pipeline completed"  
                } #>            

        }
        catch {
            Write-Warning "Failed to create citizen environment $($environment.envName)"
            Write-Output "Failed to create environment citizen.'`r`n$_'"  
        }
    }
    if ($PPCitizenDlp -eq "Yes") {
        New-DLPAssignmentFromEnv -Environments $environmentsToCreate.envName -EnvironmentDLP 'citizenDlpPolicy'
    }
}
#endregion create landing zones for citizen devs

$DeploymentScriptOutputs['Deployment'] = 'Successful'
