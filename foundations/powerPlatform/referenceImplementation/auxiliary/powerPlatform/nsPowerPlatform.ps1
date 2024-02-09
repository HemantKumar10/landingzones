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
$envTiers = 'dev', 'test'

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

            if ($true -eq $EnvALM) {
                foreach ($envTier in $envTiers) {

                    if ( $envTier -eq 'dev' ){
                        $securityGroupId = $devSecurityGroupId
                    }
                    if ( $envTier -eq 'test' ){
                        $securityGroupId = $testSecurityGroupId
                    }
                    if ( $envTier -eq 'prod' ){
                        $securityGroupId = $prodSecurityGroupId
                    }
                    if ( $envTier -eq 'admin' ){
                        $securityGroupId = $adminSecurityGroupId
                    }

                    [PSCustomObject]@{
                        envName        = "{0}-{1}" -f $environmentName, $envTier
                        envRegion      = $EnvRegion
                        envDataverse   = $EnvDataverse
                        envLanguage    = $envLanguage
                        envCurrency    = $envCurrency
                        envDescription = $envDescription
                        envRbac        = $securityGroupId
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
                }
            }
        }
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
            }   
       $environmentt = @{
            location = 'uksouth'
            properties = @{
                displayName = 'PPFromAPI'
                environmentSku = 'Sandbox'
            }
        } 

        Echo A | Install-Module -Name Microsoft.PowerApps.Administration.PowerShell
        Import-Module (Join-Path (Split-Path $script:MyInvocation.MyCommand.Path) "Microsoft.PowerApps.RestClientModule.psm1") -NoClobber #-Force
          
      
       $ApiVersion = "2018-01-01"
       $postEnvironmentUri = "https://{bapEndpoint}/providers/Microsoft.BusinessAppPlatform/environments`?api-version={apiVersion}&id=/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments";
       $response = InvokeApi -Method POST -Route $postEnvironmentUri -ApiVersion $ApiVersion -Body $environmentt  -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)   
         Write-Output "Created citizen environment $($environment.envName) in $($environment.envRegion)"
            Write-Output "D365 for Sales: $ppD365SalesApp"
            Write-Output "D365 for Customer Service: $ppD365CustomerServiceApp"
            Write-Output "D365 for Field Service: $ppD365FieldServiceApp"        
           
        }
        catch {
            Write-Output "Failed to create environment citizen.'`r`n$_'"        
            Write-Output $_.ScriptStackTrace          
            Write-Warning "Failed to create citizen environment $($environment.envName)"
        }
    }
    if ($PPCitizenDlp -eq "Yes") {
        New-DLPAssignmentFromEnv -Environments $environmentsToCreate.envName -EnvironmentDLP 'citizenDlpPolicy'
    }
}
#endregion create landing zones for citizen devs

function New-AdminPowerAppEnvironments
{
<#
 .SYNOPSIS
 Creates an Environment.
 .DESCRIPTION
 The New-AdminPowerAppEnvironment cmdlet creates a new Environment by the logged in user.
 Api version 2019-05-01 adds the capability to create an environment with a database. The new commandline argument 'ProvisionDatabase'
 acts as switch to indicate we need to create an environment with the database. If the switch is set, LanguageName and CurrencyName arguments
 are mandatory to pass while Templates,SecurityGroupId and DomainName are optional.
 Use Get-Help New-AdminPowerAppEnvironment -Examples for more detail.
 .PARAMETER DisplayName
 The display name of the new Environment.
 .PARAMETER LocationName
 The location of the new Environment. Use Get-AdminPowerAppEnvironmentLocations to see the valid locations.
 .PARAMETER EnvironmentSku
 The Environment type (Trial or Production).
 .PARAMETER ProvisionDatabase
 The switch to provision Cds database along with creating the environment. If set, LanguageName and CurrencyName are mandatory to pass as arguments.
 .PARAMETER CurrencyName
 The default currency for the database, use Get-AdminPowerAppCdsDatabaseCurrencies to get the supported values
 .PARAMETER LanguageName
 The default languages for the database, use Get-AdminPowerAppCdsDatabaseLanguages to get the support values
 .PARAMETER Templates
 The list of templates used for provisioning. If it is null, an empty Common Data Service database will be created
 .PARAMETER SecurityGroupId
 The Azure Active Directory security group object identifier to restrict database membership.
 .PARAMETER DomainName
 The domain name.
 .PARAMETER WaitUntilFinished
 If set to true, the function will not return until provisioning the database is complete (as either a success or failure)
 .EXAMPLE
 New-AdminPowerAppEnvironment -DisplayName 'HQ Apps' -Location unitedstates -EnvironmentSku Trial
 Creates a new Trial Environment in the United States with the display name 'HQ Apps'
 .EXAMPLE
 New-AdminPowerAppEnvironment -DisplayName 'Asia Dev' -Location asia -EnvironmentSku Production
 Creates a new Production Environment in Asia with the display name 'Asia Dev'
 #>
    [CmdletBinding(DefaultParameterSetName="User")]
    param
    (
        [Parameter(Mandatory = $false, ParameterSetName = "Name")]
        [string]$DisplayName,

        [Parameter(Mandatory = $true, ParameterSetName = "Name", ValueFromPipelineByPropertyName = $true)]
        [string]$LocationName,

        [ValidateSet("Trial", "Production", "Sandbox")]
        [Parameter(Mandatory = $true, ParameterSetName = "Name")]
        [string]$EnvironmentSku,

        [Parameter(Mandatory = $false, ParameterSetName = "ProvisionDatabase")]
        [Switch]$ProvisionDatabase,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$CurrencyName,
    
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$LanguageName,

        [Parameter(Mandatory = $false)]
        [string[]]$Templates,

        [Parameter(Mandatory = $false)]
        [string]$SecurityGroupId = $null,

        [Parameter(Mandatory = $false)]
        [string]$DomainName = $null,

        [Parameter(Mandatory = $false)]
        [bool]$WaitUntilFinished = $true,

        [Parameter(Mandatory = $false, ParameterSetName = "User")]
        [string]$ApiVersion = "2018-01-01"
    )
    process
    {
        $postEnvironmentUri = "https://{bapEndpoint}/providers/Microsoft.BusinessAppPlatform/environments`?api-version={apiVersion}&id=/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments";

        $environment = @{
            location = $LocationName
            properties = @{
                displayName = $DisplayName
                environmentSku = $EnvironmentSku
            }
        }

        if ($ProvisionDatabase)
        {
            if ($CurrencyName -ne $null -and
                $LanguageName -ne $null)
            {
                $environment.properties["linkedEnvironmentMetadata"] = @{
                    baseLanguage = $LanguageName
                    type = "LinkedD365Instance"
                    currency = @{
                        code = $CurrencyName
                    }
                    templates = $Templates
                }

                if (-not [string]::IsNullOrEmpty($SecurityGroupId))
                {
                    $environment.properties["linkedEnvironmentMetadata"] += @{
                       securityGroupId = $SecurityGroupId
                    }
                }

                if (-not [string]::IsNullOrEmpty($DomainName))
                {
                    $environment.properties["linkedEnvironmentMetadata"] += @{
                        domainName = $DomainName
                    }
                }
            }
            else
            {
                Write-Error "CurrencyName and Language must be passed as arguments."
                throw
            }

            # By default we poll until the CDS database is finished provisioning
            If($WaitUntilFinished)
            {
                $response = InvokeApiNoParseContent -Method POST -Route $postEnvironmentUri -Body $environment -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)
                $statusUrl = $response.Headers['Location']

                if ($response.StatusCode -eq "BadRequest")
                {
                    #Write-Error "An error occured."
                    CreateHttpResponse($response)
                }
                else
                {
                    $currentTime = Get-Date -format HH:mm:ss
                    $nextTime = Get-Date -format HH:mm:ss
                    $TimeDiff = New-TimeSpan $currentTime $nextTime
                    $timeoutInSeconds = 300
        
                    #Wait until the environment has been deleted, there is an error, or we hit a timeout
                    while(($response.StatusCode -ne 200) -and ($response.StatusCode -ne 404) -and ($response.StatusCode -ne 500) -and ($TimeDiff.TotalSeconds -lt $timeoutInSeconds))
                    {
                        Start-Sleep -s 5
                        $response = InvokeApiNoParseContent -Route $statusUrl -Method GET -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)
                        $nextTime = Get-Date -format HH:mm:ss
                        $TimeDiff = New-TimeSpan $currentTime $nextTime
                    }

                    CreateHttpResponse($response)
                }
            }
            # optionally the caller can choose to NOT wait until provisioning is complete and get the provisioning status by polling on Get-AdminPowerAppEnvironment and looking at the provisioning status field
            else
            {
                $response = InvokeApi -Method POST -Route $route -Body $environment -ApiVersion $ApiVersion -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

                if ($response.StatusCode -eq "BadRequest")
                {
                    #Write-Error "An error occured."
                    CreateHttpResponse($response)
                }

                CreateHttpResponse($response)
            }
        }
        else
        {
            $response = InvokeApi -Method POST -Route $postEnvironmentUri -ApiVersion $ApiVersion -Body $environment  -Verbose:($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent -eq $true)

            if ($response.StatusCode -eq "BadRequest")
            {
                #Write-Error "An error occured."
                CreateHttpResponse($response)
            }
            else
            {
                CreateEnvironmentObject -EnvObject $response -ReturnCdsDatabaseType $false
            }
        }
    }
}

$DeploymentScriptOutputs['Deployment'] = 'Successful'
