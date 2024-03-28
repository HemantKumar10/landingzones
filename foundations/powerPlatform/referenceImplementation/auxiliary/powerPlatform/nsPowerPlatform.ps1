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
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPCitizenNaming,
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPCitizenRegion,
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPCitizenDlp,    
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPCitizenManagedEnv,        
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPCitizenCurrency,
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$PPCitizenLanguage,     
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$ppD365SalesApp,
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$ppD365CustomerServiceApp,
    [Parameter(Mandatory = $false)][string][AllowEmptyString()][AllowNull()]$ppD365FieldServiceApp        
)

$DeploymentScriptOutputs = @{}
#Install required modules
Install-Module -Name PowerOps -AllowPrerelease -Force   

#Default ALM environment tiers
$envTiers = 'admin','dev','test','prod'

$Global:envAdminName = ''
$Global:envTestName = ''
$Global:envDevName = ''
$Global:envProdName = ''

$PPCitizen = 'yes'
$PPCitizenAlm = 'Yes'

#region supporting functions
function New-EnvironmentCreationObject {
    param (             
        [Parameter(Mandatory = $true, ParameterSetName = 'EnvCount')]$EnvNaming,
        [Parameter(Mandatory = $true, ParameterSetName = 'EnvCount')]$EnvRegion,
        [Parameter(Mandatory = $true, ParameterSetName = 'EnvCount')]$EnvLanguage,
        [Parameter(Mandatory = $true, ParameterSetName = 'EnvCount')]$EnvCurrency,
        [Parameter(Mandatory = $true, ParameterSetName = 'EnvCount')]$EnvDescription,
        [Parameter(Mandatory = $false)][switch]$EnvALM,
        [Parameter(Mandatory = $false, ParameterSetName = 'EnvCount')][switch]$EnvDataverse
    )
                
    $environmentName = $EnvNaming
    $securityGroupId = ''      
    $envSku = 'Sandbox'                 
    if ($true -eq $EnvALM) {                
        foreach ($envTier in $envTiers) {                 
            if($envTier -eq 'dev'){                                          
                $createdSecurityGroup = New-CreateSecurityGroup -EnvironmentType dev                                    
                $securityGroupId = $createdSecurityGroup
                $envSku = 'Sandbox'  
                $envDescription = 'Environment used for development purposes'
                $Global:envDevName =  "{0}-{1}" -f $environmentName, $envTier    
            }
            if ( $envTier -eq 'test' ){
                $createdSecurityGroup = New-CreateSecurityGroup -EnvironmentType test
                $securityGroupId = $createdSecurityGroup
                $envSku = 'Sandbox'  
                $envDescription = 'Environment used for testing purposes'
                $Global:envTestName =  "{0}-{1}" -f $environmentName, $envTier      
            }
            if ( $envTier -eq 'prod' ){
                $createdSecurityGroup = New-CreateSecurityGroup -EnvironmentType prod
                $securityGroupId = $createdSecurityGroup
                $envSku ='Production'      
                $envDescription = 'Environment used for production purposes' 
                $Global:envProdName =  "{0}-{1}" -f $environmentName, $envTier                  
            }
            if ( $envTier -eq 'admin' ){
                $createdSecurityGroup = New-CreateSecurityGroup -EnvironmentType admin
                $securityGroupId = $createdSecurityGroup                
                $envSku ='Production'
                $envDescription = 'Environment used for administration purposes'     
                $Global:envAdminName =  "{0}-{1}" -f $environmentName, $envTier                   
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
                
            $Value =''
            # Code Begins
            # Get token to authenticate to Power Platform                       
            $Token = (Get-AzAccessToken -ResourceUrl " https://graph.microsoft.com/.default").Token            
            
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
            
            try {
                $response = Invoke-RestMethod @PostParameters               
                $Value  = $response.id                                
            }
            catch {           
             
                throw "REST API call failed drastically"
            }  

            return $Value
}

#Install a package or App to environment
function New-InstallPackaggeToEnvironment {
    param (      
        [Parameter(Mandatory = $true)][string]$EnvironmentId,
        [Parameter(Mandatory = $true)][string]$PackageName,
        [Parameter(Mandatory = $true)][string]$EnvironmentURL
    ) 
        # Code Begins
        # Get token to authenticate to Power Platform
        
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
            $outputPackage = Invoke-RestMethod @PostParameters 
            $operationId =  $outputPackage.lastOperation.operationId  
            Write-Output "Application Installation $($PackageName) in progress"  
            Start-Sleep -Seconds 15   
            New-GetApplicationInstallStatus -OperationId $operationId -EnvironmentId $EnvironmentId -EnvironmentURL $EnvironmentURL -EnvironmentName $Global:envAdminName -EnvironmentType '200000000'         
           
        }
        catch {            
            Write-Error "$($PackageName) Installation EnvironmentId $($EnvironmentId) failed`r`n$_"               
        }          
}



#Get the Installation Status of any package by EnvId and Operation Id
function New-GetApplicationInstallStatus {
    param (      
        [Parameter(Mandatory = $true)][string]$OperationId,
        [Parameter(Mandatory = $true)][string]$EnvironmentId,
        [Parameter(Mandatory = $true)][string]$EnvironmentURL,
        [Parameter(Mandatory = $true)][string]$EnvironmentName,
        [Parameter(Mandatory = $true)][string]$EnvironmentType
        
    ) 

       $getApplicationAttempt = 0

       Write-Output "Checking Application Status"   
     do{
        $getApplicationAttempt++
          # Code Begins
        # Get token to authenticate to Power Platform
        
        $Token = (Get-AzAccessToken -ResourceUrl "https://api.powerplatform.com/").Token
        # Power Platform HTTP Post Environment Uri
        $GetPackages = "https://api.powerplatform.com/appmanagement/environments/$($EnvironmentId)/operations/$($OperationId)?api-version=2022-03-01-preview"    

        # Declare Rest headers      

        # Declare Rest headers
        $Headers = @{
            "Content-Type"  = "application/json"
            "Authorization" = "Bearer $($Token)"
        }
        # Declaring the HTTP Post request
        $GetParameters = @{
            "Uri"         = "$($GetPackages)"
            "Method"      = "Get"
            "Headers"     = $headers
            "ContentType" = "application/json"
        }   
        try {
            $packageSTatus = Invoke-RestMethod @GetParameters 
            if ($packageSTatus.status -ne 'Succeeded' -or $packageSTatus.status -ne 'Canceled' -or $packageSTatus.status -ne 'Failed') {                      
                Start-Sleep -Seconds 15
            } 
            if($packageSTatus.status -eq 'Succeeded'){            
                Start-Sleep -Seconds 5
                #Region Check the Dev Environment is Successfully created or not
                 $getdevEnvAttempts =0
                 do {
                    $getdevEnvAttempts++
                   $fetchDevEnv =  Get-PowerOpsEnvironment | Where-Object { $_.properties.displayName -eq $Global:envDevName} 
                   if ($fetchDevEnv.properties.provisioningState -ne 'Succeeded' ) {
                       Write-Output "Getting Dev environment - attempt $getdevEnvAttempts"
                       Start-Sleep -Seconds 15
                   }
                   else {
                    $envType = '200000000' #Development 
                    New-CreateDeploymentEnvrionmentRecord -EnvironmentURL $EnvironmentURL -EnvironmentName $($fetchDevEnv.properties.displayName) -EnvironmentId $($fetchDevEnv.name) -EnvironmentType $envType 
                   }
                 } until ( $fetchDevEnv.properties.provisioningState -eq 'Succeeded' -or $getdevEnvAttempts -eq 20)
                #End Region Check the Dev Environment is Successfully created or not

                #Region Check the test Environment is Successfully created or not
                  $getTestEnvAttempts =0
                  do {
                     $getTestEnvAttempts++
                    $fetchTestEnv =  Get-PowerOpsEnvironment | Where-Object { $_.properties.displayName -eq $Global:envTestName} 
                    if ($fetchTestEnv.properties.provisioningState -ne 'Succeeded' ) {
                        Write-Output "Getting Test environment - attempt $getTestEnvAttempts"
                        Start-Sleep -Seconds 15
                    }
                    else {
                     $envType = '200000001' #Taregt 
                     New-CreateDeploymentEnvrionmentRecord -EnvironmentURL $EnvironmentURL -EnvironmentName $($fetchTestEnv.properties.displayName) -EnvironmentId $($fetchTestEnv.name) -EnvironmentType $envType 
                    }
                  } until ( $fetchTestEnv.properties.provisioningState -eq 'Succeeded' -or $getTestEnvAttempts -eq 20)
                 #End Region Check the test Environment is Successfully created or not
 

                   #Region Check the Prod Environment is Successfully created or not
                   $getProdEnvAttempts =0
                   do {
                      $getProdEnvAttempts++
                     $fetchProdEnv =  Get-PowerOpsEnvironment | Where-Object { $_.properties.displayName -eq $Global:envProdName} 
                     if ($fetchProdEnv.properties.provisioningState -ne 'Succeeded' ) {
                         Write-Output "Getting Production environment - attempt $getProdEnvAttempts"
                         Start-Sleep -Seconds 15
                     }
                     else {
                      $envType = '200000001' #Taregt 
                      New-CreateDeploymentEnvrionmentRecord -EnvironmentURL $EnvironmentURL -EnvironmentName $($fetchProdEnv.properties.displayName) -EnvironmentId $($fetchProdEnv.name) -EnvironmentType $envType 
                     }
                   } until ( $fetchProdEnv.properties.provisioningState -eq 'Succeeded' -or $getProdEnvAttempts -eq 20)
                  #End Region Check the Prod Environment is Successfully created or not



                #Create Deployment Environment Record for Admin
               <# $adminEnvDetails = Get-PowerOpsEnvironment | Where-Object { $_.properties.displayName -eq $Global:envAdminName }     
                $envType = '200000001' #Taregt 
                New-CreateDeploymentEnvrionmentRecord -EnvironmentURL $EnvironmentURL -EnvironmentName $($adminEnvDetails.properties.displayName) -EnvironmentId $($adminEnvDetails.name) -EnvironmentType $envType 
                #>
               <# Get-PowerOpsEnvironment | Where-Object {$_.properties.displayName -eq $Global:envAdminName -or $_.properties.displayName -eq $Global:envTestName -or $_.properties.displayName -eq $Global:envDevName -or $_.properties.displayName -eq $Global:envProdName} | ForEach-Object -Process {
                    $envType = '200000001' #Taregt
                    if($_.properties.displayName-eq $Global:envDevName){
                        $envType = '200000000' #Development 
                    }                    
                    New-CreateDeploymentEnvrionmentRecord -EnvironmentURL $EnvironmentURL -EnvironmentName $($_.properties.displayName) -EnvironmentId $($_.name) -EnvironmentType $envType 
                } #>
                      
                New-CreateDeploymentPipeline -Name "Power Platform Pipeline" -EnvironmentURL $EnvironmentURL 
                Start-Sleep -Seconds 5
                $listDeploymentEnvironments =  New-GetDeploymentEnvrionmentRecords -EnvironmentURL $EnvironmentURL
                Start-Sleep -Seconds 5
                $listDeploymentPipelines = New-GetDeploymentPipelineRecords -EnvironmentURL $EnvironmentURL 

                foreach($pipeline in $listDeploymentPipelines.value){
                    $listDeploymentEnvironments.value | Where-Object {$_.environmenttype -eq 200000000} | ForEach-Object -Process {
                        New-AssociateDeploymentEnvironmentWithPipeline -DeploymentPipelineId $pipeline.deploymentpipelineid -DeploymentEnvrionmentId $_.deploymentenvironmentid -EnvironmentURL $EnvironmentURL  
                    }
                }
                

                $testEnvrionmentName = $Global:envTestName
                foreach($pipeline in $listDeploymentPipelines.value){
                $listDeploymentEnvironments.value | Where-Object {$_.environmenttype -eq 200000001 -and $_.name -eq $testEnvrionmentName} | ForEach-Object -Process {                    
                New-CreateDeploymentStages -Name "Deploy to $($testEnvrionmentName)" -DeploymentPipeline $pipeline.deploymentpipelineid -PreviousStage 'Null' -TargetDeploymentEnvironment $_.deploymentenvironmentid  -EnvironmentURL $EnvironmentURL 
                }
            }

                Start-Sleep -Seconds 5
                foreach($pipeline in $listDeploymentPipelines.value){
                $listDeploymentStages = New-GetDeploymentStageRecords -EnvironmentURL $EnvironmentURL 
                $prodEnvrionmentName = $Global:envProdName
                $listDeploymentEnvironments.value | Where-Object {$_.environmenttype -eq 200000001 -and $_.name -eq $prodEnvrionmentName} | ForEach-Object -Process {                
                    $previousStage = $listDeploymentStages.value[0].deploymentstageid 
                    New-CreateDeploymentStages -Name "Deploy to $($prodEnvrionmentName)" -DeploymentPipeline $pipeline.deploymentpipelineid -PreviousStage $previousStage -TargetDeploymentEnvironment $_.deploymentenvironmentid  -EnvironmentURL $EnvironmentURL 
                }  
            }             
               

            }
           #Write-Host ($packageSTatus | Format-List | Out-String)
        }
        catch {            
            Write-Error "Failed gettting package status`r`n$_"               
        } 

     } until ($packageSTatus.status -eq 'Succeeded' -or $packageSTatus.status -eq 'Canceled' -or $packageSTatus.status -eq 'Failed' -or $getApplicationAttempt -eq 20)
}

#Create a Deployment Environment Record
function New-CreateDeploymentEnvrionmentRecord {
    param (      
        [Parameter(Mandatory = $true)][string]$EnvironmentURL,
        [Parameter(Mandatory = $true)][string]$EnvironmentName,
        [Parameter(Mandatory = $true)][string]$EnvironmentId,
        [Parameter(Mandatory = $true)][string]$EnvironmentType
    ) 
        # Code Begins
        # Get token to authenticate to Power Platform
        
        $Token = (Get-AzAccessToken -ResourceUrl $($EnvironmentURL)).Token
        # Power Platform HTTP Post Environment Uri
        $PostEnvironment = "$($EnvironmentURL)/api/data/v9.0/deploymentenvironments"           
        
        #Write-Output "Token $($Token)"
        Write-Output " Envrionment URL $($PostEnvironment)"
        # Declare Rest headers
        $PostBody = @{           
            "name" = "$($EnvironmentName)"
            "environmenttype"   = $($EnvironmentType)
            "environmentid"    =  "$($EnvironmentId)" 
        }

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
            "Body"        = $postBody | ConvertTo-json -Depth 100
        }   
        try {
            Invoke-RestMethod @PostParameters  
            Write-Output "Deployment Envrionment Created $($EnvironmentName)"
            #Write-Host ($outputDeploymentEnvironment | Format-List | Out-String)
       
        }
        catch {            
            Write-Error "Deployment Envrionment Creation $($EnvironmentName) failed`r`n$_"               
        }          
}


#Create a Deployment Pipeline Record
function New-CreateDeploymentPipeline {
    param (      
        [Parameter(Mandatory = $true)][string]$Name,       
        [Parameter(Mandatory = $true)][string]$EnvironmentURL
    ) 
        # Code Begins
        # Power Platform HTTP Post Environment Uri
        $PostEnvironment = "$($EnvironmentURL)/api/data/v9.0/deploymentpipelines"     
        
        $Token = (Get-AzAccessToken -ResourceUrl $($EnvironmentURL)).Token
        $PostBody = @{
                    "name" = "$($Name)"
        }
        
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
            "Body"        = $postBody | ConvertTo-json -Depth 100
        }  
        try {
            Invoke-RestMethod @PostParameters  
            Write-Output "Deployment Pipeline record created: $($Name)"        
            #New-CreateDeploymentStages -Name 'Prodcution - Deployment Statge' -DeploymentPipeline '' -PreviousStage '' -TargetDeploymentEnvironment '' -EnvironmentURL '' -Token $Token 
        }
        catch {            
            Write-Error "Deployment Pipeline record creation: $($Name) failed`r`n$_"               
        }          
}


#Get the list of Deployment Environment Record
function New-GetDeploymentEnvrionmentRecords {
    param (      
        [Parameter(Mandatory = $true)][string]$EnvironmentURL      
        
    ) 
        # Code Begins
     
        $Token = (Get-AzAccessToken -ResourceUrl $($EnvironmentURL)).Token
        # Power Platform HTTP Post Environment Uri
        $GetEnvironment = "$($EnvironmentURL)/api/data/v9.0/deploymentenvironments"   
        # Declare Rest headers
        $Headers = @{
            "Content-Type"  = "application/json"
            "Authorization" = "Bearer $($Token)"
        }
      
        # Declaring the HTTP Post request
        $GetParameters = @{
            "Uri"         = "$($GetEnvironment)"
            "Method"      = "GET"
            "Headers"     = $headers
            "ContentType" = "application/json"
        }   
        try {
            $outputDeploymentEnvironments = Invoke-RestMethod @GetParameters 
            return $outputDeploymentEnvironments          
       
        }
        catch {            
            Write-Error "Get Deployment Envrionment $($EnvironmentName) failed`r`n$_"               
        }          
}


#Get the list of Deployment pipeline records
function New-GetDeploymentPipelineRecords {
    param (      
        [Parameter(Mandatory = $true)][string]$EnvironmentURL
    ) 
        # Code Begins    
        $Token = (Get-AzAccessToken -ResourceUrl $($EnvironmentURL)).Token  
        # Power Platform HTTP Post Environment Uri
        $GetEnvironment = "$($EnvironmentURL)/api/data/v9.0/deploymentpipelines" 

        # Declare Rest headers
        # Declare Rest headers
        $Headers = @{
            "Content-Type"  = "application/json"
            "Authorization" = "Bearer $($Token)"
        }
       <# $Headers = @{            
            "Authorization" = "Bearer $($Token)"
            "OData-MaxVersion" = 4.0
            "OData-Version" = 4.0
            "Accept" = "application/json"
            "Content-Type" = "application/json; charset=utf-8"
            "Prefer" = "odata.include-annotations='*',return=representation"
        } #>
        # Declaring the HTTP Post request
        $GetParameters = @{
            "Uri"         = "$($GetEnvironment)"
            "Method"      = "GET"
            "Headers"     = $headers
            "ContentType" = "application/json"
        }   
        try {
            $outputDeploymentPipelines = Invoke-RestMethod @GetParameters  
            return $outputDeploymentPipelines
       
        }
        catch {            
            Write-Error "Get Deployment Pipeline $($EnvironmentName) failed`r`n$_"               
        }          
}


#Get the Deployment Status Record
function New-GetDeploymentStageRecords {
    param (      
        [Parameter(Mandatory = $true)][string]$EnvironmentURL
    ) 
        # Code Begins    
        $Token = (Get-AzAccessToken -ResourceUrl $($EnvironmentURL)).Token  
        # Power Platform HTTP Post Environment Uri
        $GetEnvironment = "$($EnvironmentURL)/api/data/v9.0/deploymentstages" 

        # Declare Rest headers
        # Declare Rest headers
        $Headers = @{
            "Content-Type"  = "application/json"
            "Authorization" = "Bearer $($Token)"
        }
     
        # Declaring the HTTP Post request
        $GetParameters = @{
            "Uri"         = "$($GetEnvironment)"
            "Method"      = "GET"
            "Headers"     = $headers
            "ContentType" = "application/json"
        }   
        try {
            $outputDeploymentStages = Invoke-RestMethod @GetParameters  
            return $outputDeploymentStages
       
        }
        catch {            
            Write-Error "Get Deployment Stage $($EnvironmentName) failed`r`n$_"               
        }          
}

#Associate Deployment Envrionment (Development Type) with the Pipeline Record
#N:N Association
function New-AssociateDeploymentEnvironmentWithPipeline {
    param (      
        [Parameter(Mandatory = $true)][string]$DeploymentPipelineId,
        [Parameter(Mandatory = $true)][string]$DeploymentEnvrionmentId,
        [Parameter(Mandatory = $true)][string]$EnvironmentURL
    ) 
        # Code Begins
        # Get token to authenticate to Power Platform
        
        $Token = (Get-AzAccessToken -ResourceUrl $($EnvironmentURL)).Token
        # Power Platform HTTP Post Environment Uri
        $refVar = '$ref'
        $PostEnvironment = "$($EnvironmentURL)/api/data/v9.0/deploymentpipelines($DeploymentPipelineId)/deploymentpipeline_deploymentenvironment/$refVar"           
        
        $PostBody = @{
            "@odata.id" = "$($EnvironmentURL)/api/data/v9.0/deploymentenvironments($DeploymentEnvrionmentId)"
       }
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
            "Body"        = $postBody | ConvertTo-json -Depth 100
        }  
        try {
            Invoke-RestMethod @PostParameters  
            Write-Output "Association of Envrionment and Pipeline completed"
        }
        catch {            
            Write-Error "Association of Envrionment and Pipeline failed`r`n$_"               
        }          
}

#Create Deployment Stage records
function New-CreateDeploymentStages {
    param (      
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$DeploymentPipeline,
        [Parameter(Mandatory = $true)][string]$PreviousStage,
        [Parameter(Mandatory = $true)][string]$TargetDeploymentEnvironment,
        [Parameter(Mandatory = $true)][string]$EnvironmentURL
    ) 
        # Code Begins
        # Get token to authenticate to Power Platform
        # Power Platform HTTP Post Environment Uri
          $Token = (Get-AzAccessToken -ResourceUrl $($EnvironmentURL)).Token
           $PostEnvironment = "$($EnvironmentURL)/api/data/v9.0/deploymentstages"    
         
           $PostBody = @{
            "name" = "$($Name)"
            "targetdeploymentenvironmentid@odata.bind" = "/deploymentenvironments($TargetDeploymentEnvironment)"
            "deploymentpipelineid@odata.bind" = "/deploymentpipelines($DeploymentPipeline)"
            }
            if($PreviousStage -eq 'Null'){
                $PostBody = @{
                    "name" = "$($Name)"
                    "targetdeploymentenvironmentid@odata.bind" = "/deploymentenvironments($TargetDeploymentEnvironment)"
                    "deploymentpipelineid@odata.bind" = "/deploymentpipelines($DeploymentPipeline)"
                    }
            }
            else {
                $PostBody = @{
                    "name" = "$($Name)"
                    "targetdeploymentenvironmentid@odata.bind" = "/deploymentenvironments($TargetDeploymentEnvironment)"
                    "previousdeploymentstageid@odata.bind" = "/deploymentstages($PreviousStage)"
                    "deploymentpipelineid@odata.bind" = "/deploymentpipelines($DeploymentPipeline)"
                    }
            }

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
                "Body"        = $postBody | ConvertTo-json -Depth 100
            }  
            try {
                Invoke-RestMethod @PostParameters  
                Write-Output "Deployment Statge record created: $($Name)"
            }
            catch {            
                Write-Error "Deployment Statge record creation: $($Name) failed`r`n$_"               
            }           
}

function New-DLPAssignmentFromEnv {
    param (
        [Parameter(Mandatory = $true)][string[]]$Environments,
        [Parameter(Mandatory = $true)][string]$EnvironmentDLP
    )
    #DLP Template references
    $dlpPolicies = @{
        baseUri          = 'https://raw.githubusercontent.com/BogdanCiobanu1982/industry/main/foundations/powerPlatform/referenceImplementation/auxiliary/powerPlatform/'
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

#region create landing zones for citizen devs
if ($PPCitizen -in "yes") 
{   
    try {
        $envHt = @{            
            EnvNaming       = $PPCitizenNaming
            EnvRegion       = $PPCitizenRegion
            envLanguage     = $PPCitizenLanguage
            envCurrency     = $PPCitizenCurrency
            envDescription  = ''
            EnvALM          = $PPCitizenAlm -eq 'Yes'
            EnvDataverse    = $PPCitizen -eq 'Yes'            
        }
        $environmentsToCreate = New-EnvironmentCreationObject @envHt
    }
    catch {
        throw "Failed to create environment object. Input data is malformed. '`r`n$_'"
    }
    
    foreach ($environment in $environmentsToCreate) 
    {             
        try {
            $envCreationHt = @{
                Name               = $environment.envName
                Description        = $environment.envDescription
                Location           = $environment.envRegion
                Dataverse          = $true
                ManagedEnvironment = $PPCitizenManagedEnv -eq 'Yes'                
                LanguageName       = $environment.envLanguage
                Currency           = $environment.envCurrency
                SecurityGroupId    = $environment.envRbac
                EnvSku             = $environment.envSKu                                           
            }  

            Write-Output "Create Environment: $($envCreationHt.Name)" 
                                   
            # Get token to authenticate to Power Platform
            $Token = (Get-AzAccessToken).Token   

            # Power Platform API base Uri
            $BaseUri = "https://api.bap.microsoft.com"            
            
            # Power Plaform HTTP Get Environment Uri
            $GetEnvironment = '/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments?$expand=permissions&api-version=2016-11-01'
            
            # Power Platform HTTP Post Environment Uri
            $PostEnvironment = '/providers/Microsoft.BusinessAppPlatform/environments?api-version=2019-05-01&ud=/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments'
                       
            # Declare Rest headers
            $Headers = @{
                "Content-Type"  = "application/json"
                "Authorization" = "Bearer $($Token)"
            }
            
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
            
        # Declaring the HTTP Post request
            $PostBody = @{
                "properties" = @{
                    "linkedEnvironmentMetadata" = @{
                        "baseLanguage" = "$($envCreationHt.LanguageName)"
                        "domainName"   = "$($envCreationHt.Name)"
                        "templates"    =  $templates  
                        "securityGroupId" = "$($environment.envRbac)"
                    }                    
                    "databaseType"   = "CommonDataService"
                    "displayName"    = "$($envCreationHt.Name)"
                    "description"    = "$($envCreationHt.Description)"
                    "environmentSku" = "$($envCreationHt.EnvSku)"                                        
                }
                "location"          = "$($environment.envRegion)"                
            }
        
            $PostParameters = @{
                "Uri"         = "$($baseUri)$($postEnvironment)"
                "Method"      = "Post"
                "Headers"     = $headers
                "Body"        = $postBody | ConvertTo-json -Depth 100
                "ContentType" = "application/json"
            }            
        
            try {
                $response = Invoke-RestMethod @PostParameters   
                #Write-Host ($response | Format-List | Out-String)                            
            }
            catch {
                Write-Error "Creation of citizen Environment $($envCreationHt.Name) failed`r`n$_"
                throw "REST API call failed drastically"
            }                                                       
        }
        catch {
            Write-Warning "Failed to create citizen environment $($environment.envName)"
            Write-Output "Failed to create environment citizen.'`r`n$_'"  
        }
    }
    if ($PPCitizenDlp -eq "Yes") {
        New-DLPAssignmentFromEnv -Environments $environmentsToCreate.envName -EnvironmentDLP 'citizenDlpPolicy'
    }

    #region Install Power Platform Pipeline App in Admin Envrionemnt        
    Start-Sleep -Seconds 10         
    
    If($PPCitizenAlm -eq 'Yes'){
            try {                
                Write-Output "Admin: $envAdminName"  
                $adminEnvAttempts = 0
                do {
                    $adminEnvAttempts++
                    $adminEnvironment = Get-PowerOpsEnvironment | Where-Object { $_.Properties.displayName -eq $Global:envAdminName }                    
                    if ($null -eq $adminEnvironment.properties.linkedEnvironmentMetadata.instanceApiUrl -or 
                    $adminEnvironment.properties.linkedEnvironmentMetadata.instanceApiUrl -eq '' -or 
                    $adminEnvironment.properties.provisioningState -ne 'Succeeded' ) {                 
                        Start-Sleep -Seconds 15
                    }
                    else {
                        Write-Output "Admin Id: $($adminEnvironment.name)   attempt $($adminEnvAttempts)"  
                    }
                  } until ( ($null -ne $adminEnvironment.properties.linkedEnvironmentMetadata.instanceApiUrl -and $adminEnvironment.properties.provisioningState -eq 'Succeeded' ) -or $adminEnvAttempts -eq 20)
                  
                   if ($null -ne $adminEnvironment.properties.linkedEnvironmentMetadata.instanceApiUrl) {
                    New-InstallPackaggeToEnvironment -EnvironmentId $($adminEnvironment.name) -PackageName 'msdyn_AppDeploymentAnchor' -EnvironmentURL $($adminEnvironment.properties.linkedEnvironmentMetadata.instanceApiUrl)
                   }  
                   else {
                    Write-Output "Admin Environment is not ready or URL is empty"   
                   } 
                    
            }
            catch {
                Write-Warning "Error installing App`r`n$_"
            }
        }     
    #endregion Install Power Platform Pipeline App in Admin Envrionemnt   
}
#endregion create landing zones for citizen devs

$DeploymentScriptOutputs['Deployment'] = 'Successful'
