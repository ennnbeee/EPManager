<#PSScriptInfo

.VERSION 0.6
.GUID dda70c3d-e3c9-44cb-9acf-6e452e36d9d5
.AUTHOR Nick Benton
.COMPANYNAME odds+endpoints
.COPYRIGHT GPL
.TAGS Graph Intune Windows
.LICENSEURI https://github.com/ennnbeee/EPManager/blob/main/LICENSE
.PROJECTURI https://github.com/ennnbeee/EPManager
.ICONURI
.EXTERNALMODULEDEPENDENCIES Microsoft.Graph.Authentication
.REQUIREDSCRIPTS
.EXTERNALSCRIPTDEPENDENCIES
.RELEASENOTES
v0.1 - Initial release
v0.2 - Updated logic
v0.3 - Improved Functions and information.
v0.3.1 - Resolved parameter issues
v0.3.2 - Updated to allow for multiple rules of the same file
v0.3.3 - Updated policy naming, introduced rule count limit, updated validation
v0.4 - Improved validation of report data
v0.4.1 - Parameter requirements
v0.5 - Updated functions to use Export Jobs instead of Graph Calls for elevation reports
v0.6 - Updated to include Deny rules

.PRIVATEDATA
#>
<#
.SYNOPSIS
EPManager - Export elevation data from Intune and import to create EPM Rule policies.

.DESCRIPTION
Used to export elevation requests reporting to Intune to CSV, allowing to modify the CSV file to create EPM rule policies and assign based on provided groups.

.PARAMETER tenantId
Provide the Id of the tenant to connect to.

.PARAMETER appId
Provide the Id of the Entra App registration to be used for authentication.

.PARAMETER appSecret
Provide the App secret to allow for authentication to graph

.PARAMETER report
Generates and downloads EPM report details to a CSV file in the same folder as the script.

.PARAMETER import
Allows the import of new rules based on the report following modification to the CSV file.

.PARAMETER importPath
Only used with import, path to the amended exported EPM rules

.PARAMETER assign
Only used with import, used assign profiles after creating them.

.PARAMETER elevationMode
The type of elevation to report upon, selection from the following:
All, Unmanaged, Automatic, UserConfirmed, SupportApproved

.PARAMETER whatIf
Switch to enable WhatIf mode to simulate changes.

.EXAMPLE
PS> .\EPManager.ps1 -tenantId 36019fe7-a342-4d98-9126-1b6f94904ac7 -report

.EXAMPLE
PS> .\EPManager.ps1 -tenantId 36019fe7-a342-4d98-9126-1b6f94904ac7 -import -importPath "EPM-Report-20250321-105116.csv"

.EXAMPLE
PS> .\EPManager.ps1 -tenantId 36019fe7-a342-4d98-9126-1b6f94904ac7 -import -importPath "EPM-Report-20250321-105116.csv" -assign

.NOTES
Version:        0.5
Author:         Nick Benton
WWW:            oddsandendpoints.co.uk
Creation Date:  11/06/2025

#>

[CmdletBinding()]
param(

    [Parameter(HelpMessage = 'Generates and downloads EPM report details')]
    [switch]$report,

    [Parameter(HelpMessage = 'Allows the import of new rules based on the report')]
    [switch]$import,

    [Parameter(HelpMessage = 'Path to the report file used for importing new rules')]
    [String]$importFile,

    [Parameter(HelpMessage = 'Whether to assign the create rule policies to the provided groups')]
    [switch]$assign,

    [ValidateSet('All', 'Unmanaged', 'Automatic', 'UserConfirmed', 'SupportApproved')]
    [String]$elevationMode = 'All',

    [ValidateSet('Hash')]
    [string]$elevationGrouping = 'Hash',

    [Parameter(HelpMessage = 'WhatIf mode to simulate changes')]
    [switch]$whatIf,

    [Parameter(HelpMessage = 'Provide the Id of the Entra ID tenant to connect to')]
    [ValidateLength(36, 36)]
    [String]$tenantId,

    [Parameter(HelpMessage = 'Provide the Id of the Entra App registration to be used for authentication')]
    [ValidateLength(36, 36)]
    [String]$appId,

    [Parameter(HelpMessage = 'Provide the App secret to allow for authentication to graph')]
    [ValidateNotNullOrEmpty()]
    [String]$appSecret

)

if ($report -and $import) {
    Write-Host ''
    Write-Host "Please select only 'report' or 'import' when running the script." -ForegroundColor Yellow
    Write-Host ''
    break
}

#region Functions
Function Connect-ToGraph {
    <#
.SYNOPSIS
Authenticates to the Graph API via the Microsoft.Graph.Authentication module.

.DESCRIPTION
The Connect-ToGraph cmdlet is a wrapper cmdlet that helps authenticate to the Intune Graph API using the Microsoft.Graph.Authentication module. It leverages an Azure AD app ID and app secret for authentication or user-based auth.

.PARAMETER Tenant
Specifies the tenant (e.g. contoso.onmicrosoft.com) to which to authenticate.

.PARAMETER AppId
Specifies the Azure AD app ID (GUID) for the application that will be used to authenticate.

.PARAMETER AppSecret
Specifies the Azure AD app secret corresponding to the app ID that will be used to authenticate.

.PARAMETER Scopes
Specifies the user scopes for interactive authentication.

.EXAMPLE
Connect-ToGraph -tenantId $tenantId -appId $app -appSecret $secret

-#>
    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory = $false)] [string]$tenantId,
        [Parameter(Mandatory = $false)] [string]$appId,
        [Parameter(Mandatory = $false)] [string]$appSecret,
        [Parameter(Mandatory = $false)] [string[]]$scopes
    )

    Process {
        #Import-Module Microsoft.Graph.Authentication
        $version = (Get-Module microsoft.graph.authentication | Select-Object -ExpandProperty Version).major

        if ($AppId -ne '') {
            $body = @{
                grant_type    = 'client_credentials';
                client_id     = $appId;
                client_secret = $appSecret;
                scope         = 'https://graph.microsoft.com/.default';
            }

            $response = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" -Body $body
            $accessToken = $response.access_token

            if ($version -eq 2) {
                Write-Host 'Version 2 module detected'
                $accessTokenFinal = ConvertTo-SecureString -String $accessToken -AsPlainText -Force
            }
            else {
                Write-Host 'Version 1 Module Detected'
                Select-MgProfile -Name Beta
                $accessTokenFinal = $accessToken
            }
            $graph = Connect-MgGraph -AccessToken $accessTokenFinal
            Write-Host "Connected to Intune tenant $TenantId using app-based authentication (Azure AD authentication not supported)"
        }
        else {
            if ($version -eq 2) {
                Write-Host 'Version 2 module detected'
            }
            else {
                Write-Host 'Version 1 Module Detected'
                Select-MgProfile -Name Beta
            }
            $graph = Connect-MgGraph -Scopes $scopes -TenantId $tenantId
            Write-Host "Connected to Intune tenant $($graph.TenantId)"
        }
    }
}
Function Test-JSONData() {

    param (
        $JSON
    )

    try {
        $TestJSON = ConvertFrom-Json $JSON -ErrorAction Stop
        $TestJSON | Out-Null
        $validJson = $true
    }
    catch {
        $validJson = $false
        $_.Exception
    }
    if (!$validJson) {
        Write-Host "Provided JSON isn't in valid JSON format" -f Red
        break
    }

}
Function Get-DeviceEPMElevations() {

    [cmdletbinding()]

    param (

        [Parameter(Mandatory = $false)]
        [ValidateSet('All', 'Unmanaged', 'Automatic', 'UserConfirmed', 'SupportApproved')]
        [String]$type

    )

    $graphApiVersion = 'beta'
    $Resource = 'deviceManagement/privilegeManagementElevations'

    try {

        switch ($type) {
            'All' { $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)" }
            'Unmanaged' { $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?filter=(elevationType eq 'unmanagedElevation')" }
            'Automatic' { $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?filter=(elevationType eq 'zeroTouchElevation')" }
            'UserConfirmed' { $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?filter=(elevationType eq 'userConfirmedElevation')" }
            'SupportApproved' { $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)?filter=(elevationType eq 'supportApprovedElevation')" }
            Default { $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)" }
        }

        $graphResults = Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject

        $results = @()
        $results += $graphResults.value

        $pages = $graphResults.'@odata.nextLink'
        while ($null -ne $pages) {

            $additional = Invoke-MgGraphRequest -Uri $pages -Method Get -OutputType PSObject

            if ($pages) {
                $pages = $additional.'@odata.nextLink'
            }
            $results += $additional.value
        }
        $results

    }
    catch {
        Write-Error $_.Exception.Message
        break
    }
}
Function New-DeviceEPMReport() {

    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'low')]

    param (

        [Parameter(Mandatory = $false)]
        [ValidateSet('All', 'Unmanaged', 'Automatic', 'UserConfirmed', 'SupportApproved')]
        [String]$type

    )

    $graphApiVersion = 'beta'
    $Resource = 'deviceManagement/reports/exportJobs'

    switch ($type) {
        'All' { $reportFilter = $null }
        'Unmanaged' { $reportFilter = "(ElevationType eq 'UnmanagedElevation')" }
        'Automatic' { $reportFilter = "(ElevationType eq 'zeroTouchElevation')" }
        'UserConfirmed' { $reportFilter = "(ElevationType eq 'userConfirmedElevation')" }
        'SupportApproved' { $reportFilter = "(ElevationType eq 'supportApprovedElevation')" }
        Default { $reportFilter = $null }
    }

    $JSON = @"
{
    "reportName":"EpmElevationReportElevationEvent",
    "filter": "$reportFilter",
    "select":[

    ],
    "format":"csv",
    "snapshotId":null
}
"@

    if ($PSCmdlet.ShouldProcess('Creating new Elevation Report')) {
        try {
            Test-JSONData -Json $JSON
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            Invoke-MgGraphRequest -Uri $uri -Method Post -Body $JSON -ContentType 'application/json'
        }
        catch {
            Write-Error $_.Exception.Message
            break
        }
    }
    elseif ($WhatIfPreference.IsPresent) {
        Write-Output 'Elevation Report would have been created'
    }
    else {
        Write-Output 'Elevation Report was not created'
    }
}
Function Get-DeviceEPMReport() {

    [CmdletBinding()]

    param (

        [parameter(Mandatory = $true)]
        $Id

    )

    $graphApiVersion = 'beta'
    $Resource = "deviceManagement/reports/exportJobs('$Id')"

    try {

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"

        Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject

    }
    catch {
        Write-Error $_.Exception.Message
        break
    }
}
Function Get-IntuneGroup() {

    [cmdletbinding()]

    param
    (
        [parameter(Mandatory = $true)]
        [string]$name
    )

    $graphApiVersion = 'beta'
    $Resource = 'groups'

    try {

        $searchTerm = 'search="displayName:' + $name + '"'
        $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource`?$searchTerm"
        (Invoke-MgGraphRequest -Headers @{ConsistencyLevel = 'eventual' } -Uri $uri -Method Get -OutputType PSObject).Value

    }
    catch {
        Write-Error $_.Exception.Message
        break
    }
}
Function Get-DeviceSettingsCatalog() {

    [cmdletbinding()]

    param (

        [Parameter(Mandatory = $false)]
        [string]$name,

        [Parameter(Mandatory = $false)]
        [string]$Id,

        [Parameter(Mandatory = $false)]
        [switch]$EPM

    )

    $graphApiVersion = 'beta'
    $Resource = "deviceManagement/configurationPolicies?`$filter=technologies has 'mdm'"

    try {
        if ($EPM) {
            $Resource = "deviceManagement/configurationPolicies?`$filter=templateReference/TemplateFamily eq 'endpointSecurityEndpointPrivilegeManagement'"
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
        }
        if ($Id) {
            $uri = "https://graph.microsoft.com/$graphApiVersion/$Resource/$Id"
            Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject
        }
        elseif ($name) {
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value | Where-Object { ($_.Name).contains("$name") }
        }
        Else {
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            (Invoke-MgGraphRequest -Uri $uri -Method Get -OutputType PSObject).Value
        }
    }
    catch {
        Write-Error $_.Exception.Message
        break
    }
}
Function New-DeviceSettingsCatalog() {

    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'low')]

    param
    (
        [parameter(Mandatory = $true)]
        $JSON
    )

    $graphApiVersion = 'Beta'
    $Resource = 'deviceManagement/configurationPolicies'
    if ($PSCmdlet.ShouldProcess('Creating new Device Settings Catalog')) {
        try {
            Test-JSONData -Json $JSON
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            Invoke-MgGraphRequest -Uri $uri -Method Post -Body $JSON -ContentType 'application/json'
        }
        catch {
            Write-Error $_.Exception.Message
            break
        }
    }
    elseif ($WhatIfPreference.IsPresent) {
        Write-Output 'Setting Catalog policy would have been created'
    }
    else {
        Write-Output 'Setting Catalog was not created'
    }

}
Function Add-DeviceSettingsCatalogAssignment() {

    [cmdletbinding()]

    param
    (
        [parameter(Mandatory = $true)]
        [string]$Id,

        [parameter(Mandatory = $false)]
        [string]$name,

        [parameter(Mandatory = $true)]
        [string]$groupId,

        [parameter(Mandatory = $true)]
        [ValidateSet('Include', 'Exclude')]
        [string]$assignmentType
    )

    $graphApiVersion = 'Beta'
    $Resource = "deviceManagement/configurationPolicies/$Id/assign"

    try {
        $TargetGroup = New-Object -TypeName psobject

        if ($assignmentType -eq 'Exclude') {
            $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.exclusionGroupAssignmentTarget'
        }
        elseif ($assignmentType -eq 'Include') {
            $TargetGroup | Add-Member -MemberType NoteProperty -Name '@odata.type' -Value '#microsoft.graph.groupAssignmentTarget'
        }

        $TargetGroup | Add-Member -MemberType NoteProperty -Name 'groupId' -Value "$groupId"

        $Target = New-Object -TypeName psobject
        $Target | Add-Member -MemberType NoteProperty -Name 'target' -Value $TargetGroup
        $TargetGroups = $Target

        # Creating JSON object to pass to Graph
        $Output = New-Object -TypeName psobject
        $Output | Add-Member -MemberType NoteProperty -Name 'assignments' -Value @($TargetGroups)
        $JSON = $Output | ConvertTo-Json -Depth 3

        # POST to Graph Service
        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-MgGraphRequest -Uri $uri -Method Post -Body $JSON -ContentType 'application/json'
    }
    catch {
        Write-Error $_.Exception.Message
        break
    }
}
Function Get-TenantDetail() {

    [cmdletbinding()]

    param
    (

    )

    $graphApiVersion = 'Beta'
    $Resource = 'organization'

    try {

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        (Invoke-MgGraphRequest -Uri $uri -Method GET -OutputType PSObject).value
    }
    catch {
        Write-Error $_.Exception.Message
        break
    }
}
#endregion Functions

#region intro
Write-Host '
 _______ ______ _______
|    ___|   __ \   |   |.---.-.-----.---.-.-----.-----.----.
|    ___|    __/       ||  _  |     |  _  |  _  |  -__|   _|
|_______|___|  |__|_|__||___._|__|__|___._|___  |_____|__|
                                          |_____|
' -ForegroundColor Red

Write-Host 'EPManager - Export elevation data from Intune and import to create EPM Rule policies.' -ForegroundColor Green
Write-Host 'Nick Benton - oddsandendpoints.co.uk' -NoNewline;
Write-Host ' | Version' -NoNewline; Write-Host ' 0.6 Public Preview' -ForegroundColor Yellow -NoNewline
Write-Host ' | Last updated: ' -NoNewline; Write-Host '2025-06-11' -ForegroundColor Magenta
Write-Host ''
Write-Host 'If you have any feedback, please open an issue at https://github.com/ennnbeee/EndpointPrivilegeManager/issues' -ForegroundColor Cyan
Write-Host ''
#endregion intro

#region variables
$rndWait = Get-Random -Minimum 1 -Maximum 3
$date = (Get-Date -Format 'yyyyMMdd-HHmmss').ToString()
$requiredScopes = @('Group.Read.All', 'DeviceManagementConfiguration.ReadWrite.All', 'Organization.Read.All', 'DeviceManagementConfiguration.Read.All', 'DeviceManagementManagedDevices.Read.All')
#$requiredScopes = @('Group.Read.All', 'DeviceManagementConfiguration.ReadWrite.All', 'DeviceManagementManagedDevices.Read.All')
[String[]]$scopes = $requiredScopes -join ', '
$elevationTypes = @('Automatic', 'UserAuthentication', 'UserJustification', 'SupportApproved', 'Deny')
$childProcessBehaviours = @('AllowAll', 'RequireRule', 'DenyAll', 'NotConfigured')
#endregion variables

#region module check
$modules = @('Microsoft.Graph.Authentication')
foreach ($module in $modules) {
    Write-Host "Checking for $module PowerShell module..." -ForegroundColor Cyan
    Write-Host ''
    If (!(Get-Module -Name $module -ListAvailable)) {
        Install-Module -Name $module -Scope CurrentUser -AllowClobber
    }
    Write-Host "PowerShell Module $module found." -ForegroundColor Green
    Write-Host ''
    Import-Module -Name $module -Force
}
#endregion module check

#region app auth
try {
    if (!$tenantId) {
        Write-Host 'Connecting using interactive authentication' -ForegroundColor Yellow
        Connect-MgGraph -Scopes $scopes -NoWelcome -ErrorAction Stop
    }
    else {
        if ((!$appId -and !$appSecret) -or ($appId -and !$appSecret) -or (!$appId -and $appSecret)) {
            Write-Host 'Missing App Details, connecting using user authentication' -ForegroundColor Yellow
            Connect-ToGraph -tenantId $tenantId -Scopes $scopes -ErrorAction Stop
        }
        else {
            Write-Host 'Connecting using App authentication' -ForegroundColor Yellow
            Connect-ToGraph -tenantId $tenantId -appId $appId -appSecret $appSecret -ErrorAction Stop
        }
    }
    $context = Get-MgContext
    $tenantName = ((Get-TenantDetail).verifiedDomains | Where-Object { $_.isInitial -eq $true }).name
    Write-Host ''
    Write-Host "Successfully connected to Microsoft Graph tenant $tenantName with ID $($context.TenantId)." -ForegroundColor Green
}
catch {
    Write-Error $_.Exception.Message
    Exit
}
#endregion app auth

#region scopes
$currentScopes = $context.Scopes
# Validate required permissions
$missingScopes = $requiredScopes | Where-Object { $_ -notin $currentScopes }
if ($missingScopes.Count -gt 0) {
    Write-Host 'WARNING: The following scope permissions are missing:' -ForegroundColor Red
    $missingScopes | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
    Write-Host ''
    Write-Host 'Please ensure these permissions are granted to the app registration for full functionality.' -ForegroundColor Yellow
    exit
}
Write-Host ''
Write-Host 'All required scope permissions are present.' -ForegroundColor Green
#endregion scopes

#region Report
if ($report) {

    $csvFile = ".\EPManager-Report-$date.csv"

    switch ($elevationGrouping) {
        'Hash' { $grouping = 'hash' }
        'User' { $grouping = 'upn' }
        'Device' { $grouping = 'deviceName' }
        Default { $grouping = 'hash' }
    }

    $epmReport = @()
    #$elevations = Get-DeviceEPMElevations -type $elevationMode

    $elevationReport = New-DeviceEPMReport -type $elevationMode
    While ((Get-DeviceEPMReport -Id $elevationReport.id).status -ne 'completed') {
        Write-Host 'Waiting for the Elevation Update report to finish processing...' -ForegroundColor Cyan
        Start-Sleep -Seconds $rndWait
    }

    Write-Host "EPM report for $elevationMode elevations completed processing." -ForegroundColor Green
    Write-Host
    Write-Host 'Getting EPM Report data...' -ForegroundColor Magenta
    Write-Host

    $csvUrl = (Get-DeviceEPMReport -Id $elevationReport.id).url
    $csvHeader = @{Accept = '*/*'; 'accept-encoding' = 'gzip, deflate, br, zstd' }
    Add-Type -AssemblyName System.IO.Compression
    $csvReportStream = Invoke-WebRequest -Uri $csvURL -Method Get -Headers $csvHeader -UseBasicParsing -ErrorAction Stop -Verbose
    $csvReportZip = [System.IO.Compression.ZipArchive]::new([System.IO.MemoryStream]::new($csvReportStream.Content))
    $csvReportElevations = [System.IO.StreamReader]::new($csvReportZip.GetEntry($csvReportZip.Entries[0]).open()).ReadToEnd() | ConvertFrom-Csv



    if ($csvReportElevations.count -eq 0) {
        Write-Host ''
        Write-Host "No elevations with mode $elevationMode found in Intune." -ForegroundColor Red
        Write-Host ''
        Break
    }
    Write-Host ''
    Write-Host "Found $($csvReportElevations.count) $elevationMode elevation(s) in Intune." -ForegroundColor Cyan
    Write-Host ''

    $groupedElevations = $csvReportElevations | Group-Object -Property $grouping

    foreach ($groupedElevation in $groupedElevations) {

        $elevationGroups = $groupedElevation.Group
        $users = @()
        $devices = @()

        foreach ($elevationGroup in $elevationGroups) {
            $fileName = $elevationGroup.filePath | Split-Path -Leaf
            $fileInternalName = $elevationGroup.internalName
            $fileCompany = $elevationGroup.companyName
            $fileProduct = $elevationGroup.productName
            $fileDescription = $elevationGroup.fileDescription
            $fileHash = $elevationGroup.hash
            $filePath = ($elevationGroup.filePath | Split-Path) -replace '\\', '\\'
            $fileVersion = $elevationGroup.fileVersion
            $users += $elevationGroup.upn
            $devices += $elevationGroup.deviceName
        }

        $Data = [PSCustomObject]@{
            ElevationCount        = $groupedElevation.Count
            Product               = $fileProduct
            Description           = $fileDescription
            Publisher             = $fileCompany
            FileName              = $fileName
            FileInternalName      = $fileInternalName
            FileVersion           = $fileVersion
            FilePath              = $filePath
            FileHash              = $fileHash
            Users                 = (($users | Get-Unique) -join ' ' | Out-String).Trim()
            Devices               = (($devices | Get-Unique) -join ' ' | Out-String).Trim()
            ElevationType         = $($elevationTypes -join '/')
            ChildProcessBehaviour = $($childProcessBehaviours -join '/')
            Group                 = 'AssignmentGroupName'
        }

        $epmReport += $Data
    }

    # CSV Report
    $epmReport | Sort-Object ElevationCount -Descending | Export-Csv -Path $csvFile -NoTypeInformation
    Write-Host ''
    Write-Host "EPM Activity report exported to $csvFile" -ForegroundColor Green
    Write-Host ''
    Write-Host "Before running the script with the '-import' switch, update the exported file with the rules to be created." -ForegroundColor Cyan
    Write-Host ''
}
#endregion Report

#region Import
if ($import) {

    while (!(Test-Path "$importFile")) {
        Write-Host ''
        Write-Host "Unable to find provided import file $importFile" -ForegroundColor yellow
        Write-Host ''
        $importFile = Read-Host -Prompt 'Please specify a valid path to EPM data CSV to e.g., C:\Temp\EPM_Data.csv'
    }
    $importedPolicies = Import-Csv -Path $importFile | Group-Object -Property Group

    #region Validation
    Write-Host 'Beginning validation of the imported policies.' -ForegroundColor Cyan
    Write-Host ''
    $validationCount = 0

    #elevation types
    if ($($importedPolicies.Group.ElevationType).Where{ $_ -notin $elevationTypes }) {
        Write-Host 'Rule policy elevation types are incorrect, please review.' -ForegroundColor Yellow
        Write-Host ''
        $validationCount++
    }
    #child process behaviour
    if ($($importedPolicies.Group.ChildProcessBehaviour).Where{ $_ -notin $childProcessBehaviours }) {
        Write-Host 'Rule policy child process behaviours are incorrect, please review.' -ForegroundColor Yellow
        Write-Host ''
        $validationCount++
    }
    #FileName invalid characters
    $fileNameIssues = $importedPolicies.Group.FileName -notmatch '^$|^[^<\/*?\"\"\\\\>:|]+\.[a-zA-Z0-9]{2,4}$'
    if ($fileNameIssues.Count -gt 0) {
        Write-Host 'Rule policy FileNames contain invalid characters or are incorrectly formatted, please review.' -ForegroundColor Yellow
        Write-Host ''
        foreach ($fileNameIssue in $fileNameIssues) {
            Write-Host $fileNameIssue -ForegroundColor White
        }
        Write-Host ''
        $validationCount++
    }
    #filePath invalid characters
    $filePathIssues = $importedPolicies.Group.filePath -notmatch '^$|(([a-zA-Z]:)(\\[ \w\\.()!#$%&''()+-.]*|[!#$%&''()+-.]|\\?|\\%[ \w\\.()]+%+)+|%[ \w\\.()]+%(\\[ \w\\.()]*|\\?|\\%[ \w\\.()]+%+)*)$'
    if ($filePathIssues.Count -gt 0) {
        Write-Host 'Rule policy filePaths contain invalid characters, please review.' -ForegroundColor Yellow
        Write-Host ''
        foreach ($filePathIssue in $filePathIssues) {
            Write-Host $filePathIssue -ForegroundColor white
        }
        Write-Host ''
        $validationCount++
    }
    #FileInternalName too short or long
    $fileInternNameIssues = ($importedPolicies.Group.FileInternalName | ForEach-Object { $_.Length })
    if ($fileInternNameIssues -lt 3) {
        Write-Host 'Rule policy FileInternalNames are shorter than 3 characters, please review.' -ForegroundColor Yellow
        Write-Host ''
        $validationCount++
    }
    #fileDescription too short or long
    $descriptionIssues = ($importedPolicies.Group.Description | ForEach-Object { $_.Length })
    if ($descriptionIssues -lt 3) {
        Write-Host 'Rule policy Descriptions are shorter than 3 characters, please review.' -ForegroundColor Yellow
        Write-Host ''
        $validationCount++
    }
    #fileDescription too short or long
    $productIssues = ($importedPolicies.Group.Product | ForEach-Object { $_.Length })
    if ($productIssues -lt 3) {
        Write-Host 'Rule policy Products are shorter than 3 characters, please review.' -ForegroundColor Yellow
        Write-Host ''
        $validationCount++
    }
    #group issues
    if ($assign) {
        $assignmentGroups = $importedPolicies.Name
        foreach ($assignmentGroup in $assignmentGroups) {
            if ($null -eq (Get-IntuneGroup -Name $assignmentGroup)) {
                Write-Host "Rule policy group $assignmentGroup cannot be found in Entra ID, please review." -ForegroundColor Yellow
                Write-Host ''
                $validationCount++
            }
        }
    }

    if ($validationCount -gt 0) {
        Write-Host 'Review and remediate the reported issues with the import file.' -ForegroundColor Red
        Write-Host ''
        Break
    }
    else {
        Write-Host 'Validation complete, creating EPM Rule Policies.' -ForegroundColor Green
        Write-Host ''
    }


    #endregion Validation

    #region rule split
    $intunePolicies = @()
    $counter = [pscustomobject] @{ Value = 0 }
    $groupSize = 50
    foreach ($importedPolicy in $importedPolicies) {

        if ($importedPolicy.count -gt $groupSize) {
            $importedPolicySubSets = $importedPolicy.Group | Group-Object -Property { [math]::Floor($counter.Value++ / $groupSize) }
            foreach ($importedPolicySubSet in $importedPolicySubSets) {
                $intunePolicies += [pscustomobject]@{Name = $($importedPolicy.Name + '-' + $importedPolicySubSet.Name); Group = $importedPolicySubSet.Group }
            }
        }
        else {
            $intunePolicies += [pscustomobject]@{Name = $importedPolicy.Name; Group = $importedPolicy.Group }
        }
    }
    #endregion rule split

    #region Create Policies
    foreach ($intunePolicy in $intunePolicies) {

        $rules = $intunePolicy.Group
        $JSONRules = @()
        $policyName = "EPManager created policy for $($intunePolicy.Name)"
        $policyDescription = "EPManager created policy for $($intunePolicy.Name) created on $date"

        $JSONPolicyStart = @"
{
    "description": "$policyDescription",
    "name": "$policyName",
    "platforms": "windows10",
    "settings": [
        {
            "settingInstance": {
                "@odata.type": "#microsoft.graph.deviceManagementConfigurationGroupSettingCollectionInstance",
                "settingDefinitionId": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}",
                "settingInstanceTemplateReference": {
                    "settingInstanceTemplateId": "ee3d2e5f-6b3d-4cb1-af9b-37b02d3dbae2"
                },
                "groupSettingCollectionValue": [

"@
        $JSONPolicyEnd = @'
                ]
            }
        }
    ],
    "technologies": "endpointPrivilegeManagement",
    "templateReference": {
        "templateId": "cff02aad-51b1-498d-83ad-81161a393f56_1"
    }
}
'@
        foreach ($rule in $rules) {
            $ruleName = "$($rule.FileName)-$($rule.FileHash)"
            $fileName = $rule.FileName -replace '^(.{50}).*', '$1'
            $fileInternalName = $rule.FileInternalName -replace '^(.{50}).*', '$1'
            $filePath = $rule.FilePath
            $fileHash = $rule.FileHash
            $elevationType = $rule.ElevationType
            $childProcess = $rule.ChildProcessBehaviour
            $fileProduct = $($rule.Product -replace '[^\x30-\x39\x41-\x5A\x61-\x7A]+', ' ') -replace '^(.{50}).*', '$1'
            $fileDescription = $rule.Description -replace '^(.{50}).*', '$1'
            $ruleDescription = $($rule.Publisher + ' ' + $rule.Description) -replace '[^\x30-\x39\x41-\x5A\x61-\x7A]+', ' '

            # First Rule needs TemplateIDs in the JSON
            if ($rule -eq $rules[0]) {

                $JSONRuleStart = @"
                    {
                        "settingValueTemplateReference": null,
                        "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_appliesto",
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "0cde1c42-c701-44b1-94b7-438dd4536128"
                            },
                            "choiceSettingValue": {
                                "value": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_allusers",
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "2ec26569-c08f-434c-af3d-a50ac4a1ce26",
                                    "useTemplateDefault": false
                                },
                                "children": []
                            }
                        },
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_description",
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "b3714f3a-ead8-4682-a16f-ffa264c9d58f"
                            },
                            "simpleSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
                                "value": "$ruleDescription",
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "5e82a1e9-ef4f-43ea-8031-93aace2ad14d",
                                    "useTemplateDefault": false
                                }
                            }
                        },
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_productname",
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "234631a1-aeb1-436f-9e05-dcd9489caf08"
                            },
                            "simpleSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
                                "value": "$fileProduct",
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "e466f96d-0633-40b3-86a4-9e093b696077",
                                    "useTemplateDefault": false
                                }
                            }
                        },
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_internalname",
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "08511f12-25b5-4218-812c-39a2db444ef1"
                            },
                            "simpleSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
                                "value": "$fileInternalName",
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "ec295dd4-6bbc-4fa8-a503-960784c53f41",
                                    "useTemplateDefault": false
                                }
                            }
                        },
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_filehash",
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "e4436e2c-1584-4fba-8e38-78737cbbbfdf"
                            },
                            "simpleSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
                                "value": "$fileHash",
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "1adcc6f7-9fa4-4ce3-8941-2ce22cf5e404",
                                    "useTemplateDefault": false
                                }
                            }
                        },

"@

                switch ($elevationType) {
                    'Automatic' {
                        $JSONRuleElevation = @'
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "children": [],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "cb2ea689-ebc3-42ea-a7a4-c704bb13e3ad"
                                },
                                "value": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_automatic"
                            },
                            "settingDefinitionId": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_ruletype",
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "bc5a31ac-95b5-4ec6-be1f-50a384bb165f"
                            }
                        },

'@
                    }
                    'UserAuthentication' {
                        $JSONRuleElevation = @'
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "children": [
                                    {
                                        "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingCollectionInstance",
                                        "choiceSettingCollectionValue": [
                                            {
                                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                                "children": [],
                                                "value": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_ruletype_validation_1"
                                            }
                                        ],
                                        "settingDefinitionId": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_ruletype_validation"
                                    }
                                ],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "cb2ea689-ebc3-42ea-a7a4-c704bb13e3ad"
                                },
                                "value": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_self"
                            },
                            "settingDefinitionId": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_ruletype",
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "bc5a31ac-95b5-4ec6-be1f-50a384bb165f"
                            }
                        },

'@
                    }
                    'UserJustification' {
                        $JSONRuleElevation = @'
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "children": [
                                    {
                                        "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingCollectionInstance",
                                        "choiceSettingCollectionValue": [
                                            {
                                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                                "children": [],
                                                "value": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_ruletype_validation_0"
                                            }
                                        ],
                                        "settingDefinitionId": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_ruletype_validation"
                                    }
                                ],
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "cb2ea689-ebc3-42ea-a7a4-c704bb13e3ad"
                                },
                                "value": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_self"
                            },
                            "settingDefinitionId": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_ruletype",
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "bc5a31ac-95b5-4ec6-be1f-50a384bb165f"
                            }
                        },

'@
                    }
                    'SupportApproved' {
                        $JSONRuleElevation = @'
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_ruletype",
                            "choiceSettingValue":
                                {
                                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                    "value": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_supportarbitrated",
                                    "children": [],
                                    "settingValueTemplateReference":
                                    {
                                        "settingValueTemplateId": "cb2ea689-ebc3-42ea-a7a4-c704bb13e3ad",
                                    },
                                },
                            "settingInstanceTemplateReference":
                                {
                                    "settingInstanceTemplateId": "bc5a31ac-95b5-4ec6-be1f-50a384bb165f",
                                },
                        },

'@
                    }
                    'Deny' {
                        $JSONRuleElevation = @'
                            {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                                "settingDefinitionId": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_ruletype",
                                "choiceSettingValue": {
                                    "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                    "value": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_deny",
                                    "children": [],
                                    "settingValueTemplateReference": {
                                        "settingValueTemplateId": "cb2ea689-ebc3-42ea-a7a4-c704bb13e3ad"
                                    }
                                },
                                "settingInstanceTemplateReference": {
                                    "settingInstanceTemplateId": "bc5a31ac-95b5-4ec6-be1f-50a384bb165f"
                                }
                            },

'@
                    }

                }



                $JSONRuleEnd = @"
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_filedescription",
                            "settingInstanceTemplateReference": {
                            "settingInstanceTemplateId": "5e10c5a9-d3ca-4684-b425-e52238cf3c8b"
                            },
                            "simpleSettingValue": {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
                            "value": "$fileDescription",
                            "settingValueTemplateReference": {
                                "settingValueTemplateId": "df3081ea-4ea7-4f34-ac87-49b2e84d4c4b",
                                "useTemplateDefault": false
                            }
                            }
                        },
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_name",
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "fdabfcf9-afa4-4dbf-a4ef-d5c1549065e1"
                            },
                            "simpleSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
                                "value": "$ruleName",
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "03f003e5-43ef-4e7e-bf30-57f00781fdcc",
                                    "useTemplateDefault": false
                                }
                            }
                        },
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_filename",
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "0c1ceb2b-bbd4-46d4-9ba5-9ee7abe1f094"
                            },
                            "simpleSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
                                "value": "$fileName",
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "a165327c-f0e5-4c7d-9af1-d856b02191f7",
                                    "useTemplateDefault": false
                                }
                            }
                        },
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_filepath",
                            "settingInstanceTemplateReference": {
                                "settingInstanceTemplateId": "c3b7fda4-db6a-421d-bf04-d485e9d0cfb1"
                            },
                            "simpleSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
                                "value": "$filePath",
                                "settingValueTemplateReference": {
                                    "settingValueTemplateId": "f011bcfc-03cd-4b28-a1f4-305278d7a030",
                                    "useTemplateDefault": false
                                }
                            }
                        }
                    ]

"@

            }

            # Additional Rules has different JSON format with no TemplateID
            else {

                $JSONRuleStart = @"
                {
                    "settingValueTemplateReference": null,
                    "children": [
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_appliesto",
                            "settingInstanceTemplateReference": null,
                            "choiceSettingValue": {
                            "settingValueTemplateReference": null,
                            "value": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_allusers",
                            "children": []
                            }
                        },
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_description",
                            "settingInstanceTemplateReference": null,
                            "simpleSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
                                "settingValueTemplateReference": null,
                                "value": "$ruleDescription"
                            }
                        },
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_productname",
                            "settingInstanceTemplateReference": null,
                            "simpleSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
                                "settingValueTemplateReference": null,
                                "value": "$fileProduct"
                            }
                        },
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_internalname",
                            "settingInstanceTemplateReference": null,
                            "simpleSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
                                "settingValueTemplateReference": null,
                                "value": "$fileInternalName"
                            }
                        },
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_filehash",
                            "settingInstanceTemplateReference": null,
                            "simpleSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
                                "settingValueTemplateReference": null,
                                "value": "$fileHash"
                            }
                    },

"@

                switch ($elevationType) {
                    'Automatic' {
                        $JSONRuleElevation = @'
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_ruletype",
                            "settingInstanceTemplateReference": null,
                            "choiceSettingValue": {
                                "settingValueTemplateReference": null,
                                "value": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_automatic",
                            "children": []
                            }
                        },

'@
                    }
                    'UserAuthentication' {
                        $JSONRuleElevation = @'
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_ruletype",
                            "settingInstanceTemplateReference": null,
                            "choiceSettingValue": {
                            "settingValueTemplateReference": null,
                            "value": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_self",
                            "children": [
                                {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingCollectionInstance",
                                "settingDefinitionId": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_ruletype_validation",
                                "settingInstanceTemplateReference": null,
                                "choiceSettingCollectionValue": [
                                    {
                                    "settingValueTemplateReference": null,
                                    "value": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_ruletype_validation_1",
                                    "children": []
                                    }
                                ]
                                }
                            ]
                            }
                        },

'@
                    }
                    'UserJustification' {
                        $JSONRuleElevation = @'
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_ruletype",
                            "settingInstanceTemplateReference": null,
                            "choiceSettingValue": {
                            "settingValueTemplateReference": null,
                            "value": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_self",
                            "children": [
                                {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingCollectionInstance",
                                "settingDefinitionId": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_ruletype_validation",
                                "settingInstanceTemplateReference": null,
                                "choiceSettingCollectionValue": [
                                    {
                                    "settingValueTemplateReference": null,
                                    "value": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_ruletype_validation_0",
                                    "children": []
                                    }
                                ]
                                }
                            ]
                            }
                        },

'@
                    }
                    'SupportApproved' {
                        $JSONRuleElevation = @'
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_ruletype",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_supportarbitrated",
                                "children": []
                            }
                        },

'@
                    }
                    'Deny' {
                        $JSONRuleElevation = @'
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_ruletype",
                            "choiceSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                                "value": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_deny",
                                "children": []
                            }
                        },

'@
                    }
                }

                $JSONRuleEnd = @"
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_filedescription",
                            "settingInstanceTemplateReference": null,
                            "simpleSettingValue": {
                                "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
                                "settingValueTemplateReference": null,
                                "value": "$fileDescription"
                            }
                        },
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_name",
                            "settingInstanceTemplateReference": null,
                            "simpleSettingValue": {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
                            "settingValueTemplateReference": null,
                            "value": "$ruleName"
                            }
                        },
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_filename",
                            "settingInstanceTemplateReference": null,
                            "simpleSettingValue": {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
                            "settingValueTemplateReference": null,
                            "value": "$fileName"
                            }
                        },
                        {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance",
                            "settingDefinitionId": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_filepath",
                            "settingInstanceTemplateReference": null,
                            "simpleSettingValue": {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
                            "settingValueTemplateReference": null,
                            "value": "$filePath"
                            }
                        }
                    ]

"@

            }

            # Child Process behaviour is the same across all rules
            switch ($childProcess) {
                'AllowAll' {
                    $JSONRuleChild = @'
                    {
                        "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                        "settingDefinitionId": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_childprocessbehavior",
                        "choiceSettingValue": {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                            "value": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_allowrunelevated",
                            "children": []
                        }
                    },

'@
                }
                'RequireRule' {
                    $JSONRuleChild = @'
                    {
                        "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                        "settingDefinitionId": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_childprocessbehavior",
                        "choiceSettingValue": {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                            "value": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_allowrunelevatedrulerequired",
                            "children": []
                        }
                    },

'@
                }
                'DenyAll' {
                    $JSONRuleChild = @'
                    {
                        "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance",
                        "settingDefinitionId": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_childprocessbehavior",
                        "choiceSettingValue": {
                            "@odata.type": "#microsoft.graph.deviceManagementConfigurationChoiceSettingValue",
                            "value": "device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_deny",
                            "children": []
                        }
                    },

'@
                }
                'NotConfigured' {
                    $JSONRuleChild = @'
'@
                }
            }

            # Last rule in the set
            if ($rule -eq $rules[-1]) {
                $JSONRuleEnding = @'
                }
'@
            }
            # Not last rule in the set
            else {
                $JSONRuleEnding = @'
                },

'@
            }

            # Combines the rule
            $JSONRule = $JSONRuleStart + $JSONRuleElevation + $JSONRuleChild + $JSONRuleEnd + $JSONRuleEnding

            # Adds the rule to the set of rules
            $JSONRules += $JSONRule
        }

        # Combines all JSON ready to push to Graph
        $JSONOutput = $JSONPolicyStart + $JSONRules + $JSONPolicyEnd

        if ($whatIf) {
            Write-Host ''
            Write-Host 'WhatIf mode enabled, no changes will be made.' -ForegroundColor Magenta
            $JSONOutput > "$policyName.json"
            Write-Host "EPM Policy exported to $policyName.json" -ForegroundColor Cyan

        }
        else {
            if ($null -ne (Get-DeviceSettingsCatalog -EPM | Where-Object { $_.Name -eq $policyName })) {
                Write-Host "EPM policy '$policyName' already exists in Intune." -ForegroundColor Cyan
                Write-Host ''
            }
            else {
                $EPMPolicy = New-DeviceSettingsCatalog -JSON $JSONOutput
                Write-Host "EPM policy '$policyName' created in Intune." -ForegroundColor Green
                Write-Host ''
            }

            if ($assign) {
                $group = Get-IntuneGroup -Name $intunePolicy.Name
                Add-DeviceSettingsCatalogAssignment -Id $EPMPolicy.id -groupId $group.id -assignmentType Include -name $EPMPolicy.name
                Write-Host ''
                Write-Host "Successfully assigned Elevation Rules Policy to $($group.displayname)" -ForegroundColor Green
                Write-Host ''
            }
        }
    }
    #endregion Create Policies
}
#endregion Import