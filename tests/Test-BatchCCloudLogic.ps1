<#
.SYNOPSIS
    Runs C1 (Get-UserMailboxStatus.ps1) and C2 (Get-UserLicenseReport.ps1) against mocked
    Exchange Online and Microsoft Graph cmdlets, so their logic is tested without a tenant.

.DESCRIPTION
    Development-side check; never run on client machines. No network traffic: every Exchange
    and Graph cmdlet the scripts call is replaced by a stand-in function defined in a wrapper
    script (functions are found before cmdlets), and the real modules are never imported.

    Runs the scenarios below on whichever PowerShell runs it: Windows PowerShell 5.1 (the
    Windows path of both scripts) or PowerShell 7 (any platform), and checks the JSON results.
    Where PSScriptAnalyzer is installed it also checks that C1, C2 and this test use no syntax
    newer than 5.1.

      C2  Sign-in with exactly the three read-only scopes, device code, process-only token,
          disconnect at the end; subscriptions over-assigned / in grace; disabled account
          with licenses; user without licenses; stale sign-in; pending service plan; unknown
          user; friendly SKU names. Tenant without Entra ID P1 (sign-in SKIPPED, the rest
          still reported, never ERROR, with a plain-English reason naming Business Premium;
          also with -All). Existing connection with write scopes (used, not closed, noted).
          Not signed in and no terminal (SKIPPED, nothing connects).
      C1  A compromised-looking mailbox: full, no archive, litigation hold, recoverable items
          near full, external mailbox forwarding without a copy, a forwarding rule, a rule
          that hides mail, web access off, a quarantined phone, delegates (system entries left
          out). Connect loads only the read cmdlets. SKIPPED findings name the user / mailbox. A healthy mailbox on an existing
          connection. Unknown mailbox. Inbox rules refused by Exchange (rule checks SKIPPED,
          never PASS).

.EXAMPLE
    pwsh -NoProfile -File tests/Test-BatchCCloudLogic.ps1

.NOTES
    Risk Level    : Safe -- writes and removes files in a temporary folder only; no network
    Prerequisites : Windows PowerShell 5.1 or PowerShell 7 | Admin: No
    Exit code     : 0 all passed, 1 any failure
    Version       : 1.0.0
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPositionalParameters', '', Justification = 'Assert-Equal / Assert-True (Name, Expected, Actual) are one-line test assertions used throughout.')]
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
if (-not $here) { $here = Split-Path -Path $MyInvocation.MyCommand.Path -Parent }
$repo = (Resolve-Path -LiteralPath (Join-Path $here '..')).ProviderPath
$exe = (Get-Process -Id $PID).Path
$work = Join-Path ([System.IO.Path]::GetTempPath()) ('msp-batchc-{0}' -f [guid]::NewGuid().ToString('N').Substring(0, 8))
$null = New-Item -ItemType Directory -Path $work -Force
$c1 = 'cloud-services/m365/diagnostics/Get-UserMailboxStatus.ps1'
$c2 = 'cloud-services/m365/diagnostics/Get-UserLicenseReport.ps1'

$script:passed = 0
$script:failed = 0
function Assert-Equal {
    param([string]$Name, $Expected, $Actual)
    if ("$Expected" -ceq "$Actual") { $script:passed++ }
    else { $script:failed++; Write-Host ("FAIL: {0}`n  expected: [{1}]`n  actual:   [{2}]" -f $Name, $Expected, $Actual) -ForegroundColor Red }
}
function Assert-True {
    param([string]$Name, [bool]$Condition, [string]$Detail = '')
    if ($Condition) { $script:passed++ }
    else { $script:failed++; Write-Host ('FAIL: {0} {1}' -f $Name, $Detail) -ForegroundColor Red }
}

function Invoke-Mocked {
    <# Runs SCRIPT with MOCKS defined first; returns exit code, console, JSON result and the call log. #>
    param([string]$Name, [string]$Mocks, [string]$Script, [string[]]$ScriptArgs = @())
    $dir = Join-Path $work $Name
    $out = Join-Path $dir 'out'
    $null = New-Item -ItemType Directory -Path $out -Force
    $calls = Join-Path $dir 'calls.txt'
    $argText = ($ScriptArgs | ForEach-Object { if ($_ -like '-*') { $_ } else { "'{0}'" -f ($_ -replace "'", "''") } }) -join ' '
    $wrapper = Join-Path $dir 'run.ps1'
    $text = "`$env:MSP_TEST_CALLS = '{0}'`n{1}`n& '{2}' -OutputPath '{3}' {4}`nexit `$LASTEXITCODE`n" -f ($calls -replace "'", "''"), $Mocks, ((Join-Path $repo $Script) -replace "'", "''"), ($out -replace "'", "''"), $argText
    [System.IO.File]::WriteAllText($wrapper, $text, (New-Object System.Text.UTF8Encoding($true)))
    $console = & $exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $wrapper 2>&1 | Out-String
    $code = $LASTEXITCODE
    $json = @(Get-ChildItem -LiteralPath $out -Filter '*.json' -File)
    $result = $null
    if ($json.Count -gt 0) { $result = Get-Content -LiteralPath $json[0].FullName -Raw | ConvertFrom-Json }
    $log = @()
    if (Test-Path -LiteralPath $calls) { $log = @(Get-Content -LiteralPath $calls) }
    return [pscustomobject]@{ Code = $code; Console = $console; Result = $result; Calls = $log }
}
function Get-Finding {
    param($Run, [string]$Check, [string]$Target = '')
    if (-not $Run.Result) { return $null }
    return @($Run.Result.Findings | Where-Object { $_.Check -eq $Check -and (-not $Target -or $_.Target -eq $Target) }) | Select-Object -First 1
}
function Assert-Finding {
    <# The finding exists with STATUS and its detail matches PATTERN. #>
    param($Run, [string]$Label, [string]$Check, [string]$Status, [string]$Pattern = '', [string]$Target = '')
    $f = Get-Finding -Run $Run -Check $Check -Target $Target
    $ok = $f -and $f.Status -eq $Status -and (-not $Pattern -or [string]$f.Detail -match $Pattern)
    $got = 'missing'
    if ($f) { $got = '[{0}] {1}' -f $f.Status, $f.Detail }
    Assert-True $Label $ok $got
}

# --- Static check: no syntax newer than Windows PowerShell 5.1 ------------------------------
# The scenarios below run on whichever PowerShell runs this test (5.1 and 7 in the harness on
# Windows); this also catches 7-only syntax when the test runs on macOS/Linux.
if (Get-Command -Name Invoke-ScriptAnalyzer -ErrorAction SilentlyContinue) {
    $compat = @{ Rules = @{ PSUseCompatibleSyntax = @{ Enable = $true; TargetVersions = @('5.1', '7.0') } } }
    foreach ($s in $c1, $c2, 'tests/Test-BatchCCloudLogic.ps1') {
        $hits = @(Invoke-ScriptAnalyzer -Path (Join-Path $repo $s) -IncludeRule PSUseCompatibleSyntax -Settings $compat)
        Assert-True ('{0}: syntax works on 5.1 and 7' -f (Split-Path $s -Leaf)) ($hits.Count -eq 0) (($hits | ForEach-Object { '{0}: {1}' -f $_.Line, $_.Message }) -join '; ')
    }
}

# =========================================================================================
# C2 Microsoft Graph mocks. $global:GraphConnected / GraphScopes / NoPremium set the scene.
# =========================================================================================
$graphMocks = @'
function Write-Call { param([string]$Text) Add-Content -LiteralPath $env:MSP_TEST_CALLS -Value $Text }
function Get-MgContext {
    if (-not $global:GraphConnected) { return $null }
    return [pscustomobject]@{ Account = 'tech@contoso.com'; TenantId = '00000000-1111-2222-3333-444444444444'; Scopes = $global:GraphScopes }
}
function Connect-MgGraph {
    [CmdletBinding()]
    param([string[]]$Scopes, [switch]$UseDeviceCode, [switch]$NoWelcome, [string]$ContextScope)
    Write-Call ('Connect-MgGraph Scopes={0} DeviceCode={1} ContextScope={2}' -f ($Scopes -join ','), [bool]$UseDeviceCode, $ContextScope)
    $global:GraphConnected = $true
    $global:GraphScopes = $Scopes
}
function Disconnect-MgGraph { [CmdletBinding()] param() Write-Call 'Disconnect-MgGraph' }
$sku = @{ SPB = '11111111-0000-0000-0000-000000000001'; EXS = '11111111-0000-0000-0000-000000000002'; STD = '11111111-0000-0000-0000-000000000003' }
function Get-MgSubscribedSku {
    [CmdletBinding()] param([switch]$All)
    @(
        [pscustomobject]@{ SkuId = $sku.SPB; SkuPartNumber = 'SPB'; CapabilityStatus = 'Enabled'; ConsumedUnits = 12; PrepaidUnits = [pscustomobject]@{ Enabled = 10; Warning = 0; Suspended = 0 } },
        [pscustomobject]@{ SkuId = $sku.EXS; SkuPartNumber = 'EXCHANGESTANDARD'; CapabilityStatus = 'Warning'; ConsumedUnits = 2; PrepaidUnits = [pscustomobject]@{ Enabled = 0; Warning = 5; Suspended = 0 } },
        [pscustomobject]@{ SkuId = $sku.STD; SkuPartNumber = 'O365_BUSINESS_PREMIUM'; CapabilityStatus = 'Enabled'; ConsumedUnits = 3; PrepaidUnits = [pscustomobject]@{ Enabled = 5; Warning = 0; Suspended = 0 } }
    )
}
function New-FakeUser {
    param([string]$Upn, [bool]$Enabled, [string[]]$Skus, $SignIn)
    [pscustomobject]@{
        Id = 'id-' + $Upn; UserPrincipalName = $Upn; DisplayName = ($Upn -split '@')[0]; AccountEnabled = $Enabled; UserType = 'Member'
        CreatedDateTime = (Get-Date).AddDays(-400)
        AssignedLicenses = @($Skus | ForEach-Object { [pscustomobject]@{ SkuId = $sku[$_]; DisabledPlans = @() } })
        SignInActivity = $(if ($SignIn) { [pscustomobject]@{ LastSignInDateTime = $SignIn; LastSuccessfulSignInDateTime = $null } } else { $null })
    }
}
$fakeUsers = @{
    'alice@contoso.com' = (New-FakeUser 'alice@contoso.com' $true @('SPB') (Get-Date).AddDays(-5))
    'bob@contoso.com'   = (New-FakeUser 'bob@contoso.com' $false @('SPB', 'EXS') (Get-Date).AddDays(-40))
    'carol@contoso.com' = (New-FakeUser 'carol@contoso.com' $true @() (Get-Date).AddDays(-2))
    'dave@contoso.com'  = (New-FakeUser 'dave@contoso.com' $true @('STD') (Get-Date).AddDays(-200))
    'erin@contoso.com'  = (New-FakeUser 'erin@contoso.com' $true @('SPB') $null)
}
function Get-MgUser {
    [CmdletBinding()]
    param([string]$UserId, [switch]$All, [string]$Filter, [string]$ConsistencyLevel, [string]$CountVariable, [string[]]$Property)
    if ($global:NoPremium -and $Property -contains 'signInActivity') {
        throw 'Neither tenant is B2C or tenant doesn''t have premium license. Status: 403 (Forbidden) ErrorCode: Authentication_RequestFromNonPremiumTenantOrB2CTenant'
    }
    Write-Call ('Get-MgUser {0} {1}' -f $UserId, ($Property -join ','))
    if ($All) { return @($fakeUsers.Values | Where-Object { @($_.AssignedLicenses).Count -gt 0 }) }
    if (-not $fakeUsers.ContainsKey($UserId)) { throw ('[Request_ResourceNotFound] : Resource ''{0}'' does not exist or one of its queried reference-property objects are not present.' -f $UserId) }
    return $fakeUsers[$UserId]
}
function Get-MgUserLicenseDetail {
    [CmdletBinding()] param([string]$UserId, [switch]$All)
    $plans = @([pscustomobject]@{ ServicePlanName = 'EXCHANGE_S_STANDARD'; AppliesTo = 'User'; ProvisioningStatus = 'Success' },
        [pscustomobject]@{ ServicePlanName = 'TEAMS1'; AppliesTo = 'User'; ProvisioningStatus = 'Disabled' })
    if ($UserId -eq 'id-erin@contoso.com') { $plans += [pscustomobject]@{ ServicePlanName = 'INTUNE_A'; AppliesTo = 'User'; ProvisioningStatus = 'PendingInput' } }
    return [pscustomobject]@{ SkuPartNumber = 'SPB'; ServicePlans = $plans }
}
'@
$readScopes = "`$global:GraphScopes = @('User.Read.All', 'Organization.Read.All', 'AuditLog.Read.All')"

# --- C2: sign in with device code, five named users + one unknown --------------------------
$r = Invoke-Mocked 'c2-users' $graphMocks $c2 @('-UserPrincipalName', 'alice@contoso.com,bob@contoso.com,carol@contoso.com,dave@contoso.com,erin@contoso.com,ghost@contoso.com', '-DeviceCode')
Assert-Equal 'C2 users: exit 0' 0 $r.Code
Assert-True 'C2 users: JSON written' ($null -ne $r.Result) $r.Console
Assert-True 'C2: connects with exactly the three read scopes, device code, process-only token' (@($r.Calls | Where-Object { $_ -eq 'Connect-MgGraph Scopes=User.Read.All,Organization.Read.All,AuditLog.Read.All DeviceCode=True ContextScope=Process' }).Count -eq 1) ($r.Calls -join "`n")
Assert-True 'C2: disconnects the connection it opened' ($r.Calls -contains 'Disconnect-MgGraph')
Assert-Finding $r 'C2: over-assigned subscription' 'Subscription: SPB' 'WARN' '12 assigned but only 10 bought'
Assert-Finding $r 'C2: subscription in grace period' 'Subscription: EXCHANGESTANDARD' 'WARN' 'expired and is in its grace period'
Assert-Finding $r 'C2: Business Standard named correctly' 'Subscription: O365_BUSINESS_PREMIUM' 'INFO' 'Microsoft 365 Business Standard \(O365_BUSINESS_PREMIUM\)'
Assert-Finding $r 'C2: alice licensed' 'Licenses' 'INFO' 'Microsoft 365 Business Premium \(SPB\)' 'alice@contoso.com'
Assert-Finding $r 'C2: alice recent sign-in' 'Last sign-in' 'PASS' '5 days ago' 'alice@contoso.com'
Assert-Finding $r 'C2: alice plans fine, Teams switched off' 'Service plans' 'INFO' 'Switched off by an admin: SPB: TEAMS1' 'alice@contoso.com'
Assert-Finding $r 'C2: bob disabled with licenses' 'Account enabled' 'WARN' 'blocked but the account still holds 2 license' 'bob@contoso.com'
Assert-Finding $r 'C2: carol has no license' 'Licenses' 'WARN' 'No licenses assigned' 'carol@contoso.com'
Assert-Finding $r 'C2: dave stale' 'Last sign-in' 'WARN' '200 days ago' 'dave@contoso.com'
Assert-Finding $r 'C2: erin pending plan' 'Service plans' 'WARN' 'INTUNE_A \(PendingInput\)' 'erin@contoso.com'
Assert-Finding $r 'C2: erin never signed in' 'Last sign-in' 'INFO' 'No sign-in recorded' 'erin@contoso.com'
Assert-Finding $r 'C2: unknown user' 'User found' 'FAIL' 'No user ghost@contoso.com' 'ghost@contoso.com'
Assert-Equal 'C2: Users table' 5 @($r.Result.Data.Users).Count
Assert-True 'C2: no ERROR findings' (@($r.Result.Findings | Where-Object { $_.Status -eq 'ERROR' }).Count -eq 0) (($r.Result.Findings | Where-Object { $_.Status -eq 'ERROR' } | ForEach-Object { '{0}: {1}' -f $_.Check, $_.Detail }) -join '; ')
Assert-Equal 'C2: CheckId' 'C2' $r.Result.CheckId

# --- C2: tenant without Entra ID P1 ----------------------------------------------------------
$r = Invoke-Mocked 'c2-nopremium' ("{0}`n`$global:NoPremium = `$true`n`$global:GraphConnected = `$true`n{1}" -f $graphMocks, $readScopes) $c2 @('-UserPrincipalName', 'dave@contoso.com')
Assert-Equal 'C2 no P1: exit 0' 0 $r.Code
Assert-Finding $r 'C2 no P1: last sign-in SKIPPED with the reason' 'Last sign-in' 'SKIPPED' 'no Microsoft Entra ID P1 or P2 license.*Business Premium' 'dave@contoso.com'
Assert-True 'C2 no P1: no ERROR finding at all' (@($r.Result.Findings | Where-Object { $_.Status -eq 'ERROR' }).Count -eq 0) ((@($r.Result.Findings | Where-Object { $_.Status -eq 'ERROR' } | ForEach-Object { '{0}: {1}' -f $_.Check, $_.Detail })) -join '; ')
Assert-True 'C2 no P1: users still read' (@($r.Result.Findings | Where-Object { $_.Check -eq 'Users read' -and $_.Status -eq 'INFO' }).Count -eq 1)

# --- C2: tenant without Entra ID P1, -All ------------------------------------------------------
$r = Invoke-Mocked 'c2-nopremium-all' ("{0}`n`$global:NoPremium = `$true`n`$global:GraphConnected = `$true`n{1}" -f $graphMocks, $readScopes) $c2 @('-All')
Assert-Equal 'C2 no P1 -All: exit 0' 0 $r.Code
Assert-Equal 'C2 no P1 -All: one SKIPPED last sign-in per licensed user' 4 @($r.Result.Findings | Where-Object { $_.Check -eq 'Last sign-in' -and $_.Status -eq 'SKIPPED' -and $_.Target -like '*@contoso.com' }).Count
Assert-True 'C2 no P1 -All: no ERROR finding' (@($r.Result.Findings | Where-Object { $_.Status -eq 'ERROR' }).Count -eq 0)
Assert-Finding $r 'C2 no P1: licenses still reported' 'Licenses' 'INFO' 'Business Standard' 'dave@contoso.com'
Assert-True 'C2 no P1: existing connection not closed' ($r.Calls -notcontains 'Disconnect-MgGraph')

# --- C2: existing connection with write scopes, -All ----------------------------------------
$r = Invoke-Mocked 'c2-existing' ("{0}`n`$global:GraphConnected = `$true`n`$global:GraphScopes = @('User.ReadWrite.All', 'Organization.Read.All', 'AuditLog.Read.All')" -f $graphMocks) $c2 @('-All', '-IncludeServicePlans')
Assert-Equal 'C2 existing: exit 0' 0 $r.Code
Assert-True 'C2 existing: no new sign-in' (@($r.Calls | Where-Object { $_ -like 'Connect-MgGraph*' }).Count -eq 0)
Assert-Finding $r 'C2 existing: write scopes noted' 'Graph connection' 'INFO' 'also allows changes; this script only reads'
Assert-Finding $r 'C2 existing: missing User.Read.All named' 'Graph scopes' 'WARN' 'missing User\.Read\.All'
Assert-Equal 'C2 -All: only licensed users' 4 @($r.Result.Data.Users).Count
Assert-True 'C2 -IncludeServicePlans: ServicePlans table' (@($r.Result.Data.ServicePlans).Count -ge 8)

# --- C2: not signed in, no terminal, no -DeviceCode -----------------------------------------
$r = Invoke-Mocked 'c2-noninteractive' $graphMocks $c2 @('-UserPrincipalName', 'alice@contoso.com')
Assert-Equal 'C2 non-interactive: exit 1' 1 $r.Code
Assert-Finding $r 'C2 non-interactive: SKIPPED with how to sign in' 'Graph connection' 'SKIPPED' 'cannot show a sign-in window'
Assert-True 'C2 non-interactive: never connects' (@($r.Calls | Where-Object { $_ -like 'Connect-MgGraph*' }).Count -eq 0)

# =========================================================================================
# C1 Exchange Online mocks. $global:Exo* variables set the scene.
# =========================================================================================
$exoMocks = @'
function Write-Call { param([string]$Text) Add-Content -LiteralPath $env:MSP_TEST_CALLS -Value $Text }
function Get-ConnectionInformation {
    [CmdletBinding()] param()
    if ($global:ExoConnected) { return [pscustomobject]@{ State = 'Connected'; UserPrincipalName = 'tech@contoso.com'; TenantID = '00000000-1111-2222-3333-444444444444' } }
}
function Connect-ExchangeOnline {
    [CmdletBinding()]
    param([switch]$ShowBanner, [string[]]$CommandName, [switch]$SkipLoadingFormatData, [switch]$Device)
    Write-Call ('Connect-ExchangeOnline CommandName={0} Device={1}' -f ($CommandName -join ','), [bool]$Device)
    $global:ExoConnected = $true
}
function Disconnect-ExchangeOnline { [CmdletBinding()] param([switch]$Confirm) Write-Call 'Disconnect-ExchangeOnline' }
function Get-AcceptedDomain { [CmdletBinding()] param() @([pscustomobject]@{ DomainName = 'contoso.com' }, [pscustomobject]@{ DomainName = 'contoso.onmicrosoft.com' }) }
function Get-EXOMailbox {
    [CmdletBinding()] param([string]$Identity, [string[]]$Properties)
    if ($Identity -like 'ghost*') { throw ('The operation couldn''t be performed because object ''{0}'' couldn''t be found on ''EURP.PROD.OUTLOOK.COM''.' -f $Identity) }
    return $global:ExoMailbox
}
function Get-EXOMailboxStatistics {
    [CmdletBinding()] param([string]$Identity, [switch]$Archive, [string[]]$Properties)
    if ($Archive) { return [pscustomobject]@{ TotalItemSize = '2.1 GB (2,254,857,830 bytes)'; ItemCount = 9000 } }
    return $global:ExoStats
}
function Get-InboxRule {
    [CmdletBinding()] param([string]$Mailbox)
    if ($global:ExoDenyRules) { throw 'Access is denied. The user does not have permission to run Get-InboxRule.' }
    return $global:ExoRules
}
function Get-MailboxAutoReplyConfiguration { [CmdletBinding()] param([string]$Identity) return $global:ExoAuto }
function Get-EXOCasMailbox { [CmdletBinding()] param([string]$Identity, [string[]]$Properties) return $global:ExoCas }
function Get-EXOMobileDeviceStatistics { [CmdletBinding()] param([string]$Mailbox) return $global:ExoDevices }
function Get-EXOMailboxPermission { [CmdletBinding()] param([string]$Identity) return $global:ExoPerms }
function Get-EXORecipientPermission { [CmdletBinding()] param([string]$Identity) return $global:ExoSendAs }
'@
$exoBad = @'
$global:ExoMailbox = [pscustomobject]@{
    RecipientTypeDetails = 'UserMailbox'; AccountDisabled = $false
    ProhibitSendQuota = '49.5 GB (53,150,220,288 bytes)'; ProhibitSendReceiveQuota = '50 GB (53,687,091,200 bytes)'; IssueWarningQuota = '49 GB (52,613,349,376 bytes)'
    RecoverableItemsQuota = '30 GB (32,212,254,720 bytes)'; ArchiveStatus = 'None'; ArchiveGuid = '00000000-0000-0000-0000-000000000000'; AutoExpandingArchiveEnabled = $false
    LitigationHoldEnabled = $true; LitigationHoldDate = (Get-Date '2026-01-15'); InPlaceHolds = @(); ComplianceTagHoldApplied = $false; DelayHoldApplied = $false; RetentionHoldEnabled = $false
    ForwardingAddress = $null; ForwardingSmtpAddress = 'smtp:mallory.backup@gmail.com'; DeliverToMailboxAndForward = $false; GrantSendOnBehalfTo = @('Carol Assistant')
}
$global:ExoStats = [pscustomobject]@{ TotalItemSize = '49.6 GB (53,257,594,470 bytes)'; TotalDeletedItemSize = '28.5 GB (30,601,641,984 bytes)'; ItemCount = 120000; LastLogonTime = (Get-Date).AddHours(-2) }
$global:ExoRules = @(
    [pscustomobject]@{ Name = 'Sync'; Enabled = $true; ForwardTo = @('"Ext" [SMTP:collect@proton.me]'); ForwardAsAttachmentTo = $null; RedirectTo = $null; DeleteMessage = $false; MoveToFolder = $null; MarkAsRead = $false; Description = 'forward' },
    [pscustomobject]@{ Name = '.'; Enabled = $true; ForwardTo = $null; ForwardAsAttachmentTo = $null; RedirectTo = $null; DeleteMessage = $false; MoveToFolder = 'alice:\RSS Feeds'; MarkAsRead = $true; Description = 'hide' },
    [pscustomobject]@{ Name = 'Newsletters'; Enabled = $true; ForwardTo = $null; ForwardAsAttachmentTo = $null; RedirectTo = $null; DeleteMessage = $false; MoveToFolder = 'alice:\Newsletters'; MarkAsRead = $false; Description = 'move' }
)
$global:ExoAuto = [pscustomobject]@{ AutoReplyState = 'Enabled'; ExternalAudience = 'All'; StartTime = $null; EndTime = $null }
$global:ExoCas = [pscustomobject]@{ MAPIEnabled = $true; OWAEnabled = $false; ActiveSyncEnabled = $true; EwsEnabled = $true; PopEnabled = $false; ImapEnabled = $false }
$global:ExoDevices = @([pscustomobject]@{ DeviceManufacturer = 'Apple'; DeviceModel = 'iPhone15,2'; DeviceOS = 'iOS 18.1'; ClientType = 'Outlook'; DeviceAccessState = 'Quarantined'; LastSuccessSync = (Get-Date).AddDays(-1) })
$global:ExoPerms = @(
    [pscustomobject]@{ User = 'NT AUTHORITY\SELF'; AccessRights = @('FullAccess', 'ReadPermission'); IsInherited = $false; Deny = $false },
    [pscustomobject]@{ User = 'bob@contoso.com'; AccessRights = @('FullAccess'); IsInherited = $false; Deny = $false }
)
$global:ExoSendAs = @(
    [pscustomobject]@{ Trustee = 'NT AUTHORITY\SELF'; AccessRights = @('SendAs'); IsInherited = $false },
    [pscustomobject]@{ Trustee = 'mallory@contoso.com'; AccessRights = @('SendAs'); IsInherited = $false }
)
'@
$exoGood = @'
$global:ExoConnected = $true
$global:ExoMailbox = [pscustomobject]@{
    RecipientTypeDetails = 'UserMailbox'; AccountDisabled = $false
    ProhibitSendQuota = '99 GB (106,300,440,576 bytes)'; ProhibitSendReceiveQuota = '100 GB (107,374,182,400 bytes)'; IssueWarningQuota = '98 GB (105,226,698,752 bytes)'
    RecoverableItemsQuota = '30 GB (32,212,254,720 bytes)'; ArchiveStatus = 'Active'; ArchiveGuid = '5b7c0000-0000-0000-0000-000000000001'; AutoExpandingArchiveEnabled = $true
    LitigationHoldEnabled = $false; InPlaceHolds = @(); ComplianceTagHoldApplied = $false; DelayHoldApplied = $false; RetentionHoldEnabled = $false
    ForwardingAddress = $null; ForwardingSmtpAddress = $null; DeliverToMailboxAndForward = $false; GrantSendOnBehalfTo = @()
}
$global:ExoStats = [pscustomobject]@{ TotalItemSize = '12.3 GB (13,207,024,435 bytes)'; TotalDeletedItemSize = '310 MB (325,058,560 bytes)'; ItemCount = 40000; LastLogonTime = (Get-Date).AddHours(-1) }
$global:ExoRules = @()
$global:ExoAuto = [pscustomobject]@{ AutoReplyState = 'Disabled' }
$global:ExoCas = [pscustomobject]@{ MAPIEnabled = $true; OWAEnabled = $true; ActiveSyncEnabled = $true; EwsEnabled = $true; PopEnabled = $false; ImapEnabled = $false }
$global:ExoDevices = @()
$global:ExoPerms = @([pscustomobject]@{ User = 'NT AUTHORITY\SELF'; AccessRights = @('FullAccess'); IsInherited = $false; Deny = $false })
$global:ExoSendAs = @()
'@

# --- C1: compromised-looking mailbox, sign-in with device code ------------------------------
$r = Invoke-Mocked 'c1-bad' ("{0}`n{1}" -f $exoMocks, $exoBad) $c1 @('-UserPrincipalName', 'alice@contoso.com', '-DeviceCode')
Assert-Equal 'C1 bad: exit 0' 0 $r.Code
Assert-True 'C1 bad: JSON written' ($null -ne $r.Result) $r.Console
Assert-True 'C1: connect loads only the read cmdlets, device code' (@($r.Calls | Where-Object { $_ -eq 'Connect-ExchangeOnline CommandName=Get-InboxRule,Get-MailboxAutoReplyConfiguration,Get-AcceptedDomain Device=True' }).Count -eq 1) ($r.Calls -join "`n")
Assert-True 'C1: disconnects the connection it opened' ($r.Calls -contains 'Disconnect-ExchangeOnline')
Assert-Finding $r 'C1: full mailbox FAIL' 'Mailbox size' 'FAIL' 'cannot send'
Assert-Finding $r 'C1: no archive while nearly full' 'Archive' 'WARN' 'No archive mailbox'
Assert-Finding $r 'C1: litigation hold listed' 'Holds' 'INFO' 'litigation hold since 2026-01-15'
Assert-Finding $r 'C1: recoverable items near full' 'Recoverable items' 'WARN' '95 %'
Assert-True 'C1: recoverable items advice respects the hold' ([string](Get-Finding $r 'Recoverable items').Recommendation -match 'legal hold')
Assert-Finding $r 'C1: external forwarding, no copy' 'Mailbox forwarding' 'WARN' 'mallory\.backup@gmail\.com \(NO copy.*outside the organization'
Assert-Finding $r 'C1: forwarding rule' 'Forwarding rules' 'WARN' '"Sync" -> .*collect@proton\.me.*outside the organization'
Assert-Finding $r 'C1: hiding rule' 'Rules that hide mail' 'WARN' '"\." moves to .*RSS Feeds and marks read'
Assert-True 'C1: normal move rule not flagged' ([string](Get-Finding $r 'Rules that hide mail').Detail -notmatch 'Newsletters')
Assert-Finding $r 'C1: auto-reply' 'Auto-reply' 'INFO' 'Enabled; outside senders: All'
Assert-Finding $r 'C1: web access off' 'Mail apps' 'WARN' 'Switched off: Outlook on the web'
Assert-Finding $r 'C1: quarantined phone' 'Mobile devices' 'WARN' 'Apple iPhone15,2 \(Quarantined\)'
Assert-Finding $r 'C1: delegates without SELF' 'Delegates' 'INFO' '^bob@contoso\.com \(Full Access\); mallory@contoso\.com \(Send As\); Carol Assistant \(Send on Behalf\)\.'
Assert-Equal 'C1: InboxRules table' 3 @($r.Result.Data.InboxRules).Count
Assert-True 'C1 bad: no ERROR findings' (@($r.Result.Findings | Where-Object { $_.Status -eq 'ERROR' }).Count -eq 0) (($r.Result.Findings | Where-Object { $_.Status -eq 'ERROR' } | ForEach-Object { '{0}: {1}' -f $_.Check, $_.Detail }) -join '; ')

# --- C1: healthy mailbox on an existing connection ------------------------------------------
$r = Invoke-Mocked 'c1-good' ("{0}`n{1}" -f $exoMocks, $exoGood) $c1 @('-UserPrincipalName', 'alice@contoso.com')
Assert-Equal 'C1 good: exit 0' 0 $r.Code
Assert-True 'C1 good: no new connection, none closed' ($r.Calls.Count -eq 0) ($r.Calls -join "`n")
Assert-Finding $r 'C1 good: size' 'Mailbox size' 'PASS' '12\.3 GB of 99\.0 GB'
Assert-Finding $r 'C1 good: archive' 'Archive' 'INFO' 'auto-expanding: 2\.1 GB'
foreach ($check in 'Holds', 'Recoverable items', 'Mailbox forwarding', 'Forwarding rules', 'Rules that hide mail', 'Mail apps', 'Delegates') {
    Assert-Finding $r ('C1 good: {0} PASS' -f $check) $check 'PASS'
}
Assert-True 'C1 good: no WARN or FAIL' (@($r.Result.Findings | Where-Object { $_.Status -in 'WARN', 'FAIL', 'ERROR' }).Count -eq 0) (($r.Result.Findings | Where-Object { $_.Status -in 'WARN', 'FAIL', 'ERROR' } | ForEach-Object { '{0}: {1}' -f $_.Check, $_.Detail }) -join '; ')

# --- C1: unknown mailbox ---------------------------------------------------------------------
$r = Invoke-Mocked 'c1-ghost' ("{0}`n{1}" -f $exoMocks, $exoGood) $c1 @('-UserPrincipalName', 'ghost@contoso.com')
Assert-Equal 'C1 unknown: exit 0' 0 $r.Code
Assert-Finding $r 'C1 unknown: FAIL with the address' 'Mailbox' 'FAIL' 'No mailbox ghost@contoso\.com'
Assert-True 'C1 unknown: no further checks' ($null -eq (Get-Finding $r 'Mailbox size'))

# --- C1: inbox rules refused ------------------------------------------------------------------
$r = Invoke-Mocked 'c1-denied' ("{0}`n{1}`n`$global:ExoDenyRules = `$true" -f $exoMocks, $exoGood) $c1 @('-UserPrincipalName', 'alice@contoso.com')
Assert-Finding $r 'C1 denied: inbox rules SKIPPED with the role' 'Inbox rules' 'SKIPPED' 'may not read this' 'alice@contoso.com'
Assert-True 'C1 denied: role named' ([string](Get-Finding $r 'Inbox rules').Recommendation -match 'Global Reader')
Assert-Finding $r 'C1 denied: forwarding rules SKIPPED, not PASS' 'Forwarding rules' 'SKIPPED'
Assert-Finding $r 'C1 denied: hiding rules SKIPPED, not PASS' 'Rules that hide mail' 'SKIPPED'

# --- C1: not connected, no terminal -----------------------------------------------------------
$r = Invoke-Mocked 'c1-noninteractive' $exoMocks $c1 @('-UserPrincipalName', 'alice@contoso.com')
Assert-Equal 'C1 non-interactive: exit 1' 1 $r.Code
Assert-Finding $r 'C1 non-interactive: SKIPPED' 'Exchange connection' 'SKIPPED' 'cannot show a sign-in window'
Assert-True 'C1 non-interactive: never connects' ($r.Calls.Count -eq 0)

if (-not $env:MSP_KEEP) { Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue }
Write-Host ('{0} passed, {1} failed (PowerShell {2})' -f $script:passed, $script:failed, $PSVersionTable.PSVersion)
if ($script:failed -gt 0) { exit 1 }
exit 0
