<#
.SYNOPSIS
    Runs C4 (Get-M365SecurityPosture.ps1) against mocked Microsoft Graph and Exchange Online
    cmdlets, so its logic is tested without a tenant.

.DESCRIPTION
    Development-side check; never run on client machines. No network traffic: every Graph and
    Exchange cmdlet the script calls is replaced by a stand-in function defined in a wrapper
    script (functions are found before cmdlets). Each run also records the loaded modules, and
    the test fails if a real Microsoft.Graph or ExchangeOnlineManagement module was imported.

    Runs on whichever PowerShell runs it (Windows PowerShell 5.1 or PowerShell 7) and checks the
    JSON results. Where PSScriptAnalyzer is installed it also checks that C4 and this test use no
    syntax newer than 5.1.

      Risky tenant     Sign-in with exactly the five read-only scopes, device code, process-only
                       token; Exchange loads only its read cmdlets; both connections closed.
                       Admin and user without MFA; CA without MFA for all users; legacy block only
                       in report-only; a successful IMAP sign-in; 5 Global Admins; an admin with a
                       mailbox; outbound forwarding On; external mailbox forwarding; an external
                       redirect rule (internal ones ignored); inactive and never-used guests;
                       mailbox auditing off; Secure Score with the top actions.
      No Entra ID P1   Existing connections (no new sign-in, none closed); security defaults on;
                       MFA, legacy sign-ins and inactive guests SKIPPED with the P1 reason, never
                       ERROR; guests still counted; everything else PASS.
      Neither          No P1 and security defaults off: FAIL High; legacy not blocked.
      Role too narrow  Admin roles and Secure Score refused: SKIPPED naming Global Reader.
      Missing scope    Existing Graph connection without SecurityEvents.Read.All: Secure Score
                       SKIPPED naming the scope.
      -SkipExchange    No Exchange sign-in; Exchange checks SKIPPED; Graph checks still run.
      No terminal      Not signed in anywhere and no -DeviceCode: SKIPPED, exit 1, nothing connects.

.EXAMPLE
    pwsh -NoProfile -File tests/Test-M365SecurityPostureLogic.ps1

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
$work = Join-Path ([System.IO.Path]::GetTempPath()) ('msp-c4-{0}' -f [guid]::NewGuid().ToString('N').Substring(0, 8))
$null = New-Item -ItemType Directory -Path $work -Force
$c4 = 'cloud-services/m365/audit/Get-M365SecurityPosture.ps1'

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
    <# Runs C4 with MOCKS defined first; returns exit code, console, JSON result, call log and loaded modules. #>
    param([string]$Name, [string]$Mocks, [string[]]$ScriptArgs = @())
    $dir = Join-Path $work $Name
    $out = Join-Path $dir 'out'
    $null = New-Item -ItemType Directory -Path $out -Force
    $calls = Join-Path $dir 'calls.txt'
    $modules = Join-Path $dir 'modules.txt'
    $argText = ($ScriptArgs | ForEach-Object { if ($_ -like '-*') { $_ } else { "'{0}'" -f ($_ -replace "'", "''") } }) -join ' '
    $wrapper = Join-Path $dir 'run.ps1'
    $text = "`$env:MSP_TEST_CALLS = '{0}'`n{1}`n& '{2}' -OutputPath '{3}' {4}`n`$code = `$LASTEXITCODE`nGet-Module | ForEach-Object {{ `$_.Name }} | Set-Content -LiteralPath '{5}'`nexit `$code`n" -f `
    ($calls -replace "'", "''"), $Mocks, ((Join-Path $repo $c4) -replace "'", "''"), ($out -replace "'", "''"), $argText, ($modules -replace "'", "''")
    [System.IO.File]::WriteAllText($wrapper, $text, (New-Object System.Text.UTF8Encoding($true)))
    $console = & $exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $wrapper 2>&1 | Out-String
    $code = $LASTEXITCODE
    $json = @(Get-ChildItem -LiteralPath $out -Filter '*.json' -File)
    $result = $null
    if ($json.Count -gt 0) { $result = Get-Content -LiteralPath $json[0].FullName -Raw | ConvertFrom-Json }
    $log = @()
    if (Test-Path -LiteralPath $calls) { $log = @(Get-Content -LiteralPath $calls) }
    $loaded = @()
    if (Test-Path -LiteralPath $modules) { $loaded = @(Get-Content -LiteralPath $modules) }
    return [pscustomobject]@{ Code = $code; Console = $console; Result = $result; Calls = $log; Modules = $loaded }
}
function Get-Finding {
    param($Run, [string]$Check)
    if (-not $Run.Result) { return $null }
    return @($Run.Result.Findings | Where-Object { $_.Check -eq $Check }) | Select-Object -First 1
}
function Assert-Finding {
    <# The finding exists with STATUS (and SEVERITY) and its detail matches PATTERN. #>
    param($Run, [string]$Label, [string]$Check, [string]$Status, [string]$Pattern = '', [string]$Severity = '')
    $f = Get-Finding -Run $Run -Check $Check
    $ok = $f -and $f.Status -eq $Status -and (-not $Pattern -or [string]$f.Detail -match $Pattern) -and (-not $Severity -or $f.Severity -eq $Severity)
    $got = 'missing'
    if ($f) { $got = '[{0}/{1}] {2}' -f $f.Status, $f.Severity, $f.Detail }
    Assert-True $Label $ok $got
}
function Assert-Clean {
    <# Exit code, JSON written, no ERROR finding, no real Microsoft module loaded. #>
    param($Run, [string]$Label, [int]$ExitCode = 0)
    Assert-Equal ('{0}: exit {1}' -f $Label, $ExitCode) $ExitCode $Run.Code
    Assert-True ('{0}: JSON written' -f $Label) ($null -ne $Run.Result) $Run.Console
    $errors = @($Run.Result.Findings | Where-Object { $_.Status -eq 'ERROR' })
    Assert-True ('{0}: no ERROR findings' -f $Label) ($errors.Count -eq 0) (($errors | ForEach-Object { '{0}: {1}' -f $_.Check, $_.Detail }) -join '; ')
    $real = @($Run.Modules | Where-Object { $_ -like 'Microsoft.Graph*' -or $_ -like 'ExchangeOnlineManagement*' -or $_ -like 'tmpEXO*' })
    Assert-True ('{0}: no real Graph or Exchange module loaded' -f $Label) ($real.Count -eq 0) ($real -join ', ')
}

# --- Static check: no syntax newer than Windows PowerShell 5.1 ------------------------------
if (Get-Command -Name Invoke-ScriptAnalyzer -ErrorAction SilentlyContinue) {
    $compat = @{ Rules = @{ PSUseCompatibleSyntax = @{ Enable = $true; TargetVersions = @('5.1', '7.0') } } }
    foreach ($s in $c4, 'tests/Test-M365SecurityPostureLogic.ps1') {
        $hits = @(Invoke-ScriptAnalyzer -Path (Join-Path $repo $s) -IncludeRule PSUseCompatibleSyntax -Settings $compat)
        Assert-True ('{0}: syntax works on 5.1 and 7' -f (Split-Path $s -Leaf)) ($hits.Count -eq 0) (($hits | ForEach-Object { '{0}: {1}' -f $_.Line, $_.Message }) -join '; ')
    }
}

# =========================================================================================
# Mocks. $global:* variables set the scene; Write-Call records connections for the asserts.
# =========================================================================================
$mocks = @'
function Write-Call { param([string]$Text) Add-Content -LiteralPath $env:MSP_TEST_CALLS -Value $Text }
$premiumError = 'Neither tenant is B2C or tenant doesn''t have premium license. Status: 403 (Forbidden) ErrorCode: Authentication_RequestFromNonPremiumTenantOrB2CTenant'
$deniedError = 'Insufficient privileges to complete the operation. Status: 403 (Forbidden) ErrorCode: Authorization_RequestDenied'
# --- Graph ---
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
function Get-MgReportAuthenticationMethodUserRegistrationDetail {
    [CmdletBinding()] param([switch]$All)
    if ($global:NoPremium) { throw $premiumError }
    return $global:MfaDetails
}
function Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy { [CmdletBinding()] param() return [pscustomobject]@{ IsEnabled = [bool]$global:DefaultsOn } }
function Get-MgIdentityConditionalAccessPolicy {
    [CmdletBinding()] param([switch]$All)
    if ($global:NoPremium) { throw $premiumError }
    return $global:CaPolicies
}
function Get-MgAuditLogSignIn {
    [CmdletBinding()] param([string]$Filter, [int]$Top)
    if ($global:NoPremium) { throw $premiumError }
    Write-Call ('Get-MgAuditLogSignIn {0}' -f $Filter)
    $app = ''
    if ($Filter -match "clientAppUsed eq '([^']+)'") { $app = $Matches[1] }
    return @($global:SignIns | Where-Object { $_.ClientAppUsed -eq $app })
}
function Get-MgDirectoryRole {
    [CmdletBinding()] param([switch]$All)
    if ($global:DenyRoles) { throw $deniedError }
    return $global:Roles
}
function Get-MgDirectoryRoleMember {
    [CmdletBinding()] param([string]$DirectoryRoleId, [switch]$All)
    return @($global:RoleMembers[$DirectoryRoleId])
}
function Get-MgUser {
    [CmdletBinding()]
    param([string]$UserId, [switch]$All, [string]$Filter, [string[]]$Property)
    if ($Filter -like "*Guest*") {
        if ($global:NoPremium -and $Property -contains 'signInActivity') { throw $premiumError }
        return $global:Guests
    }
    return $global:Users[$UserId]
}
function Get-MgSecuritySecureScore {
    [CmdletBinding()] param([int]$Top)
    if ($global:DenySecureScore) { throw $deniedError }
    return $global:Scores
}
function Get-MgSecuritySecureScoreControlProfile { [CmdletBinding()] param([switch]$All) return $global:Profiles }
# --- Exchange Online ---
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
function Get-HostedOutboundSpamFilterPolicy { [CmdletBinding()] param() return $global:OutboundPolicies }
function Get-EXOMailbox {
    [CmdletBinding()] param([string]$ResultSize, [string[]]$RecipientTypeDetails, [string[]]$Properties)
    return $global:Mailboxes
}
function Get-InboxRule { [CmdletBinding()] param([string]$Mailbox) return @($global:Rules[$Mailbox]) }
function Get-OrganizationConfig { [CmdletBinding()] param() return [pscustomobject]@{ AuditDisabled = [bool]$global:AuditDisabled } }

# --- Scene shared by every scenario (changed per scenario below) ---
function New-Member {
    param([string]$Upn, [string]$Name = '')
    if (-not $Name) { $Name = ($Upn -split '@')[0] }
    [pscustomobject]@{ Id = 'id-' + $Upn; AdditionalProperties = @{ '@odata.type' = '#microsoft.graph.user'; userPrincipalName = $Upn; displayName = $Name } }
}
function New-Plans { param([bool]$Mailbox) if ($Mailbox) { @([pscustomobject]@{ Service = 'exchange'; CapabilityStatus = 'Enabled' }) } else { @() } }
$ga = '62e90394-69f5-4237-9190-012177145e10'
$exa = '29232cdf-9323-42fd-ade2-1d097af3e4de'
$global:Roles = @(
    [pscustomobject]@{ Id = 'role-ga'; DisplayName = 'Global Administrator'; RoleTemplateId = $ga },
    [pscustomobject]@{ Id = 'role-exa'; DisplayName = 'Exchange Administrator'; RoleTemplateId = $exa },
    [pscustomobject]@{ Id = 'role-dir'; DisplayName = 'Directory Readers'; RoleTemplateId = '88d8e3e3-8f55-4a1e-953a-9b9898b8876b' }
)
$global:RoleMembers = @{ 'role-ga' = @((New-Member 'admin1@contoso.com'), (New-Member 'admin2@contoso.com')); 'role-exa' = @(); 'role-dir' = @((New-Member 'reader@contoso.com')) }
$global:Users = @{ 'id-admin1@contoso.com' = [pscustomobject]@{ AssignedPlans = (New-Plans $false) }; 'id-admin2@contoso.com' = [pscustomobject]@{ AssignedPlans = (New-Plans $false) } }
$global:MfaDetails = @(
    [pscustomobject]@{ UserPrincipalName = 'admin1@contoso.com'; UserDisplayName = 'Admin 1'; IsAdmin = $true; IsMfaRegistered = $true; UserType = 'member'; MethodsRegistered = @('microsoftAuthenticatorPush') },
    [pscustomobject]@{ UserPrincipalName = 'alice@contoso.com'; UserDisplayName = 'Alice'; IsAdmin = $false; IsMfaRegistered = $true; UserType = 'member'; MethodsRegistered = @('microsoftAuthenticatorPush') }
)
$global:DefaultsOn = $true
$global:CaPolicies = @()
$global:SignIns = @()
$global:OutboundPolicies = @([pscustomobject]@{ Name = 'Default'; AutoForwardingMode = 'Automatic' })
$global:Mailboxes = @([pscustomobject]@{ UserPrincipalName = 'alice@contoso.com'; ForwardingSmtpAddress = $null; ForwardingAddress = $null; DeliverToMailboxAndForward = $false })
$global:Rules = @{}
$global:Guests = @([pscustomobject]@{ UserPrincipalName = 'partner_fabrikam.com#EXT#@contoso.onmicrosoft.com'; Mail = 'partner@fabrikam.com'; AccountEnabled = $true; CreatedDateTime = (Get-Date).AddDays(-400); SignInActivity = [pscustomobject]@{ LastSignInDateTime = (Get-Date).AddDays(-3) } })
$global:AuditDisabled = $false
$global:Scores = @([pscustomobject]@{ CreatedDateTime = (Get-Date).AddDays(-1); CurrentScore = 62.5; MaxScore = 80; ControlScores = @([pscustomobject]@{ ControlName = 'MFARegistrationV2'; Score = 9 }) })
$global:Profiles = @([pscustomobject]@{ Id = 'MFARegistrationV2'; Title = 'Ensure all users can complete multifactor authentication'; MaxScore = 9; Deprecated = $false; ControlCategory = 'Identity'; UserImpact = 'Moderate'; ImplementationCost = 'Moderate' })
'@
$allScopes = "`$global:GraphConnected = `$true`n`$global:ExoConnected = `$true`n`$global:GraphScopes = @('User.Read.All', 'AuditLog.Read.All', 'Policy.Read.All', 'RoleManagement.Read.Directory', 'SecurityEvents.Read.All')"

$risky = @'
$global:MfaDetails += @(
    [pscustomobject]@{ UserPrincipalName = 'admin3@contoso.com'; UserDisplayName = 'Admin 3'; IsAdmin = $true; IsMfaRegistered = $false; UserType = 'member'; MethodsRegistered = @() },
    [pscustomobject]@{ UserPrincipalName = 'bob@contoso.com'; UserDisplayName = 'Bob'; IsAdmin = $false; IsMfaRegistered = $false; UserType = 'member'; MethodsRegistered = @() },
    [pscustomobject]@{ UserPrincipalName = 'partner_fabrikam.com#EXT#@contoso.onmicrosoft.com'; UserDisplayName = 'Partner'; IsAdmin = $false; IsMfaRegistered = $false; UserType = 'guest'; MethodsRegistered = @() }
)
$global:DefaultsOn = $false
$global:CaPolicies = @(
    [pscustomobject]@{ DisplayName = 'MFA for admins'; State = 'enabled'; Conditions = [pscustomobject]@{ Users = [pscustomobject]@{ IncludeUsers = @(); IncludeRoles = @('62e90394-69f5-4237-9190-012177145e10') }; ClientAppTypes = @('all') }; GrantControls = [pscustomobject]@{ BuiltInControls = @('mfa') } },
    [pscustomobject]@{ DisplayName = 'Block legacy auth'; State = 'enabledForReportingButNotEnforced'; Conditions = [pscustomobject]@{ Users = [pscustomobject]@{ IncludeUsers = @('All') }; ClientAppTypes = @('exchangeActiveSync', 'other') }; GrantControls = [pscustomobject]@{ BuiltInControls = @('block') } }
)
$global:SignIns = @(
    [pscustomobject]@{ CreatedDateTime = (Get-Date).AddDays(-1); UserPrincipalName = 'bob@contoso.com'; ClientAppUsed = 'IMAP4'; Status = [pscustomobject]@{ ErrorCode = 0 }; AppDisplayName = 'Office 365 Exchange Online' },
    [pscustomobject]@{ CreatedDateTime = (Get-Date).AddDays(-2); UserPrincipalName = 'alice@contoso.com'; ClientAppUsed = 'POP3'; Status = [pscustomobject]@{ ErrorCode = 50126 }; AppDisplayName = 'Office 365 Exchange Online' }
)
$global:RoleMembers['role-ga'] = @((New-Member 'admin1@contoso.com'), (New-Member 'admin2@contoso.com'), (New-Member 'admin3@contoso.com'), (New-Member 'alice@contoso.com'), (New-Member 'admin5@contoso.com'))
$global:RoleMembers['role-exa'] = @((New-Member 'bob@contoso.com'), [pscustomobject]@{ Id = 'sp-1'; AdditionalProperties = @{ '@odata.type' = '#microsoft.graph.servicePrincipal'; displayName = 'Backup App' } })
foreach ($u in 'admin3', 'admin5', 'bob') { $global:Users[('id-{0}@contoso.com' -f $u)] = [pscustomobject]@{ AssignedPlans = (New-Plans $false) } }
$global:Users['id-alice@contoso.com'] = [pscustomobject]@{ AssignedPlans = (New-Plans $true) }
$global:OutboundPolicies = @([pscustomobject]@{ Name = 'Default'; AutoForwardingMode = 'On' })
$global:Mailboxes = @(
    [pscustomobject]@{ UserPrincipalName = 'alice@contoso.com'; ForwardingSmtpAddress = 'smtp:alice.private@gmail.com'; ForwardingAddress = $null; DeliverToMailboxAndForward = $true },
    [pscustomobject]@{ UserPrincipalName = 'bob@contoso.com'; ForwardingSmtpAddress = 'smtp:carol@contoso.com'; ForwardingAddress = $null; DeliverToMailboxAndForward = $true },
    [pscustomobject]@{ UserPrincipalName = 'carol@contoso.com'; ForwardingSmtpAddress = $null; ForwardingAddress = $null; DeliverToMailboxAndForward = $false }
)
$global:Rules = @{
    'bob@contoso.com'   = @([pscustomobject]@{ Name = 'Sync'; Enabled = $true; ForwardTo = $null; ForwardAsAttachmentTo = $null; RedirectTo = @('"Ext" [SMTP:collect@proton.me]') })
    'carol@contoso.com' = @([pscustomobject]@{ Name = 'To team'; Enabled = $true; ForwardTo = @('"Team" [SMTP:team@contoso.com]'); ForwardAsAttachmentTo = $null; RedirectTo = $null },
        [pscustomobject]@{ Name = 'Old'; Enabled = $false; ForwardTo = @('[SMTP:old@outlook.com]'); ForwardAsAttachmentTo = $null; RedirectTo = $null })
}
$global:Guests = @(
    [pscustomobject]@{ UserPrincipalName = 'g1'; Mail = 'old.partner@fabrikam.com'; AccountEnabled = $true; CreatedDateTime = (Get-Date).AddDays(-500); SignInActivity = [pscustomobject]@{ LastSignInDateTime = (Get-Date).AddDays(-200) } },
    [pscustomobject]@{ UserPrincipalName = 'g2'; Mail = 'active@fabrikam.com'; AccountEnabled = $true; CreatedDateTime = (Get-Date).AddDays(-500); SignInActivity = [pscustomobject]@{ LastSignInDateTime = (Get-Date).AddDays(-10) } },
    [pscustomobject]@{ UserPrincipalName = 'g3'; Mail = 'never@tailspin.com'; AccountEnabled = $false; CreatedDateTime = (Get-Date).AddDays(-300); SignInActivity = $null }
)
$global:AuditDisabled = $true
$global:Scores = @(
    [pscustomobject]@{ CreatedDateTime = (Get-Date).AddDays(-2); CurrentScore = 30; MaxScore = 100; ControlScores = @() },
    [pscustomobject]@{ CreatedDateTime = (Get-Date).AddDays(-1); CurrentScore = 35; MaxScore = 100; ControlScores = @(
            [pscustomobject]@{ ControlName = 'AdminMFAV2'; Score = 0 }, [pscustomobject]@{ ControlName = 'BlockLegacyAuthentication'; Score = 0 },
            [pscustomobject]@{ ControlName = 'MFARegistrationV2'; Score = 9 }, [pscustomobject]@{ ControlName = 'OldControl'; Score = 0 }) }
)
$global:Profiles = @(
    [pscustomobject]@{ Id = 'AdminMFAV2'; Title = 'Ensure multifactor authentication is enabled for all users in administrative roles'; MaxScore = 10; Deprecated = $false; ControlCategory = 'Identity'; UserImpact = 'Low'; ImplementationCost = 'Low' },
    [pscustomobject]@{ Id = 'BlockLegacyAuthentication'; Title = 'Enable Conditional Access policies to block legacy authentication'; MaxScore = 8; Deprecated = $false; ControlCategory = 'Identity'; UserImpact = 'Moderate'; ImplementationCost = 'Moderate' },
    [pscustomobject]@{ Id = 'MFARegistrationV2'; Title = 'Ensure all users can complete multifactor authentication'; MaxScore = 9; Deprecated = $false; ControlCategory = 'Identity'; UserImpact = 'Moderate'; ImplementationCost = 'Moderate' },
    [pscustomobject]@{ Id = 'OldControl'; Title = 'Retired control'; MaxScore = 50; Deprecated = $true; ControlCategory = 'Data'; UserImpact = 'Low'; ImplementationCost = 'Low' }
)
'@

try {
    # --- Risky tenant: sign in to both with device code --------------------------------------
    $r = Invoke-Mocked 'risky' ("{0}`n{1}" -f $mocks, $risky) @('-DeviceCode', '-TopActions', '2')
    Assert-Clean $r 'risky'
    Assert-True 'Graph: exactly the five read-only scopes, device code, process-only token' (@($r.Calls | Where-Object { $_ -eq 'Connect-MgGraph Scopes=User.Read.All,AuditLog.Read.All,Policy.Read.All,RoleManagement.Read.Directory,SecurityEvents.Read.All DeviceCode=True ContextScope=Process' }).Count -eq 1) ($r.Calls -join "`n")
    Assert-True 'Exchange: loads only the read cmdlets, device code' (@($r.Calls | Where-Object { $_ -eq 'Connect-ExchangeOnline CommandName=Get-AcceptedDomain,Get-HostedOutboundSpamFilterPolicy,Get-InboxRule,Get-OrganizationConfig Device=True' }).Count -eq 1) ($r.Calls -join "`n")
    Assert-True 'Both connections it opened are closed' (($r.Calls -contains 'Disconnect-MgGraph') -and ($r.Calls -contains 'Disconnect-ExchangeOnline'))
    Assert-Equal 'CheckId C4' 'C4' $r.Result.CheckId
    Assert-Finding $r 'Admin without MFA = FAIL High' 'Admins without MFA' 'FAIL' '1 admin account.*admin3@contoso\.com' 'High'
    Assert-Finding $r 'User without MFA = WARN Medium, guests not counted' 'Users without MFA' 'WARN' '^1 of 4 member account\(s\).*bob@contoso\.com' 'Medium'
    Assert-Finding $r 'CA without MFA for all users = WARN' 'Security defaults or Conditional Access' 'WARN' 'none requires MFA for all users'
    Assert-Finding $r 'Legacy block only report-only = WARN' 'Legacy authentication blocked' 'WARN' 'report-only.*Block legacy auth'
    Assert-Finding $r 'Successful IMAP sign-in = WARN High' 'Legacy sign-ins' 'WARN' '^1 successful legacy sign-in.*bob@contoso\.com \(IMAP4\)' 'High'
    Assert-True 'Legacy sign-ins: one query per legacy client, with a date filter' (@($r.Calls | Where-Object { $_ -match "^Get-MgAuditLogSignIn createdDateTime ge \d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ and clientAppUsed eq '" }).Count -eq 11)
    Assert-Finding $r '5 Global Admins = WARN' 'Global Administrators' 'WARN' '^5 Global Administrators \(more than 4\)'
    Assert-Finding $r 'Admin with a licensed mailbox = WARN' 'Admins with a mailbox' 'WARN' '^1 admin account.*alice@contoso\.com'
    Assert-Finding $r 'Other privileged roles listed, service principal included' 'Other privileged roles' 'INFO' 'Exchange Administrator: bob@contoso\.com, Backup App'
    Assert-True 'Directory Readers is not a privileged role' (@($r.Result.Data.Admins | Where-Object { $_.Member -eq 'reader@contoso.com' }).Count -eq 0)
    Assert-True 'Admins table joins MFA state' (@($r.Result.Data.Admins | Where-Object { $_.Member -eq 'admin3@contoso.com' -and "$($_.MfaRegistered)" -eq 'False' }).Count -eq 1)
    Assert-Finding $r 'Outbound forwarding On = WARN High' 'Outbound forwarding policy' 'WARN' 'Default' 'High'
    Assert-Finding $r 'External mailbox forwarding = WARN High, internal ignored' 'Mailbox forwarding' 'WARN' '^1 mailbox.*alice@contoso\.com -> alice\.private@gmail\.com\.$' 'High'
    Assert-Finding $r 'External redirect rule = WARN High, internal and disabled rules ignored' 'Forwarding rules' 'WARN' '^1 enabled inbox rule.*bob@contoso\.com: "Sync" -> collect@proton\.me\.$' 'High'
    Assert-Equal 'ExternalForwarding table' 2 @($r.Result.Data.ExternalForwarding).Count
    Assert-Finding $r 'Guests counted' 'Guest users' 'INFO' '^3 guest account\(s\), 2 enabled'
    Assert-Finding $r 'Inactive and never-used guests = WARN Low' 'Inactive guests' 'WARN' '^2 guest.*old\.partner@fabrikam\.com \(last .*never@tailspin\.com \(never' 'Low'
    Assert-Finding $r 'Mailbox auditing off = FAIL' 'Mailbox auditing' 'FAIL' 'turned off'
    Assert-Finding $r 'Secure Score: newest snapshot, top 2 actions, deprecated left out' 'Secure Score' 'INFO' '^35 of 100 points \(35 %\).*Top improvements: Ensure multifactor authentication is enabled for all users in administrative roles \(\+10\); Enable Conditional Access policies to block legacy authentication \(\+8\)\.$'
    Assert-Equal 'SecureScoreActions table: deprecated and complete controls left out' 2 @($r.Result.Data.SecureScoreActions).Count
    Assert-Finding $r 'P1 available' 'Entra ID P1/P2' 'INFO' '^Available'
    foreach ($t in 'MfaGaps', 'ConditionalAccess', 'LegacySignIns', 'Admins', 'Guests') { Assert-True ('table {0}' -f $t) (@($r.Result.Data.$t).Count -gt 0) }
    Assert-True 'Tenant findings carry the tenant ID' ([string](Get-Finding $r 'Mailbox auditing').Target -eq '00000000-1111-2222-3333-444444444444')

    # --- No Entra ID P1, security defaults on, existing connections ----------------------------
    $r = Invoke-Mocked 'nop1' ("{0}`n{1}`n`$global:NoPremium = `$true" -f $mocks, $allScopes)
    Assert-Clean $r 'no P1'
    Assert-True 'no P1: no new sign-in, nothing closed' ($r.Calls.Count -eq 0) ($r.Calls -join "`n")
    Assert-Finding $r 'no P1: MFA SKIPPED with the reason' 'MFA registration' 'SKIPPED' 'no Microsoft Entra ID P1 or P2 license.*Business Premium'
    Assert-Finding $r 'no P1: security defaults PASS' 'Security defaults or Conditional Access' 'PASS' 'Security defaults are on'
    Assert-Finding $r 'no P1: legacy blocked by defaults' 'Legacy authentication blocked' 'PASS' 'security defaults'
    Assert-Finding $r 'no P1: legacy sign-ins SKIPPED' 'Legacy sign-ins' 'SKIPPED' 'P1 or P2'
    Assert-Finding $r 'no P1: 2 Global Admins PASS' 'Global Administrators' 'PASS' '^2 Global Administrators'
    Assert-Finding $r 'no P1: admins without mailboxes PASS' 'Admins with a mailbox' 'PASS'
    Assert-Finding $r 'no P1: outbound Automatic PASS' 'Outbound forwarding policy' 'PASS' 'Default: Automatic'
    foreach ($check in 'Mailbox forwarding', 'Forwarding rules', 'Mailbox auditing') { Assert-Finding $r ('no P1: {0} PASS' -f $check) $check 'PASS' }
    Assert-Finding $r 'no P1: guests still counted' 'Guest users' 'INFO' '^1 guest'
    Assert-Finding $r 'no P1: inactive guests SKIPPED' 'Inactive guests' 'SKIPPED' 'P1 or P2'
    Assert-Finding $r 'no P1: summary names the P1 checks' 'Entra ID P1/P2' 'INFO' '^Not in this tenant.*MFA registration, Conditional Access, legacy sign-ins, inactive guests'
    Assert-Finding $r 'no P1: Secure Score read' 'Secure Score' 'INFO' '62\.5 of 80 points \(78 %\)'

    # --- Neither security defaults nor Conditional Access ------------------------------------
    $r = Invoke-Mocked 'neither' ("{0}`n{1}`n`$global:NoPremium = `$true`n`$global:DefaultsOn = `$false" -f $mocks, $allScopes)
    Assert-Clean $r 'neither'
    Assert-Finding $r 'neither = FAIL High' 'Security defaults or Conditional Access' 'FAIL' 'Neither is protecting the tenant.*needs Entra ID P1' 'High'
    Assert-Finding $r 'legacy not blocked = WARN High' 'Legacy authentication blocked' 'WARN' '^Not blocked.*not available' 'High'

    # --- Account role too narrow -------------------------------------------------------------------
    $r = Invoke-Mocked 'denied' ("{0}`n{1}`n`$global:DenyRoles = `$true`n`$global:DenySecureScore = `$true" -f $mocks, $allScopes)
    Assert-Clean $r 'denied'
    Assert-Finding $r 'denied: admin roles SKIPPED' 'Admin roles' 'SKIPPED' 'may not read this'
    Assert-True 'denied: Global Reader named' ([string](Get-Finding $r 'Admin roles').Recommendation -match 'Global Reader')
    Assert-Finding $r 'denied: Secure Score SKIPPED' 'Secure Score' 'SKIPPED' 'may not read this'
    Assert-Finding $r 'denied: the rest still runs' 'Mailbox auditing' 'PASS'

    # --- Existing Graph connection without SecurityEvents.Read.All ----------------------------
    $r = Invoke-Mocked 'scope' ("{0}`n{1}`n`$global:GraphScopes = @('User.Read.All', 'AuditLog.Read.All', 'Policy.Read.All', 'RoleManagement.Read.Directory')" -f $mocks, $allScopes)
    Assert-Clean $r 'missing scope'
    Assert-Finding $r 'missing scope named' 'Graph scopes' 'WARN' 'missing SecurityEvents\.Read\.All'
    Assert-Finding $r 'Secure Score SKIPPED naming the scope' 'Secure Score' 'SKIPPED' 'Needs the SecurityEvents\.Read\.All scope'

    # --- -SkipExchange -----------------------------------------------------------------------------
    $r = Invoke-Mocked 'skipexo' ("{0}`n`$global:GraphConnected = `$true`n`$global:GraphScopes = @('User.Read.All', 'AuditLog.Read.All', 'Policy.Read.All', 'RoleManagement.Read.Directory', 'SecurityEvents.Read.All')" -f $mocks) @('-SkipExchange')
    Assert-Clean $r '-SkipExchange'
    Assert-True '-SkipExchange: no Exchange sign-in' (@($r.Calls | Where-Object { $_ -like 'Connect-ExchangeOnline*' }).Count -eq 0)
    Assert-Finding $r '-SkipExchange: connection SKIPPED' 'Exchange connection' 'SKIPPED' 'SkipExchange'
    Assert-Finding $r '-SkipExchange: auditing SKIPPED' 'Mailbox auditing' 'SKIPPED' 'SkipExchange'
    Assert-Finding $r '-SkipExchange: Graph checks still run' 'Global Administrators' 'PASS'

    # --- Not signed in, no terminal ---------------------------------------------------------------
    $r = Invoke-Mocked 'noninteractive' $mocks
    Assert-Equal 'no terminal: exit 1' 1 $r.Code
    Assert-Finding $r 'no terminal: Graph SKIPPED' 'Graph connection' 'SKIPPED' 'cannot show a sign-in window'
    Assert-Finding $r 'no terminal: Exchange SKIPPED' 'Exchange connection' 'SKIPPED' 'cannot show a sign-in window'
    Assert-True 'no terminal: never connects' ($r.Calls.Count -eq 0) ($r.Calls -join "`n")
}
finally {
    if (-not $env:MSP_KEEP) { Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue }
}

Write-Host ('{0} passed, {1} failed (PowerShell {2})' -f $script:passed, $script:failed, $PSVersionTable.PSVersion)
if ($script:failed -gt 0) { exit 1 }
exit 0
