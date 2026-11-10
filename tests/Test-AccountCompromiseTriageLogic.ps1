<#
.SYNOPSIS
    Runs C5 (Get-AccountCompromiseTriage.ps1) against mocked Microsoft Graph and Exchange Online
    cmdlets, so its logic is tested without a tenant.

.DESCRIPTION
    Development-side check; never run on client machines. No network traffic: every Graph and
    Exchange cmdlet the script reads with is replaced by a stand-in function, and so is every
    cmdlet that could change something (Set-Mailbox, Remove-InboxRule, Revoke-MgUserSignInSession,
    ...): those record the call, and the test fails if the script ever called one. Each run also
    records the loaded modules; the test fails if a real Graph or Exchange module was imported.

    Runs on whichever PowerShell runs it (Windows PowerShell 5.1 or PowerShell 7). Where
    PSScriptAnalyzer is installed it also checks that C5 and this test use no syntax newer than 5.1.

      Compromised user  Sign-in with exactly the seven read-only scopes, device code, process-only
                        token; Exchange loads only its read cmdlets; both connections closed. A new
                        country, failed MFA then success, an IMAP sign-in, two countries within
                        hours; high risk with a detection; hiding, deleting, payment-word and
                        external forwarding rules (harmless and disabled rules not flagged);
                        external mailbox forwarding; delegates; an authenticator added 2 days ago;
                        a recent consent to a mail app (Microsoft's own app not flagged); a sent-mail
                        spike; rule, forwarding and permission changes and a mass deletion in the
                        audit log; "What to do now" names each thing found; nothing changed.
      No P1 / P2        Existing connections (no new sign-in, none closed); sign-ins and risk
                        SKIPPED with the license reason, never ERROR; auditing off SKIPPED with the
                        reason; everything else PASS; no compromise indicator.
      Unknown user      FAIL for the account and the mailbox; the user checks SKIPPED, not ERROR.
      Role too narrow   Message trace and the audit log refused: SKIPPED naming the role.
      -Days 31          Refused by parameter validation; nothing connects.
      Missing scope     No Identity Protection scopes: risk SKIPPED naming the scope.
      No terminal       Not signed in anywhere and no -DeviceCode: SKIPPED, exit 1, nothing connects.

.EXAMPLE
    pwsh -NoProfile -File tests/Test-AccountCompromiseTriageLogic.ps1

.NOTES
    Risk Level    : Safe -- writes and removes files in a temporary folder only; no network
    Prerequisites : Windows PowerShell 5.1 or PowerShell 7 | Admin: No
    Exit code     : 0 all passed, 1 any failure
    Version       : 1.0.1
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPositionalParameters', '', Justification = 'Assert-Equal / Assert-True (Name, Expected, Actual) are one-line test assertions used throughout.')]
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
if (-not $here) { $here = Split-Path -Path $MyInvocation.MyCommand.Path -Parent }
$repo = (Resolve-Path -LiteralPath (Join-Path $here '..')).ProviderPath
$exe = (Get-Process -Id $PID).Path
$work = Join-Path ([System.IO.Path]::GetTempPath()) ('msp-c5-{0}' -f [guid]::NewGuid().ToString('N').Substring(0, 8))
$null = New-Item -ItemType Directory -Path $work -Force
$c5 = 'security-operations/diagnostics/Get-AccountCompromiseTriage.ps1'

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
    <# Runs C5 with MOCKS defined first; returns exit code, console, JSON result, call log and loaded modules. #>
    param([string]$Name, [string]$Mocks, [string[]]$ScriptArgs = @())
    $dir = Join-Path $work $Name
    $out = Join-Path $dir 'out'
    $null = New-Item -ItemType Directory -Path $out -Force
    $calls = Join-Path $dir 'calls.txt'
    $modules = Join-Path $dir 'modules.txt'
    $argText = ($ScriptArgs | ForEach-Object { if ($_ -like '-*') { $_ } else { "'{0}'" -f ($_ -replace "'", "''") } }) -join ' '
    $wrapper = Join-Path $dir 'run.ps1'
    $text = "`$env:MSP_TEST_CALLS = '{0}'`n{1}`n& '{2}' -OutputPath '{3}' {4}`n`$code = `$LASTEXITCODE`nGet-Module | ForEach-Object {{ `$_.Name }} | Set-Content -LiteralPath '{5}'`nexit `$code`n" -f `
    ($calls -replace "'", "''"), $Mocks, ((Join-Path $repo $c5) -replace "'", "''"), ($out -replace "'", "''"), $argText, ($modules -replace "'", "''")
    [System.IO.File]::WriteAllText($wrapper, $text, (New-Object System.Text.UTF8Encoding($true)))
    # 'Continue' here: Windows PowerShell 5.1 turns a child's stderr line (the -Days 31 parameter
    # error) into a terminating error under 'Stop'.
    $console = & { $ErrorActionPreference = 'Continue'; & $exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $wrapper 2>&1 } | Out-String
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
    <# Exit code, JSON written, no ERROR finding, no real module loaded, nothing changed. #>
    param($Run, [string]$Label, [int]$ExitCode = 0)
    Assert-Equal ('{0}: exit {1}' -f $Label, $ExitCode) $ExitCode $Run.Code
    Assert-True ('{0}: JSON written' -f $Label) ($null -ne $Run.Result) $Run.Console
    $errors = @($Run.Result.Findings | Where-Object { $_.Status -eq 'ERROR' })
    Assert-True ('{0}: no ERROR findings' -f $Label) ($errors.Count -eq 0) (($errors | ForEach-Object { '{0}: {1}' -f $_.Check, $_.Detail }) -join '; ')
    $real = @($Run.Modules | Where-Object { $_ -like 'Microsoft.Graph*' -or $_ -like 'ExchangeOnlineManagement*' -or $_ -like 'tmpEXO*' })
    Assert-True ('{0}: no real Graph or Exchange module loaded' -f $Label) ($real.Count -eq 0) ($real -join ', ')
    $changes = @($Run.Calls | Where-Object { $_ -like 'CHANGE *' })
    Assert-True ('{0}: nothing in the tenant was changed' -f $Label) ($changes.Count -eq 0) ($changes -join '; ')
}

function Get-Step {
    <# The "What to do now" steps of a run, in order. #>
    param($Run)
    if (-not $Run.Result) { return @() }
    return @($Run.Result.Data.NextSteps | Sort-Object { [int]$_.Step } | ForEach-Object { [string]$_.Action })
}
function Assert-NoRepeatedStep {
    <# No two steps say the same thing: no identical steps, and no generic step next to a specific one on its topic. #>
    param($Run, [string]$Label)
    $steps = @(Get-Step $Run)
    $norm = @($steps | ForEach-Object { ($_ -replace '\s+', ' ').Trim().ToLowerInvariant() })
    $dupes = @($norm | Group-Object | Where-Object { $_.Count -gt 1 } | ForEach-Object { $_.Name })
    Assert-True ('{0}: no step repeated word for word' -f $Label) ($dupes.Count -eq 0) ($dupes -join ' | ')
    # Topics that one step covers: at most one step each.
    $single = [ordered]@{ 'MFA methods' = '^(Review the MFA methods|Register MFA)'; 'Sent/Deleted Items' = '^Check Sent Items'; 'password reset' = '^Reset the password'
        'sessions' = '^Revoke all sessions'; 'block sign-in' = '^Block sign-in for'; 'allow sign-in again' = '^Allow sign-in again'; 'tell the client' = '^Tell the client' }
    foreach ($k in $single.Keys) {
        $hits = @($steps | Where-Object { $_ -match $single[$k] })
        Assert-True ('{0}: one step at most about {1}' -f $Label, $k) ($hits.Count -le 1) ($hits -join ' | ')
    }
    # App consents: one step per app, and the generic one only when there is no specific one.
    $generic = @($steps | Where-Object { $_ -match '^Review the app consents with the user' })
    $specific = @($steps | Where-Object { $_ -match '^Review the app consent "' })
    Assert-True ('{0}: generic app-consent step only without a specific one' -f $Label) (-not ($generic.Count -gt 0 -and $specific.Count -gt 0)) (($generic + $specific) -join ' | ')
}

# --- Static check: no syntax newer than Windows PowerShell 5.1 ------------------------------
if (Get-Command -Name Invoke-ScriptAnalyzer -ErrorAction SilentlyContinue) {
    $compat = @{ Rules = @{ PSUseCompatibleSyntax = @{ Enable = $true; TargetVersions = @('5.1', '7.0') } } }
    foreach ($s in $c5, 'tests/Test-AccountCompromiseTriageLogic.ps1') {
        $hits = @(Invoke-ScriptAnalyzer -Path (Join-Path $repo $s) -IncludeRule PSUseCompatibleSyntax -Settings $compat)
        Assert-True ('{0}: syntax works on 5.1 and 7' -f (Split-Path $s -Leaf)) ($hits.Count -eq 0) (($hits | ForEach-Object { '{0}: {1}' -f $_.Line, $_.Message }) -join '; ')
    }
}

# =========================================================================================
# Mocks. $global:* variables set the scene; Write-Call records connections and any change.
# =========================================================================================
$mocks = @'
function Write-Call { param([string]$Text) Add-Content -LiteralPath $env:MSP_TEST_CALLS -Value $Text }
$premiumError = 'Neither tenant is B2C or tenant doesn''t have premium license. Status: 403 (Forbidden) ErrorCode: Authentication_RequestFromNonPremiumTenantOrB2CTenant'
$p2Error = 'Your tenant is not licensed for this feature. Status: 403 (Forbidden)'
$deniedError = 'The operation could not be performed because the user does not have permission. Access is denied.'
# --- Anything that would change the tenant: recorded, never expected ---
foreach ($n in 'Set-Mailbox', 'Remove-InboxRule', 'Disable-InboxRule', 'Set-InboxRule', 'New-InboxRule', 'Remove-MailboxPermission', 'Remove-RecipientPermission',
    'Add-MailboxPermission', 'Set-AdminAuditLogConfig', 'Revoke-MgUserSignInSession', 'Update-MgUser', 'Remove-MgOauth2PermissionGrant',
    'Remove-MgUserAuthenticationMicrosoftAuthenticatorMethod', 'Remove-MgUserAuthenticationPhoneMethod', 'Reset-MgUserAuthenticationMethodPassword',
    'Confirm-MgRiskyUserCompromised', 'Invoke-MgDismissRiskyUser') {
    Set-Item -Path ('function:global:{0}' -f $n) -Value ([scriptblock]::Create(('Write-Call "CHANGE {0} $args"' -f $n)))
}
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
function Get-MgUser {
    [CmdletBinding()] param([string]$UserId, [string[]]$Property)
    if ($UserId -ne 'alice@contoso.com') { throw ('[Request_ResourceNotFound] : Resource ''{0}'' does not exist or one of its queried reference-property objects are not present.' -f $UserId) }
    return [pscustomobject]@{ Id = 'id-alice'; DisplayName = 'Alice Smith'; UserPrincipalName = 'alice@contoso.com'; AccountEnabled = $true; CreatedDateTime = (Get-Date).AddDays(-400); LastPasswordChangeDateTime = (Get-Date).AddDays(-200) }
}
function Get-MgAuditLogSignIn {
    [CmdletBinding()] param([string]$Filter, [switch]$All)
    if ($global:NoPremium) { throw $premiumError }
    Write-Call ('Get-MgAuditLogSignIn {0}' -f $Filter)
    return $global:SignIns
}
function Get-MgRiskyUser {
    [CmdletBinding()] param([string]$RiskyUserId)
    if ($global:NoPremium) { throw $p2Error }
    if (-not $global:Risky) { throw '[ResourceNotFound] : The requested resource does not exist.' }
    return $global:Risky
}
function Get-MgRiskDetection {
    [CmdletBinding()] param([string]$Filter, [switch]$All)
    if ($global:NoPremium) { throw $p2Error }
    return $global:Detections
}
function Get-MgUserAuthenticationMethod { [CmdletBinding()] param([string]$UserId, [switch]$All) return $global:Methods }
function Get-MgAuditLogDirectoryAudit {
    [CmdletBinding()] param([string]$Filter, [switch]$All)
    Write-Call ('Get-MgAuditLogDirectoryAudit {0}' -f $Filter)
    if ($Filter -like '*targetResources*') { return @($global:DirAudits | Where-Object { $_.Kind -eq 'target' }) }
    return @($global:DirAudits | Where-Object { $_.Kind -eq 'actor' })
}
function Get-MgUserOauth2PermissionGrant { [CmdletBinding()] param([string]$UserId, [switch]$All) return $global:Grants }
function Get-MgServicePrincipal { [CmdletBinding()] param([string]$ServicePrincipalId, [string[]]$Property) return $global:Apps[$ServicePrincipalId] }
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
function Get-EXOMailbox {
    [CmdletBinding()] param([string]$Identity, [string[]]$Properties)
    if ($Identity -ne 'alice@contoso.com') { throw ('The operation couldn''t be performed because object ''{0}'' couldn''t be found on ''EURP.PROD.OUTLOOK.COM''.' -f $Identity) }
    return $global:Mailbox
}
function Get-InboxRule { [CmdletBinding()] param([string]$Mailbox) return $global:Rules }
function Get-EXOMailboxPermission { [CmdletBinding()] param([string]$Identity) return $global:Perms }
function Get-EXORecipientPermission { [CmdletBinding()] param([string]$Identity) return $global:SendAs }
function Get-MessageTraceV2 {
    [CmdletBinding()] param([string]$SenderAddress, [datetime]$StartDate, [datetime]$EndDate, [int]$ResultSize)
    if ($global:DenyTrace) { throw $deniedError }
    Write-Call ('Get-MessageTraceV2 {0:yyyy-MM-dd} {1:yyyy-MM-dd}' -f $StartDate, $EndDate)
    return @($global:Sent | Where-Object { $_.Received -ge $StartDate -and $_.Received -lt $EndDate })
}
function Get-AdminAuditLogConfig { [CmdletBinding()] param() return [pscustomobject]@{ UnifiedAuditLogIngestionEnabled = [bool]$global:AuditOn } }
function Search-UnifiedAuditLog {
    [CmdletBinding()] param([datetime]$StartDate, [datetime]$EndDate, [string[]]$UserIds, [string[]]$ObjectIds, [string[]]$Operations, [int]$ResultSize)
    if ($global:DenyAudit) { throw $deniedError }
    if ($ObjectIds) { return @($global:AuditByOthers) }
    return @($global:AuditMine)
}

# --- A clean user (the compromised scenario adds to it) ---
$now = Get-Date
function New-SignIn { param([datetime]$Time, [string]$Country, [string]$Ip, [int]$Code = 0, [string]$Client = 'Mobile Apps and Desktop clients', [string]$App = 'Microsoft Outlook')
    [pscustomobject]@{ CreatedDateTime = $Time; IPAddress = $Ip; Location = [pscustomobject]@{ CountryOrRegion = $Country; City = 'X' }; AppDisplayName = $App; ClientAppUsed = $Client; Status = [pscustomobject]@{ ErrorCode = $Code; FailureReason = $(if ($Code) { 'Strong authentication failed' } else { '' }) } } }
$global:SignIns = @((New-SignIn $now.AddDays(-10) 'US' '203.0.113.10'), (New-SignIn $now.AddDays(-6) 'US' '203.0.113.10'), (New-SignIn $now.AddDays(-1) 'US' '203.0.113.10'))
$global:Risky = $null
$global:Detections = @()
$global:Mailbox = [pscustomobject]@{ RecipientTypeDetails = 'UserMailbox'; ForwardingSmtpAddress = $null; ForwardingAddress = $null; DeliverToMailboxAndForward = $false; GrantSendOnBehalfTo = @() }
$global:Rules = @([pscustomobject]@{ Name = 'Newsletters'; Enabled = $true; ForwardTo = $null; ForwardAsAttachmentTo = $null; RedirectTo = $null; DeleteMessage = $false; MoveToFolder = 'alice:\Newsletters'; MarkAsRead = $false; SubjectContainsWords = @('newsletter') })
$global:Perms = @([pscustomobject]@{ User = 'NT AUTHORITY\SELF'; AccessRights = @('FullAccess'); IsInherited = $false; Deny = $false })
$global:SendAs = @()
$global:Methods = @(
    [pscustomobject]@{ Id = 'm0'; AdditionalProperties = @{ '@odata.type' = '#microsoft.graph.passwordAuthenticationMethod' } },
    [pscustomobject]@{ Id = 'm1'; AdditionalProperties = @{ '@odata.type' = '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod'; displayName = 'Pixel 8'; createdDateTime = $now.AddDays(-200).ToString('o') } }
)
$global:DirAudits = @()
$global:Grants = @([pscustomobject]@{ ClientId = 'sp-ms'; Scope = ' User.Read Mail.Read '; ConsentType = 'Principal' })
$global:Apps = @{ 'sp-ms' = [pscustomobject]@{ DisplayName = 'Microsoft Office'; AppOwnerOrganizationId = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a'; VerifiedPublisher = [pscustomobject]@{ DisplayName = 'Microsoft Corporation' }; PublisherName = 'Microsoft' } }
$global:Sent = @(for ($d = 14; $d -ge 0; $d--) { for ($k = 0; $k -lt 3; $k++) { [pscustomobject]@{ Received = $now.AddDays(-$d).Date.AddHours(9 + $k); RecipientAddress = 'x@fabrikam.com' } } })
$global:AuditOn = $true
$global:AuditMine = @([pscustomobject]@{ CreationDate = $now.AddDays(-1); Operations = 'UserLoggedIn'; UserIds = 'alice@contoso.com'; RecordType = 'AzureActiveDirectoryStsLogon'; AuditData = '{"ClientIP":"203.0.113.10"}' })
$global:AuditByOthers = @()
'@
$scopes = "`$global:GraphScopes = @('User.Read.All', 'AuditLog.Read.All', 'UserAuthenticationMethod.Read.All', 'DelegatedPermissionGrant.Read.All', 'Application.Read.All', 'IdentityRiskyUser.Read.All', 'IdentityRiskEvent.Read.All')"
$connected = "`$global:GraphConnected = `$true`n`$global:ExoConnected = `$true`n{0}" -f $scopes

$compromised = @'
$global:SignIns = @(
    (New-SignIn $now.AddDays(-10) 'US' '203.0.113.10'), (New-SignIn $now.AddDays(-8) 'US' '203.0.113.10'), (New-SignIn $now.AddDays(-6) 'US' '203.0.113.10'),
    (New-SignIn $now.AddHours(-26) 'US' '203.0.113.10'),
    (New-SignIn $now.AddHours(-25) 'NG' '198.51.100.66' 500121),
    (New-SignIn $now.AddHours(-25).AddMinutes(10) 'NG' '198.51.100.66'),
    (New-SignIn $now.AddHours(-12) 'NG' '198.51.100.66' 0 'IMAP4' 'Office 365 Exchange Online')
)
$global:Risky = [pscustomobject]@{ RiskLevel = 'high'; RiskState = 'atRisk' }
$global:Detections = @([pscustomobject]@{ DetectedDateTime = $now.AddHours(-25); RiskEventType = 'unfamiliarFeatures'; RiskLevel = 'medium'; RiskState = 'atRisk'; IPAddress = '198.51.100.66'; Location = [pscustomobject]@{ CountryOrRegion = 'NG' } })
$global:Mailbox = [pscustomobject]@{ RecipientTypeDetails = 'UserMailbox'; ForwardingSmtpAddress = 'smtp:alice.backup@gmail.com'; ForwardingAddress = $null; DeliverToMailboxAndForward = $false; GrantSendOnBehalfTo = @('Carol Assistant') }
$global:Rules += @(
    [pscustomobject]@{ Name = '.'; Enabled = $true; ForwardTo = $null; ForwardAsAttachmentTo = $null; RedirectTo = $null; DeleteMessage = $false; MoveToFolder = 'alice:\RSS Feeds'; MarkAsRead = $true },
    [pscustomobject]@{ Name = 'Payments'; Enabled = $true; ForwardTo = $null; ForwardAsAttachmentTo = $null; RedirectTo = $null; DeleteMessage = $true; MoveToFolder = $null; MarkAsRead = $false; SubjectOrBodyContainsWords = @('invoice', 'payment') },
    [pscustomobject]@{ Name = 'Sync'; Enabled = $true; ForwardTo = @('"Ext" [SMTP:collect@proton.me]'); ForwardAsAttachmentTo = $null; RedirectTo = $null; DeleteMessage = $false; MoveToFolder = $null; MarkAsRead = $false },
    [pscustomobject]@{ Name = 'Old'; Enabled = $false; ForwardTo = @('[SMTP:old@outlook.com]'); ForwardAsAttachmentTo = $null; RedirectTo = $null; DeleteMessage = $false; MoveToFolder = $null; MarkAsRead = $false }
)
$global:Perms += @([pscustomobject]@{ User = 'bob@contoso.com'; AccessRights = @('FullAccess'); IsInherited = $false; Deny = $false })
$global:SendAs = @([pscustomobject]@{ Trustee = 'NT AUTHORITY\SELF'; AccessRights = @('SendAs'); IsInherited = $false }, [pscustomobject]@{ Trustee = 'mallory@contoso.com'; AccessRights = @('SendAs'); IsInherited = $false })
$global:Methods += @(
    [pscustomobject]@{ Id = 'm2'; AdditionalProperties = @{ '@odata.type' = '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod'; displayName = 'iPhone 15'; createdDateTime = $now.AddDays(-2).ToString('o') } },
    [pscustomobject]@{ Id = 'm3'; AdditionalProperties = @{ '@odata.type' = '#microsoft.graph.phoneAuthenticationMethod'; phoneNumber = '+1 555 0100' } }
)
$global:DirAudits = @(
    [pscustomobject]@{ Kind = 'target'; Id = 'a1'; ActivityDisplayName = 'User registered security info'; ActivityDateTime = $now.AddDays(-2); TargetResources = @([pscustomobject]@{ DisplayName = 'Alice Smith' }) },
    [pscustomobject]@{ Kind = 'actor'; Id = 'a2'; ActivityDisplayName = 'Consent to application'; ActivityDateTime = $now.AddDays(-3); TargetResources = @([pscustomobject]@{ DisplayName = 'Mail Sync Pro' }) },
    [pscustomobject]@{ Kind = 'actor'; Id = 'a1'; ActivityDisplayName = 'User registered security info'; ActivityDateTime = $now.AddDays(-2); TargetResources = @() }
)
$global:Grants += @([pscustomobject]@{ ClientId = 'sp-1'; Scope = 'Mail.ReadWrite offline_access'; ConsentType = 'Principal' })
$global:Apps['sp-1'] = [pscustomobject]@{ DisplayName = 'Mail Sync Pro'; AppOwnerOrganizationId = '99999999-0000-0000-0000-000000000000'; VerifiedPublisher = [pscustomobject]@{ DisplayName = $null }; PublisherName = 'mailsync' }
$global:Sent += @(for ($k = 0; $k -lt 250; $k++) { [pscustomobject]@{ Received = $now.AddDays(-1).Date.AddHours(14).AddSeconds($k); RecipientAddress = 'contact@fabrikam.com' } })
$global:AuditMine += @([pscustomobject]@{ CreationDate = $now.AddHours(-24); Operations = 'New-InboxRule'; UserIds = 'alice@contoso.com'; RecordType = 'ExchangeAdmin'; AuditData = '{"ClientIP":"198.51.100.66"}' })
$global:AuditMine += @(for ($k = 0; $k -lt 150; $k++) { [pscustomobject]@{ CreationDate = $now.AddHours(-12).AddSeconds($k); Operations = 'HardDelete'; UserIds = 'alice@contoso.com'; RecordType = 'ExchangeItemGroup'; AuditData = '{}' } })
$global:AuditByOthers = @([pscustomobject]@{ CreationDate = $now.AddDays(-2); Operations = 'Add-MailboxPermission'; UserIds = 'admin@contoso.com'; RecordType = 'ExchangeAdmin'; AuditData = '{"ClientIP":"203.0.113.5"}' },
    [pscustomobject]@{ CreationDate = $now.AddHours(-20); Operations = 'Set-Mailbox'; UserIds = 'alice@contoso.com'; RecordType = 'ExchangeAdmin'; AuditData = '{"ClientIP":"198.51.100.66"}' })
'@

try {
    # --- Compromised user: sign in to both with device code ----------------------------------
    $r = Invoke-Mocked 'compromised' ("{0}`n{1}" -f $mocks, $compromised) @('-UserPrincipalName', 'alice@contoso.com', '-DeviceCode')
    Assert-Clean $r 'compromised'
    Assert-True 'Graph: exactly the seven read-only scopes, device code, process-only token' (@($r.Calls | Where-Object { $_ -eq 'Connect-MgGraph Scopes=User.Read.All,AuditLog.Read.All,UserAuthenticationMethod.Read.All,DelegatedPermissionGrant.Read.All,Application.Read.All,IdentityRiskyUser.Read.All,IdentityRiskEvent.Read.All DeviceCode=True ContextScope=Process' }).Count -eq 1) ($r.Calls -join "`n")
    Assert-True 'Exchange: loads only the read cmdlets, device code' (@($r.Calls | Where-Object { $_ -eq 'Connect-ExchangeOnline CommandName=Get-AcceptedDomain,Get-InboxRule,Get-MessageTraceV2,Get-AdminAuditLogConfig,Search-UnifiedAuditLog Device=True' }).Count -eq 1) ($r.Calls -join "`n")
    Assert-True 'Both connections it opened are closed' (($r.Calls -contains 'Disconnect-MgGraph') -and ($r.Calls -contains 'Disconnect-ExchangeOnline'))
    Assert-Equal 'CheckId C5' 'C5' $r.Result.CheckId
    Assert-True 'Sign-ins filtered by user and the 14-day window' (@($r.Calls | Where-Object { $_ -match "^Get-MgAuditLogSignIn userId eq 'id-alice' and createdDateTime ge \d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$" }).Count -eq 1) ($r.Calls -join "`n")
    Assert-True 'Message trace read in pieces of at most 10 days' (@($r.Calls | Where-Object { $_ -like 'Get-MessageTraceV2*' }).Count -eq 2)
    Assert-Finding $r 'Account read' 'Account' 'INFO' 'Alice Smith: sign-in allowed'
    Assert-Finding $r 'New country = WARN High' 'New sign-in countries' 'WARN' '^Successful sign-ins from a country not seen earlier in the window: NG .*Usual: US\.$' 'High'
    Assert-Finding $r 'Failed MFA then success = WARN High' 'Failed MFA then success' 'WARN' 'MFA failed \(NG, 198\.51\.100\.66\) -> .* success \(NG' 'High'
    Assert-Finding $r 'IMAP sign-in = WARN High' 'Legacy-protocol sign-ins' 'WARN' 'IMAP4 x1' 'High'
    Assert-Finding $r 'Two countries within hours = WARN High' 'Two countries within hours' 'WARN' 'US .* -> NG' 'High'
    Assert-Finding $r 'High risk with detection' 'Risk' 'WARN' '^Risk level high \(atRisk\); 1 risk detection.*unfamiliarFeatures' 'High'
    Assert-Finding $r 'Attacker rules flagged, harmless and disabled not' 'Inbox rules' 'WARN' '^3 of 5 rule\(s\) look like an attacker''s: "\." \(moves to RSS Feeds, marks as read\); "Payments" \(deletes mail, matches "invoice; payment"\); "Sync" \(forwards outside to collect@proton\.me\)\.$' 'High'
    Assert-Equal 'InboxRules table lists every rule' 5 @($r.Result.Data.InboxRules).Count
    Assert-Finding $r 'External forwarding = WARN High' 'Mailbox forwarding' 'WARN' 'alice\.backup@gmail\.com \(NO copy' 'High'
    Assert-Finding $r 'Delegates listed without SELF' 'Delegates' 'INFO' '^bob@contoso\.com \(Full Access\); mallory@contoso\.com \(Send As\); Carol Assistant \(Send on Behalf\)\.'
    Assert-Finding $r 'MFA method added in the window = WARN High' 'MFA methods' 'WARN' 'microsoftAuthenticator iPhone 15 \(added .*User registered security info' 'High'
    Assert-True 'Password is not listed as an MFA method' (@($r.Result.Data.MfaMethods | Where-Object { $_.Type -eq 'password' }).Count -eq 0)
    Assert-True 'Directory audit read once per direction, duplicates merged' ((@($r.Calls | Where-Object { $_ -like 'Get-MgAuditLogDirectoryAudit*' }).Count -eq 2))
    Assert-Finding $r 'Recent mail-app consent = WARN High; Microsoft app not flagged' 'App consents' 'WARN' '^1 of 2 app grant\(s\) need a look: "Mail Sync Pro" \(consented in the last 14 days, mail/file access, publisher not verified' 'High'
    Assert-Finding $r 'Sent-mail spike = WARN High' 'Sent mail' 'WARN' 'usually 3 a day\); unusual days: \d{4}-\d\d-\d\d: 253' 'High'
    Assert-Finding $r 'Audit log summarised' 'Audit log' 'INFO' 'HardDelete x150'
    Assert-Finding $r 'Rule, forwarding and permission changes = WARN High' 'Mailbox changes' 'WARN' 'Add-MailboxPermission by admin@contoso\.com from 203\.0\.113\.5.*New-InboxRule by alice@contoso\.com from 198\.51\.100\.66.*Set-Mailbox' 'High'
    Assert-Finding $r 'Mass deletion = WARN High' 'Mass deletion' 'WARN' '^150 messages deleted' 'High'
    Assert-Finding $r 'Compromise indicators counted' 'Compromise indicators' 'WARN' 'sign\(s\) of compromise' 'High'
    $todo = [string](Get-Finding $r 'What to do now').Detail
    foreach ($p in 'Reset the password of alice@contoso\.com', 'Revoke all sessions', 'Remove the inbox rule "\."', 'Remove the inbox rule "Payments"', 'Remove the inbox rule "Sync"',
        'Remove the mailbox forwarding to alice\.backup@gmail\.com', 'iPhone 15', 'Mail Sync Pro', 'Check Sent Items, Deleted Items and the message trace', 'mallory@contoso\.com', 'Tell the client') {
        Assert-True ('What to do now names: {0}' -f $p) ($todo -match $p) $todo
    }
    Assert-True 'What to do now printed as a section' ($r.Console -match 'What to do now \(by hand; this script changed nothing\)')
    Assert-True 'Findings about the user carry the UPN' ([string](Get-Finding $r 'Inbox rules').Target -eq 'alice@contoso.com')
    Assert-NoRepeatedStep $r 'compromised'
    $steps = @(Get-Step $r)
    Assert-True 'urgent (IMAP sign-in 12 h ago): step 1 blocks sign-in, saying why' ($steps[0] -match '^Block sign-in for alice@contoso\.com now \(admin center > Users > Active users > Block sign-in\), because of .*a sign-in over IMAP4 at ' -and $steps[0] -match 'Order matters') $steps[0]
    Assert-True 'urgent: then revoke sessions, then reset the password' ($steps[1] -match '^Revoke all sessions' -and $steps[2] -match '^Reset the password') (($steps | Select-Object -First 3) -join ' | ')
    Assert-True 'urgent: sign-in is allowed again only at the end' (@($steps | Where-Object { $_ -match '^Allow sign-in again only after' }).Count -eq 1)
    Assert-True 'specific steps replace the generic ones' (@($steps | Where-Object { $_ -match '^Review the MFA methods with the user; delete any|^Review the app consents with the user|^Check Sent Items and Deleted Items for mail' }).Count -eq 0) ($steps -join ' | ')
    foreach ($t in 'SignIns', 'RiskDetections', 'InboxRules', 'Delegates', 'MfaMethods', 'AppConsents', 'SentPerDay', 'AuditEvents', 'NextSteps') { Assert-True ('table {0}' -f $t) (@($r.Result.Data.$t).Count -gt 0) }

    # --- No P1 / P2, clean user, existing connections, auditing off ----------------------------
    $r = Invoke-Mocked 'nop1' ("{0}`n{1}`n`$global:NoPremium = `$true`n`$global:AuditOn = `$false" -f $mocks, $connected) @('-UserPrincipalName', 'alice@contoso.com')
    Assert-Clean $r 'no P1/P2'
    Assert-True 'no P1/P2: no new sign-in, nothing closed' ($r.Calls -notcontains 'Disconnect-MgGraph' -and @($r.Calls | Where-Object { $_ -like 'Connect-*' }).Count -eq 0) ($r.Calls -join "`n")
    Assert-Finding $r 'no P1: sign-ins SKIPPED with the reason' 'Sign-ins' 'SKIPPED' 'no Microsoft Entra ID P1 or P2 license.*sign-in logs'
    Assert-Finding $r 'no P2: risk SKIPPED with the reason' 'Risk' 'SKIPPED' 'no Microsoft Entra ID P2 license.*Entra ID Protection'
    Assert-Finding $r 'auditing off: audit log SKIPPED with the reason' 'Audit log' 'SKIPPED' 'turned off'
    foreach ($check in 'Inbox rules', 'Mailbox forwarding', 'Delegates', 'MFA methods', 'App consents', 'Sent mail') { Assert-Finding $r ('clean: {0} PASS' -f $check) $check 'PASS' }
    Assert-Finding $r 'clean: no compromise indicator, with the caveat' 'Compromise indicators' 'INFO' 'does not prove the account is safe'
    Assert-Finding $r 'clean: What to do now still lists the basics' 'What to do now' 'INFO' '^1\. Reset the password'
    Assert-NoRepeatedStep $r 'clean'
    $steps = @(Get-Step $r)
    Assert-True 'clean: password reset first, then revoke, no block step' ($steps[0] -match '^Reset the password' -and $steps[1] -match '^Revoke all sessions' -and @($steps | Where-Object { $_ -match '^Block sign-in|^Allow sign-in again' }).Count -eq 0) ($steps -join ' | ')
    foreach ($g in '^Review the MFA methods with the user; delete any they did not add\.$', '^Review the app consents with the user', '^Check Sent Items and Deleted Items for mail the user did not write') {
        Assert-True ('clean: generic step present once: {0}' -f $g) (@($steps | Where-Object { $_ -match $g }).Count -eq 1) ($steps -join ' | ')
    }

    # --- Sent-mail spike today, nothing else: block first -----------------------------------------
    $spikeToday = @'
$span = [math]::Max(1, ($now - $now.Date).TotalSeconds - 1)
$global:Sent += @(for ($k = 0; $k -lt 250; $k++) { [pscustomobject]@{ Received = $now.Date.AddSeconds($span * $k / 250); RecipientAddress = 'contact@fabrikam.com' } })
'@
    $r = Invoke-Mocked 'spike-today' ("{0}`n{1}`n{2}" -f $mocks, $connected, $spikeToday) @('-UserPrincipalName', 'alice@contoso.com')
    Assert-Clean $r 'spike today'
    Assert-NoRepeatedStep $r 'spike today'
    $steps = @(Get-Step $r)
    Assert-True 'spike today: step 1 blocks sign-in because of the mail sent today' ($steps[0] -match '^Block sign-in for alice@contoso\.com now .*because of \d+ messages sent today') $steps[0]
    Assert-True 'spike today: then revoke, then reset' ($steps[1] -match '^Revoke all sessions' -and $steps[2] -match '^Reset the password') (($steps | Select-Object -First 3) -join ' | ')

    # --- Suspicious sign-ins, but none in the last 24 hours and the spike was yesterday ------------
    $older = $compromised -replace "\(New-SignIn \`$now\.AddHours\(-12\) 'NG'", "(New-SignIn `$now.AddHours(-30) 'NG'"
    $r = Invoke-Mocked 'not-urgent' ("{0}`n{1}" -f $mocks, $older) @('-UserPrincipalName', 'alice@contoso.com', '-DeviceCode')
    Assert-Clean $r 'not urgent'
    Assert-Finding $r 'not urgent: still flagged as a legacy sign-in' 'Legacy-protocol sign-ins' 'WARN'
    Assert-NoRepeatedStep $r 'not urgent'
    $steps = @(Get-Step $r)
    Assert-True 'not urgent: usual order, no block step' ($steps[0] -match '^Reset the password' -and $steps[1] -match '^Revoke all sessions' -and @($steps | Where-Object { $_ -match '^Block sign-in|^Allow sign-in again' }).Count -eq 0) (($steps | Select-Object -First 3) -join ' | ')

    # --- Unknown user ------------------------------------------------------------------------------
    $r = Invoke-Mocked 'unknown' ("{0}`n{1}" -f $mocks, $connected) @('-UserPrincipalName', 'ghost@contoso.com')
    Assert-Clean $r 'unknown user'
    Assert-Finding $r 'unknown: account FAIL' 'Account' 'FAIL' 'No user ghost@contoso\.com'
    Assert-Finding $r 'unknown: mailbox FAIL' 'Mailbox' 'FAIL' 'No mailbox ghost@contoso\.com'
    Assert-Finding $r 'unknown: sign-ins SKIPPED, not ERROR' 'Sign-ins' 'SKIPPED' 'was not found'
    Assert-Finding $r 'unknown: rules SKIPPED, not ERROR' 'Inbox rules' 'SKIPPED' 'mailbox could not be read'

    # --- Role too narrow for message trace and the audit log ---------------------------------------
    $r = Invoke-Mocked 'denied' ("{0}`n{1}`n`$global:DenyTrace = `$true`n`$global:DenyAudit = `$true" -f $mocks, $connected) @('-UserPrincipalName', 'alice@contoso.com')
    Assert-Clean $r 'denied'
    Assert-Finding $r 'denied: sent mail SKIPPED' 'Sent mail' 'SKIPPED' 'may not read this'
    Assert-True 'denied: Global Reader named for message trace' ([string](Get-Finding $r 'Sent mail').Recommendation -match 'Global Reader')
    Assert-Finding $r 'denied: audit log SKIPPED' 'Audit log' 'SKIPPED' 'may not read this'
    Assert-True 'denied: View-Only Audit Logs named for the audit log' ([string](Get-Finding $r 'Audit log').Recommendation -match 'View-Only Audit Logs')
    Assert-Finding $r 'denied: the rest still runs' 'Inbox rules' 'PASS'

    # --- -Days 31 is refused -----------------------------------------------------------------------
    $r = Invoke-Mocked 'days31' $mocks @('-UserPrincipalName', 'alice@contoso.com', '-Days', '31')
    Assert-True '-Days 31: refused by parameter validation' ($r.Console -match 'Days' -and $r.Console -match 'greater than the maximum allowed range|ValidateRange|maximum allowed') $r.Console
    Assert-True '-Days 31: no result, nothing connects' ($null -eq $r.Result -and $r.Calls.Count -eq 0)

    # --- No Identity Protection scopes -------------------------------------------------------------
    $r = Invoke-Mocked 'scope' ("{0}`n{1}`n`$global:GraphScopes = @('User.Read.All', 'AuditLog.Read.All', 'UserAuthenticationMethod.Read.All', 'DelegatedPermissionGrant.Read.All', 'Application.Read.All')" -f $mocks, $connected) @('-UserPrincipalName', 'alice@contoso.com', '-Days', '30')
    Assert-Clean $r 'missing scope'
    Assert-Finding $r 'missing scopes named' 'Graph scopes' 'WARN' 'missing IdentityRiskyUser\.Read\.All, IdentityRiskEvent\.Read\.All'
    Assert-Finding $r 'risk SKIPPED naming the scope' 'Risk' 'SKIPPED' 'Needs the IdentityRiskyUser\.Read\.All scope'
    Assert-True '-Days 30: message trace in 3 pieces' (@($r.Calls | Where-Object { $_ -like 'Get-MessageTraceV2*' }).Count -eq 3)

    # --- Not signed in, no terminal ---------------------------------------------------------------
    $r = Invoke-Mocked 'noninteractive' $mocks @('-UserPrincipalName', 'alice@contoso.com')
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
