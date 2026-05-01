<#
.SYNOPSIS
    Comprehensive RC4 Kerberos usage audit report for Active Directory environments.

.DESCRIPTION
    Queries Security Event Logs (Event IDs 4768 and 4769) on the local domain controller
    to produce a human-readable console summary and CSV exports covering:
      - Total RC4 usage event counts (last 30 days)
      - Accounts classified as RC4-Only (no AES keys observed)
      - Accounts classified as RC4+AES (both key types observed)
      - Observed RC4 ticket/session-key usage per unique account

    Both Microsoft scripts (Get-KerbEncryptionUsage.ps1 and List-AccountKeys.ps1) are
    incorporated inline. Run this directly on a Domain Controller as a privileged account.

.PARAMETER Since
    How far back to search. Defaults to 30 days.

.PARAMETER ReportDir
    Directory where CSV exports are saved. Defaults to the script's directory.

.PARAMETER NoCSV
    Switch to suppress CSV output and print console only.

.EXAMPLE
    .\Invoke-RC4AuditReport.ps1

.EXAMPLE
    .\Invoke-RC4AuditReport.ps1 -Since (Get-Date).AddDays(-7) -ReportDir "C:\Reports"

.NOTES
    Requires: Windows Server 2016 (with Jan 2025 CU) or 2019+ for enriched event metadata.
    Must be run on a Domain Controller with access to the Security Event Log.
    Incorporates Microsoft open-source scripts from https://github.com/microsoft/Kerberos-Crypto
    Original script authors: Will Aftring (wiaftrin) - Microsoft
#>

[CmdletBinding()]
param(
    [DateTime]$Since      = (Get-Date).AddDays(-30),
    [string]  $ReportDir  = $(if ($PSScriptRoot) { $PSScriptRoot } else { $PWD.Path }),
    [switch]  $NoCSV
)

# Set-StrictMode removed: causes false positives on scalar event results
$ErrorActionPreference = "Stop"

#region ── Preflight ──────────────────────────────────────────────────────────

if ((Get-Variable -Name psISE -ErrorAction SilentlyContinue) -and $psISE) {
    Write-Error "PowerShell ISE is not supported. Run from a standard PowerShell console."
    return
}

# Ensure output directory exists
if (-not (Test-Path $ReportDir)) {
    New-Item -ItemType Directory -Path $ReportDir | Out-Null
}

$Timestamp   = Get-Date -Format "yyyyMMdd_HHmmss"
$DomainName  = $env:USERDNSDOMAIN
$DCName      = "$env:COMPUTERNAME.$DomainName"

#endregion

#region ── Shared Constants ───────────────────────────────────────────────────

$MIN_PROPERTY_COUNT = 21

# AES-SHA1 key string differs between WS 2022 and WS 2025+
$AES_SHA1_FILTER_2022 = "AES-SHA1"
$AES_SHA1_FILTER_2025 = "SHA96"

$XPathQuery = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4769) and (TimeCreated[@SystemTime >= '$($Since.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss"))'])]]
    </Select>
  </Query>
  <Query Id="1" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4768) and (TimeCreated[@SystemTime >= '$($Since.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss"))'])]]
    </Select>
  </Query>
</QueryList>
"@

#endregion

#region ── Encryption Type Classes (from Get-KerbEncryptionUsage) ─────────────

class EncryptionType {
    [string]$Name
    [int]   $Value

    EncryptionType([string]$name, [int]$value) {
        $this.Name  = $name
        $this.Value = $value
    }

    [string] ToString() { return $this.Name }

    [bool] Equals([object]$other) {
        if ($null -eq $other -or $this.GetType() -ne $other.GetType()) { return $false }
        $e = [EncryptionType]$other
        return ($e.Name -eq $this.Name -and $e.Value -eq $this.Value)
    }
}

enum RequestType { AS; TGS }

class KerbRequest {
    hidden [long]    $RecordId
    [string]         $MachineName
    [DateTime]       $Time
    [string]         $Requestor
    [string]         $Source
    [string]         $Target
    [RequestType]    $Type
    [EncryptionType] $Ticket
    [EncryptionType] $SessionKey
}

#endregion

#region ── Account Key Classes (from List-AccountKeys) ───────────────────────

enum AccountType { User; Machine; Service }

class AccountKeyRecord {
    hidden [long]  $RecordId
    [string]       $MachineName
    [datetime]     $Time
    [string]       $Name
    [AccountType]  $Type
    [string[]]     $Keys          # parsed array of key names
    [string]       $KeysDisplay   # semicolon-joined for display / CSV
}

#endregion

#region ── Helper: Raw Event Query ───────────────────────────────────────────

function Get-SecurityEvents {
    param([string]$Query)
    $results = $null
    try {
        $results = Get-WinEvent -FilterXPath $Query -LogName Security -ErrorAction Stop
    }
    catch {
        if ($_.FullyQualifiedErrorId -eq "NoMatchingEventsFound,Microsoft.PowerShell.Commands.GetWinEventCommand") {
            Write-Warning "No matching Kerberos events found in the specified time window."
        }
        else { throw $_ }
    }
    return $results
}

#endregion

#region ── Encryption Type Helpers ───────────────────────────────────────────

$ETypes = @{
    0x01 = [EncryptionType]::new("DES-CRC",       0x01)
    0x03 = [EncryptionType]::new("DES-MD5",       0x03)
    0x11 = [EncryptionType]::new("AES128-SHA96",  0x11)
    0x12 = [EncryptionType]::new("AES256-SHA96",  0x12)
    0x13 = [EncryptionType]::new("AES128-SHA256", 0x13)
    0x14 = [EncryptionType]::new("AES256-SHA384", 0x14)
    0x17 = [EncryptionType]::new("RC4",           0x17)
    0x18 = [EncryptionType]::new("RC4-EXP",       0x18)
    0xFF = [EncryptionType]::new("Unknown",        0xFF)
}

function Resolve-EType([int]$value) {
    if ($ETypes.ContainsKey($value)) { return $ETypes[$value] }
    return [EncryptionType]::new("Unknown(0x{0:x})" -f $value, $value)
}

#endregion

#region ── Step 1: Pull All Events ───────────────────────────────────────────

Write-Host ""
Write-Host "  Querying Security Event Log on $DCName ..." -ForegroundColor Cyan
Write-Host "  Time window: $($Since.ToString('yyyy-MM-dd HH:mm')) → now" -ForegroundColor Cyan
Write-Host ""

[array]$rawEvents = @(Get-SecurityEvents -Query $XPathQuery)

if ($null -eq $rawEvents -or $rawEvents.Count -eq 0) {
    Write-Warning "No 4768/4769 events found. Ensure Kerberos auditing is enabled and you are running on a DC with Windows Server 2016 (Jan 2025 CU+) or 2019+."
    return
}

# Version check: new event metadata requires >= 21 properties
$sampleEvent = $rawEvents[0]
if ($sampleEvent.Properties.Count -lt $MIN_PROPERTY_COUNT) {
    Write-Error @"
This DC is running an older event schema (property count: $($sampleEvent.Properties.Count)).
Requires Windows Server 2016 with January 2025 Cumulative Update, or Windows Server 2019+.
Please install the latest Windows Updates and retry.
"@
    return
}

Write-Host "  Total raw events retrieved: $($rawEvents.Count)" -ForegroundColor Gray

#endregion

#region ── Step 2: Parse KerbRequest Records (Usage) ─────────────────────────

$allRequests = [System.Collections.Generic.List[KerbRequest]]::new()

foreach ($evt in $rawEvents) {
    $req = [KerbRequest]::new()
    $req.RecordId    = $evt.RecordId
    $req.MachineName = $evt.MachineName
    $req.Time        = $evt.TimeCreated

    $ip = $null
    if ($evt.Id -eq 4769) {
        $req.Target    = $evt.Properties[2].Value
        $req.Ticket    = Resolve-EType -value $evt.Properties[5].Value
        $req.SessionKey= Resolve-EType -value $evt.Properties[20].Value
        $req.Type      = [RequestType]::TGS
        $ip            = $evt.Properties[6].Value
        $req.Source    = $evt.Properties[0].Value
    }
    else {
        # 4768
        $req.Target    = $evt.Properties[3].Value
        $req.Ticket    = Resolve-EType -value $evt.Properties[7].Value
        $req.SessionKey= Resolve-EType -value $evt.Properties[22].Value
        $req.Type      = [RequestType]::AS
        $ip            = $evt.Properties[9].Value
        $req.Source    = $evt.Properties[0].Value
    }

    if ($ip -like "::ffff:*") { $ip = $ip.Replace("::ffff:", "") }
    $req.Requestor = $ip

    $allRequests.Add($req)
}

#endregion

#region ── Step 3: Parse AccountKeyRecord Records (Key Inventory) ─────────────

function Parse-KeyString([string]$rawKeys) {
    $tmp = [System.Collections.Generic.List[string]]::new()
    foreach ($k in ($rawKeys.Split(",") | ForEach-Object { $_.Trim() })) {
        if ($k -eq $AES_SHA1_FILTER_2022) {
            $tmp.Add("AES128-SHA96")
            $tmp.Add("AES256-SHA96")
        }
        else { $tmp.Add($k) }
    }
    return $tmp.ToArray()
}

$allAccountRecords = [System.Collections.Generic.List[AccountKeyRecord]]::new()

foreach ($evt in $rawEvents) {
    $rec         = [AccountKeyRecord]::new()
    $rec.RecordId    = $evt.RecordId
    $rec.MachineName = $evt.MachineName
    $rec.Time        = $evt.TimeCreated

    [string]$rawKeys = $evt.Properties[16].Value
    $rec.Keys        = Parse-KeyString -rawKeys $rawKeys
    $rec.KeysDisplay = $rec.Keys -join "; "

    if ($evt.Id -eq 4769) {
        $target = $evt.Properties[2].Value
        $rec.Name = $target
        $rec.Type = if ($target.EndsWith("$")) { [AccountType]::Machine } else { [AccountType]::Service }
    }
    else {
        $target = $evt.Properties[0].Value
        $rec.Name = $target
        $rec.Type = if ($target.EndsWith("$")) { [AccountType]::Machine } else { [AccountType]::User }
    }

    $allAccountRecords.Add($rec)
}

#endregion

#region ── Step 4: RC4 Usage Statistics ──────────────────────────────────────

[array]$rc4Requests     = @($allRequests | Where-Object { $_.Ticket.Name -in @("RC4","RC4-EXP") -or $_.SessionKey.Name -in @("RC4","RC4-EXP") })
[array]$rc4TicketOnly   = @($allRequests | Where-Object { $_.Ticket.Name -in @("RC4","RC4-EXP") })
[array]$rc4SessionOnly  = @($allRequests | Where-Object { $_.SessionKey.Name -in @("RC4","RC4-EXP") })
[array]$rc4Both         = @($allRequests | Where-Object { $_.Ticket.Name -in @("RC4","RC4-EXP") -and $_.SessionKey.Name -in @("RC4","RC4-EXP") })

$totalEvents     = $allRequests.Count
$totalRC4Events  = $rc4Requests.Count
$pctRC4          = if ($totalEvents -gt 0) { [math]::Round(($totalRC4Events / $totalEvents) * 100, 1) } else { 0 }

# AS vs TGS breakdown
$rc4AS  = @($rc4Requests | Where-Object { $_.Type -eq [RequestType]::AS  }).Count
$rc4TGS = @($rc4Requests | Where-Object { $_.Type -eq [RequestType]::TGS }).Count

#endregion

#region ── Step 5: Deduplicate Accounts by Key Profile ───────────────────────

# For each unique account name, collect the union of all key types seen across all events
$accountKeyMap = @{}

foreach ($rec in $allAccountRecords) {
    $name = $rec.Name.ToLower().Trim()
    if (-not $accountKeyMap.ContainsKey($name)) {
        $accountKeyMap[$name] = @{
            Name       = $rec.Name
            Type       = $rec.Type
            AllKeys    = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            FirstSeen  = $rec.Time
            LastSeen   = $rec.Time
            EventCount = 0
        }
    }
    foreach ($k in $rec.Keys) { $accountKeyMap[$name].AllKeys.Add($k) | Out-Null }
    if ($rec.Time -lt $accountKeyMap[$name].FirstSeen) { $accountKeyMap[$name].FirstSeen = $rec.Time }
    if ($rec.Time -gt $accountKeyMap[$name].LastSeen)  { $accountKeyMap[$name].LastSeen  = $rec.Time }
    $accountKeyMap[$name].EventCount++
}

# Classify: RC4-Only vs RC4+AES
$rc4OnlyAccounts   = [System.Collections.Generic.List[hashtable]]::new()
$rc4PlusAESAccounts= [System.Collections.Generic.List[hashtable]]::new()
$aesOnlyAccounts   = [System.Collections.Generic.List[hashtable]]::new()

foreach ($entry in $accountKeyMap.Values) {
    $keys    = $entry.AllKeys
    $hasRC4  = $keys | Where-Object { $_ -in @("RC4","RC4-EXP") }
    $hasAES  = $keys | Where-Object { $_ -like "AES*" }

    $entry["KeysDisplay"] = ($keys | Sort-Object) -join "; "

    if ($hasRC4 -and -not $hasAES) {
        $rc4OnlyAccounts.Add($entry)
    }
    elseif ($hasRC4 -and $hasAES) {
        $rc4PlusAESAccounts.Add($entry)
    }
    else {
        $aesOnlyAccounts.Add($entry)
    }
}

#endregion

#region ── Step 6: Per-Account RC4 Usage (observed ticket events) ─────────────

# Deduplicate RC4 ticket usage by unique account (source field)
$rc4UsageMap = @{}

foreach ($req in $rc4Requests) {
    $name = $req.Source.ToLower().Trim()
    if (-not $rc4UsageMap.ContainsKey($name)) {
        $rc4UsageMap[$name] = @{
            Account       = $req.Source
            RequestType   = $req.Type.ToString()
            RC4EventCount = 0
            LastRC4Event  = $req.Time
            FirstRC4Event = $req.Time
            SampleTicket  = $req.Ticket.Name
            SampleSessKey = $req.SessionKey.Name
            SampleTarget  = $req.Target
            Requestors    = [System.Collections.Generic.HashSet[string]]::new()
        }
    }
    $rc4UsageMap[$name].RC4EventCount++
    if ($req.Time -gt $rc4UsageMap[$name].LastRC4Event)  { $rc4UsageMap[$name].LastRC4Event  = $req.Time }
    if ($req.Time -lt $rc4UsageMap[$name].FirstRC4Event) { $rc4UsageMap[$name].FirstRC4Event = $req.Time }
    if (-not [string]::IsNullOrWhiteSpace($req.Requestor)) {
        $rc4UsageMap[$name].Requestors.Add($req.Requestor) | Out-Null
    }
}

[array]$rc4UsageList = @($rc4UsageMap.Values | Sort-Object { $_.RC4EventCount } -Descending)

#endregion

#region ── Step 7: Console Report ─────────────────────────────────────────────

$divider    = "=" * 70
$subDivider = "-" * 70

function Write-Header([string]$text) {
    Write-Host ""
    Write-Host $divider -ForegroundColor DarkCyan
    Write-Host "  $text" -ForegroundColor Cyan
    Write-Host $divider -ForegroundColor DarkCyan
}

function Write-SubHeader([string]$text) {
    Write-Host ""
    Write-Host "  $text" -ForegroundColor Yellow
    Write-Host "  $subDivider" -ForegroundColor DarkYellow
}

Clear-Host

Write-Host ""
Write-Host $divider -ForegroundColor DarkCyan
Write-Host "  RC4 KERBEROS AUDIT REPORT" -ForegroundColor White
Write-Host "  Domain Controller : $DCName" -ForegroundColor Gray
Write-Host "  Report Generated  : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
Write-Host "  Audit Window      : $($Since.ToString('yyyy-MM-dd')) → $(Get-Date -Format 'yyyy-MM-dd')" -ForegroundColor Gray
Write-Host $divider -ForegroundColor DarkCyan

# ── Section 1: Event Summary ──────────────────────────────────────────────────
Write-Header "SECTION 1 — EVENT SUMMARY (Last 30 Days)"

Write-Host ""
Write-Host ("  {0,-40} {1,10}" -f "Total Kerberos events (4768+4769):",   $totalEvents)   -ForegroundColor White
Write-Host ("  {0,-40} {1,10}" -f "Total RC4 usage events:",              $totalRC4Events) -ForegroundColor $(if ($totalRC4Events -gt 0) {"Red"} else {"Green"})
Write-Host ("  {0,-40} {1,9}%" -f "RC4 as % of all Kerberos events:",     $pctRC4)         -ForegroundColor $(if ($pctRC4 -gt 10) {"Red"} elseif ($pctRC4 -gt 0) {"Yellow"} else {"Green"})
Write-Host ""
Write-Host ("  {0,-40} {1,10}" -f "  ↳ RC4 in AS requests  (TGT):",      $rc4AS)  -ForegroundColor Gray
Write-Host ("  {0,-40} {1,10}" -f "  ↳ RC4 in TGS requests (SvcTicket):", $rc4TGS) -ForegroundColor Gray
Write-Host ("  {0,-40} {1,10}" -f "  ↳ RC4 Ticket + RC4 Session Key:",   ($rc4Both).Count) -ForegroundColor Gray
Write-Host ("  {0,-40} {1,10}" -f "  ↳ RC4 Ticket only:",                ($rc4TicketOnly).Count) -ForegroundColor Gray
Write-Host ("  {0,-40} {1,10}" -f "  ↳ RC4 Session Key only:",           ($rc4SessionOnly).Count) -ForegroundColor Gray

# ── Section 2: Account Classification Summary ─────────────────────────────────
Write-Header "SECTION 2 — ACCOUNT CLASSIFICATION (by Available Keys)"

Write-Host ""
Write-Host ("  {0,-40} {1,10}" -f "Unique accounts observed (total):",    $accountKeyMap.Count)        -ForegroundColor White
Write-Host ("  {0,-40} {1,10}" -f "RC4-ONLY accounts (no AES keys):",    $rc4OnlyAccounts.Count)   -ForegroundColor $(if ($rc4OnlyAccounts.Count -gt 0) {"Red"} else {"Green"})
Write-Host ("  {0,-40} {1,10}" -f "RC4 + AES accounts (both key types):", $rc4PlusAESAccounts.Count) -ForegroundColor $(if ($rc4PlusAESAccounts.Count -gt 0) {"Yellow"} else {"Green"})
Write-Host ("  {0,-40} {1,10}" -f "AES-Only accounts (no RC4 keys):",    $aesOnlyAccounts.Count)   -ForegroundColor Green
Write-Host ""
Write-Host "  NOTE: Key classification is based on key availability observed in event" -ForegroundColor DarkGray
Write-Host "  log metadata, not necessarily the encryption type used for the ticket." -ForegroundColor DarkGray

# ── Section 3: RC4-Only Accounts ──────────────────────────────────────────────
Write-Header "SECTION 3 — RC4-ONLY ACCOUNTS (HIGH PRIORITY)"

if ($rc4OnlyAccounts.Count -eq 0) {
    Write-Host ""
    Write-Host "  ✓ No RC4-only accounts detected. All observed accounts have AES keys." -ForegroundColor Green
}
else {
    Write-Host ""
    Write-Host ("  {0,-35} {1,-10} {2,-10} {3,-22} {4}" -f "Account","Type","Events","Last Seen","Available Keys") -ForegroundColor White
    Write-Host ("  {0,-35} {1,-10} {2,-10} {3,-22} {4}" -f ("-"*33),("-"*8),("-"*8),("-"*20),("-"*30)) -ForegroundColor DarkGray

    foreach ($acct in ($rc4OnlyAccounts | Sort-Object { $_.EventCount } -Descending)) {
        Write-Host ("  {0,-35} {1,-10} {2,-10} {3,-22} {4}" -f `
            $acct.Name,
            $acct.Type,
            $acct.EventCount,
            $acct.LastSeen.ToString("yyyy-MM-dd HH:mm"),
            $acct.KeysDisplay) -ForegroundColor Red
    }
}

# ── Section 4: RC4 + AES Accounts ─────────────────────────────────────────────
Write-Header "SECTION 4 — RC4 + AES ACCOUNTS (MEDIUM PRIORITY)"

if ($rc4PlusAESAccounts.Count -eq 0) {
    Write-Host ""
    Write-Host "  ✓ No RC4+AES accounts detected." -ForegroundColor Green
}
else {
    Write-Host ""
    Write-Host ("  {0,-35} {1,-10} {2,-10} {3,-22} {4}" -f "Account","Type","Events","Last Seen","Available Keys") -ForegroundColor White
    Write-Host ("  {0,-35} {1,-10} {2,-10} {3,-22} {4}" -f ("-"*33),("-"*8),("-"*8),("-"*20),("-"*30)) -ForegroundColor DarkGray

    foreach ($acct in ($rc4PlusAESAccounts | Sort-Object { $_.EventCount } -Descending)) {
        Write-Host ("  {0,-35} {1,-10} {2,-10} {3,-22} {4}" -f `
            $acct.Name,
            $acct.Type,
            $acct.EventCount,
            $acct.LastSeen.ToString("yyyy-MM-dd HH:mm"),
            $acct.KeysDisplay) -ForegroundColor Yellow
    }
}

# ── Section 5: Top RC4 Usage by Account ───────────────────────────────────────
Write-Header "SECTION 5 — TOP RC4 TICKET USAGE (by Account)"

if ($rc4UsageList.Count -eq 0) {
    Write-Host ""
    Write-Host "  ✓ No RC4 ticket usage observed in this window." -ForegroundColor Green
}
else {
    $displayCount = [math]::Min(20, $rc4UsageList.Count)
    if ($rc4UsageList.Count -gt 20) {
        Write-Host "  (Showing top 20 of $($rc4UsageList.Count) accounts — full list in CSV)" -ForegroundColor DarkGray
    }
    Write-Host ""
    Write-Host ("  {0,-35} {1,-6} {2,-10} {3,-22} {4,-14} {5}" -f "Account","ReqType","RC4Events","Last RC4 Event","TicketEtype","SessionKeyEtype") -ForegroundColor White
    Write-Host ("  {0,-35} {1,-6} {2,-10} {3,-22} {4,-14} {5}" -f ("-"*33),("-"*6),("-"*9),("-"*20),("-"*13),("-"*14)) -ForegroundColor DarkGray

    $rc4UsageList | Select-Object -First $displayCount | ForEach-Object {
        Write-Host ("  {0,-35} {1,-6} {2,-10} {3,-22} {4,-14} {5}" -f `
            $_.Account,
            $_.RequestType,
            $_.RC4EventCount,
            $_.LastRC4Event.ToString("yyyy-MM-dd HH:mm"),
            $_.SampleTicket,
            $_.SampleSessKey) -ForegroundColor $(if ($_.SampleTicket -eq "RC4") {"Red"} else {"Yellow"})
    }
}

# ── Section 6: Remediation Guidance ───────────────────────────────────────────
Write-Header "SECTION 6 — REMEDIATION GUIDANCE"

Write-Host ""
if ($rc4OnlyAccounts.Count -gt 0) {
    Write-Host "  [!] RC4-ONLY ACCOUNTS — Immediate Action Required:" -ForegroundColor Red
    Write-Host "      These accounts have no AES keys. Common causes:" -ForegroundColor White
    Write-Host "        • Password never reset since before AES support (pre-WS 2003)" -ForegroundColor Gray
    Write-Host "        • msDS-SupportedEncryptionTypes explicitly set to RC4 only" -ForegroundColor Gray
    Write-Host "      Fix: Reset the account password to generate AES keys, then" -ForegroundColor White
    Write-Host "           verify msDS-SupportedEncryptionTypes includes AES bits (0x18+)" -ForegroundColor White
    Write-Host ""
}

if ($rc4PlusAESAccounts.Count -gt 0) {
    Write-Host "  [~] RC4+AES ACCOUNTS — Review and Plan Remediation:" -ForegroundColor Yellow
    Write-Host "      These accounts support AES but RC4 is still present. Consider:" -ForegroundColor White
    Write-Host "        • Setting msDS-SupportedEncryptionTypes = 0x18 (AES128+AES256 only)" -ForegroundColor Gray
    Write-Host "        • Ensuring clients are configured to prefer AES (Group Policy)" -ForegroundColor Gray
    Write-Host "        • Checking for legacy devices/apps still requesting RC4" -ForegroundColor Gray
    Write-Host ""
}

Write-Host "  [i] GENERAL STEPS TO DISABLE RC4:" -ForegroundColor Cyan
Write-Host "      1. GPO: Computer Config > Windows Settings > Security Settings >" -ForegroundColor Gray
Write-Host "         Local Policies > Security Options >" -ForegroundColor Gray
Write-Host "         'Network security: Configure encryption types allowed for Kerberos'" -ForegroundColor Gray
Write-Host "         → Enable only AES128_HMAC_SHA1 and AES256_HMAC_SHA1" -ForegroundColor Gray
Write-Host "      2. Registry (DCs only): HKLM\System\CurrentControlSet\services\KDC" -ForegroundColor Gray
Write-Host "         DefaultDomainSupportedEncTypes = 0x18" -ForegroundColor Gray
Write-Host "      3. Microsoft deadline: RC4 disabled by default in KDC by end of Q2 2026" -ForegroundColor Gray
Write-Host "         Reference: https://support.microsoft.com/help/5073381" -ForegroundColor Gray

Write-Host ""
Write-Host $divider -ForegroundColor DarkCyan
Write-Host "  END OF REPORT" -ForegroundColor White
Write-Host $divider -ForegroundColor DarkCyan
Write-Host ""

#endregion

#region ── Step 8: CSV Exports ────────────────────────────────────────────────

if (-not $NoCSV) {

    # ── CSV 1: All RC4 Usage Events (raw, deduplicated by account) ────────────
    $csvRC4Usage = Join-Path $ReportDir "RC4_Usage_ByAccount_$Timestamp.csv"

    $rc4UsageMap.Values | Sort-Object { $_.RC4EventCount } -Descending |
        Select-Object `
            @{N="Account";         E={$_.Account}},
            @{N="RequestType";     E={$_.RequestType}},
            @{N="RC4EventCount";   E={$_.RC4EventCount}},
            @{N="FirstRC4Event";   E={$_.FirstRC4Event.ToString("yyyy-MM-dd HH:mm:ss")}},
            @{N="LastRC4Event";    E={$_.LastRC4Event.ToString("yyyy-MM-dd HH:mm:ss")}},
            @{N="SampleTicketEtype";   E={$_.SampleTicket}},
            @{N="SampleSessionKeyEtype"; E={$_.SampleSessKey}},
            @{N="SampleTarget";    E={$_.SampleTarget}},
            @{N="UniqueRequestorIPs"; E={($_.Requestors | Sort-Object) -join "; "}} |
        Export-Csv -Path $csvRC4Usage -NoTypeInformation -Encoding UTF8

    # ── CSV 2: RC4-Only Accounts ──────────────────────────────────────────────
    $csvRC4Only = Join-Path $ReportDir "RC4_Only_Accounts_$Timestamp.csv"

    $rc4OnlyAccounts | Sort-Object { $_.EventCount } -Descending |
        Select-Object `
            @{N="AccountName";   E={$_.Name}},
            @{N="AccountType";   E={$_.Type}},
            @{N="EventCount";    E={$_.EventCount}},
            @{N="FirstSeen";     E={$_.FirstSeen.ToString("yyyy-MM-dd HH:mm:ss")}},
            @{N="LastSeen";      E={$_.LastSeen.ToString("yyyy-MM-dd HH:mm:ss")}},
            @{N="AvailableKeys"; E={$_.KeysDisplay}} |
        Export-Csv -Path $csvRC4Only -NoTypeInformation -Encoding UTF8

    # ── CSV 3: RC4+AES Accounts ───────────────────────────────────────────────
    $csvRC4AES = Join-Path $ReportDir "RC4_Plus_AES_Accounts_$Timestamp.csv"

    $rc4PlusAESAccounts | Sort-Object { $_.EventCount } -Descending |
        Select-Object `
            @{N="AccountName";   E={$_.Name}},
            @{N="AccountType";   E={$_.Type}},
            @{N="EventCount";    E={$_.EventCount}},
            @{N="FirstSeen";     E={$_.FirstSeen.ToString("yyyy-MM-dd HH:mm:ss")}},
            @{N="LastSeen";      E={$_.LastSeen.ToString("yyyy-MM-dd HH:mm:ss")}},
            @{N="AvailableKeys"; E={$_.KeysDisplay}} |
        Export-Csv -Path $csvRC4AES -NoTypeInformation -Encoding UTF8

    # ── CSV 4: Full Account Key Inventory (all accounts, all key types) ────────
    $csvAllAccounts = Join-Path $ReportDir "RC4_Full_AccountKey_Inventory_$Timestamp.csv"

    $accountKeyMap.Values | Sort-Object { $_.Name } |
        Select-Object `
            @{N="AccountName";      E={$_.Name}},
            @{N="AccountType";      E={$_.Type}},
            @{N="Classification";   E={
                $k = $_.AllKeys
                $hasRC4 = $k | Where-Object { $_ -in @("RC4","RC4-EXP") }
                $hasAES = $k | Where-Object { $_ -like "AES*" }
                if ($hasRC4 -and -not $hasAES) { "RC4-Only" }
                elseif ($hasRC4 -and $hasAES)  { "RC4+AES" }
                else                            { "AES-Only" }
            }},
            @{N="EventCount";       E={$_.EventCount}},
            @{N="FirstSeen";        E={$_.FirstSeen.ToString("yyyy-MM-dd HH:mm:ss")}},
            @{N="LastSeen";         E={$_.LastSeen.ToString("yyyy-MM-dd HH:mm:ss")}},
            @{N="AvailableKeys";    E={$_.KeysDisplay}} |
        Export-Csv -Path $csvAllAccounts -NoTypeInformation -Encoding UTF8

    Write-Host ""
    Write-Host "  CSV EXPORTS:" -ForegroundColor Cyan
    Write-Host "  ├─ RC4 Usage by Account  : $csvRC4Usage" -ForegroundColor Gray
    Write-Host "  ├─ RC4-Only Accounts     : $csvRC4Only" -ForegroundColor Gray
    Write-Host "  ├─ RC4+AES Accounts      : $csvRC4AES" -ForegroundColor Gray
    Write-Host "  └─ Full Key Inventory    : $csvAllAccounts" -ForegroundColor Gray
    Write-Host ""
}

#endregion