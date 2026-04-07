<#
.SYNOPSIS
  Enforces Windows auto-lock after inactivity by setting Machine Inactivity Limit.

.DESCRIPTION
  Sets the registry value:
    HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\InactivityTimeoutSecs (REG_DWORD)

  This maps to:
    Local Security Policy → Security Options → "Interactive logon: Machine inactivity limit"

.PARAMETER Minutes
  Idle time in minutes before the session locks. Common values: 15 or 30.

.PARAMETER Force
  If set, will write the value even if it already matches.

.EXAMPLE
  .\Set-InactivityTimeout.ps1 -Minutes 15

.EXAMPLE
  .\Set-InactivityTimeout.ps1 -Minutes 30 -Force
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
  [Parameter(Mandatory=$false)]
  [ValidateRange(1, 1440)]
  [int]$Minutes = 60,

  [switch]$Force
)

$RegPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$ValueName = 'InactivityTimeoutSecs'
$Seconds = $Minutes * 60

function Test-IsAdmin {
  $current = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($current)
  return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
  Write-Error "Admin rights required. Run PowerShell as Administrator."
  exit 1
}

try {
  if (-not (Test-Path $RegPath)) {
    if ($PSCmdlet.ShouldProcess($RegPath, "Create registry key")) {
      New-Item -Path $RegPath -Force | Out-Null
    }
  }

  $currentValue = $null
  try {
    $currentValue = (Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction Stop).$ValueName
  } catch {
    # value doesn't exist yet — fine
  }

  if (-not $Force -and $null -ne $currentValue -and [int]$currentValue -eq $Seconds) {
    Write-Output "No change needed. $ValueName already set to $Seconds seconds ($Minutes minutes)."
    exit 0
  }

  if ($PSCmdlet.ShouldProcess("$RegPath\$ValueName", "Set to $Seconds (DWORD)")) {
    New-ItemProperty -Path $RegPath -Name $ValueName -PropertyType DWord -Value $Seconds -Force | Out-Null
  }

  $verify = (Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction Stop).$ValueName
  if ([int]$verify -ne $Seconds) {
    throw "Verification failed. Expected $Seconds but found $verify."
  }

  Write-Output "Success. Set $ValueName to $Seconds seconds ($Minutes minutes)."
  Write-Output "Note: If a Domain GPO enforces this setting, it may be overwritten on the next GP refresh."
  exit 0
}
catch {
  Write-Error ("Failed to set inactivity timeout: {0}" -f $_.Exception.Message)
  exit 2
}