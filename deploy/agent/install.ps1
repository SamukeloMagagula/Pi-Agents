<#
.SYNOPSIS
  Install or update the devmon agent on Windows 10/11 or Windows Server 2019+.

.DESCRIPTION
  Run in PowerShell as Administrator, from a copy of this repository:
    powershell -ExecutionPolicy Bypass -File .\deploy\agent\install.ps1 -Hub 192.168.1.10 -Fingerprint XXXX-...-XXXX

  The agent runs as the built-in LocalService account (no admin rights) from a
  Scheduled Task that starts at boot and restarts every minute if it stops.
  Python 3.9+ must be installed "for all users" (in Program Files), so LocalService can run it.
  Safe to run again: it updates the code and the hub settings, and keeps the agent's key.
  It also turns on Windows Firewall's logging of dropped packets (for port-scan detection);
  -NoFirewallLog leaves the firewall settings untouched.
#>
param(
    [Parameter(Mandatory = $true)][string]$Hub,
    [Parameter(Mandatory = $true)][string]$Fingerprint,
    [int]$Port = 55555,
    [ValidateSet("", "windows-laptop", "windows-server")][string]$Kind = "",
    [switch]$NoFirewallLog
)

$ErrorActionPreference = "Stop"

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this in PowerShell as Administrator."
}

$Repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
if (-not (Test-Path (Join-Path $Repo "src\devmon\agent\__main__.py"))) {
    throw "Can't find the devmon source next to this script."
}

$Root = "C:\ProgramData\DevMon"
$Venv = Join-Path $Root "venv"
$VenvPy = Join-Path $Venv "Scripts\python.exe"
$Ini = Join-Path $Root "agent.ini"
$TaskName = "DevMon Agent"

Write-Host "==> Python"
if (-not (Get-Command py -ErrorAction SilentlyContinue)) {
    throw "The Python launcher 'py' was not found. Install Python 3.9+ from python.org for all users."
}
$BasePy = (& py -3 -c "import sys; print(sys.executable)").Trim()
& py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)"
if ($LASTEXITCODE -ne 0) { throw "Python 3.9 or newer is needed; found $(& py -3 --version)." }
# A per-user install lives in that user's profile, which LocalService cannot read.
if ($BasePy -like "$env:SystemDrive\Users\*") {
    throw "Python at $BasePy is installed for one user only. Reinstall it with 'Install for all users' ticked."
}

Write-Host "==> Stopping a running agent (if any)"
$existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($existing) { Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue }

Write-Host "==> Folder and permissions"
New-Item -ItemType Directory -Force $Root | Out-Null
# Only Administrators, SYSTEM and LocalService: agent.ini may hold a database password and
# agent.key is the device's identity. SIDs, so this works on any Windows language.
# LocalService may only read and run: SYSTEM runs the security helper from this same code,
# so the agent's account must not be able to change it. It writes only to logs\.
& icacls $Root /inheritance:r /grant:r "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" "*S-1-5-19:(OI)(CI)RX" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Setting permissions on $Root failed." }
# Earlier versions gave LocalService Modify on everything. Files it created are owned by it
# (and an owner can change permissions), so hand everything inside to Administrators and
# reset it to the folder's permissions. Only the contents: the folder keeps the ACL above.
if (Get-ChildItem -Force $Root) {
    & icacls (Join-Path $Root "*") /setowner "*S-1-5-32-544" /T /C /Q | Out-Null
    & icacls (Join-Path $Root "*") /reset /T /C /Q | Out-Null
}
$Logs = Join-Path $Root "logs"
New-Item -ItemType Directory -Force $Logs | Out-Null
& icacls $Logs /grant:r "*S-1-5-19:(OI)(CI)M" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Setting permissions on $Logs failed." }
# The helper's results: written by SYSTEM, readable by the agent (inherits read-only).
New-Item -ItemType Directory -Force (Join-Path $Root "helper") | Out-Null

Write-Host "==> Code"
$Src = Join-Path $Root "src"
if (Test-Path $Src) { Remove-Item -Recurse -Force $Src }
New-Item -ItemType Directory -Force $Src | Out-Null
Copy-Item -Recurse (Join-Path $Repo "src\devmon") $Src
Get-ChildItem -Path $Src -Recurse -Directory -Filter "__pycache__" | Remove-Item -Recurse -Force
Copy-Item (Join-Path $Repo "requirements/agent.txt") (Join-Path $Root "requirements-agent.txt") -Force

Write-Host "==> Python environment"
if (-not (Test-Path $VenvPy)) {
    & py -3 -m venv $Venv
    if ($LASTEXITCODE -ne 0) { throw "Creating the Python environment failed." }
}
& $VenvPy -m pip install --quiet --upgrade pip
& $VenvPy -m pip install --quiet -r (Join-Path $Root "requirements-agent.txt")
if ($LASTEXITCODE -ne 0) { throw "Installing the agent's Python packages failed." }
$Site = (& $VenvPy -c "import sysconfig; print(sysconfig.get_paths()['purelib'])").Trim()
Set-Content -Path (Join-Path $Site "devmon.pth") -Value $Src -Encoding ascii

Write-Host "==> Settings"
& $VenvPy (Join-Path $Repo "deploy\agent\write_agent_ini.py") --path $Ini --hub $Hub --port $Port `
    --fingerprint $Fingerprint --key-path (Join-Path $Root "agent.key") --kind $Kind
if ($LASTEXITCODE -ne 0) { throw "Writing agent.ini failed." }

# Creating the key here, before the task starts, means the two never race to create it.
# It inherits the folder's permissions, so LocalService can read it.
$AgentFp = (& $VenvPy -m devmon.agent --config $Ini --show-fingerprint 2>$null).Trim()
if ($LASTEXITCODE -ne 0) { throw "The agent could not read its settings; see the message above." }

Write-Host "==> Security log access"
# Event Log Readers may read every event log, the Security log included (failed logons for
# attack detection), and nothing else. It applies when the agent task next starts, below.
try {
    Add-LocalGroupMember -SID "S-1-5-32-573" -Member ([Security.Principal.SecurityIdentifier]"S-1-5-19") -ErrorAction Stop
} catch [Microsoft.PowerShell.Commands.MemberExistsException] { }

if ($NoFirewallLog) {
    Write-Host "==> Firewall logging skipped (-NoFirewallLog): port-scan detection stays off"
} else {
    Write-Host "==> Firewall logging (for port-scan detection)"
    # Only the firewall service writes here; the agent may only read.
    $FwLog = Join-Path $Root "fwlog"
    New-Item -ItemType Directory -Force $FwLog | Out-Null
    & icacls $FwLog /inheritance:r /grant:r "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" `
        "NT SERVICE\MpsSvc:(OI)(CI)M" "*S-1-5-19:(OI)(CI)RX" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Setting permissions on $FwLog failed." }
    Set-NetFirewallProfile -Profile Domain, Private, Public -LogBlocked True `
        -LogFileName (Join-Path $FwLog "pfirewall.log") -LogMaxSizeKilobytes 4096
}

Write-Host "==> Scheduled task"
$action = New-ScheduledTaskAction -Execute $VenvPy -WorkingDirectory $Root `
    -Argument "-m devmon.agent --config `"$Ini`" --log-file `"$(Join-Path $Logs 'agent.log')`""
$trigger = New-ScheduledTaskTrigger -AtStartup
$taskUser = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\LOCALSERVICE" -LogonType ServiceAccount -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -StartWhenAvailable -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $taskUser `
    -Settings $settings -Description "devmon monitoring agent: reports to the hub at ${Hub}:$Port" -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName

Write-Host "==> Security helper (SYSTEM, hourly)"
# -I: ignore the working directory, PYTHONPATH and user site-packages.
$helperAction = New-ScheduledTaskAction -Execute $VenvPy -WorkingDirectory $Root `
    -Argument "-I -m devmon.agent.helper --out `"$(Join-Path $Root 'helper\status.json')`""
$helperTriggers = @(
    (New-ScheduledTaskTrigger -AtStartup),
    (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Hours 1))
)
$helperUser = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$helperSettings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 30) `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName "DevMon Security Helper" -Action $helperAction -Trigger $helperTriggers `
    -Principal $helperUser -Settings $helperSettings `
    -Description "devmon security helper: Defender, firewall and Windows Update status for the agent" -Force | Out-Null
Start-ScheduledTask -TaskName "DevMon Security Helper"

Write-Host ""
Write-Host "The agent is installed and running."
Write-Host "This device's fingerprint: $AgentFp"
Write-Host "On the dashboard's Devices page, approve the pending device only if its fingerprint matches."
Write-Host "Log: $(Join-Path $Logs 'agent.log')"
Write-Host "Security helper results: $(Join-Path $Root 'helper\status.json') (refreshed hourly)"
