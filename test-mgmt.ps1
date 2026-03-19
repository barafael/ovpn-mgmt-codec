<#
.SYNOPSIS
    Starts OpenVPN with a management-only config and connects the CLI.

.DESCRIPTION
    Launches OpenVPN in held mode (no tunnel, no routing changes) with the
    management interface on 127.0.0.1:7505, then connects openvpn-mgmt-cli.
    OpenVPN is killed automatically when the CLI exits.

    Requires an elevated (Administrator) shell because OpenVPN needs it
    even with "dev null".

.PARAMETER OpenVpnPath
    Path to openvpn.exe. Auto-detected from common install locations.
#>
param(
    [string]$OpenVpnPath
)

$ErrorActionPreference = 'Stop'

# --- Locate openvpn.exe ---------------------------------------------------
if (-not $OpenVpnPath) {
    $candidates = @(
        (Get-Command openvpn -ErrorAction SilentlyContinue).Source,
        "$env:ProgramFiles\OpenVPN\bin\openvpn.exe",
        "${env:ProgramFiles(x86)}\OpenVPN\bin\openvpn.exe",
        "$env:ProgramW6432\OpenVPN\bin\openvpn.exe"
    ) | Where-Object { $_ -and (Test-Path $_) }

    if ($candidates.Count -eq 0) {
        Write-Error "Cannot find openvpn.exe. Pass -OpenVpnPath explicitly."
        return
    }
    $OpenVpnPath = $candidates[0]
}

Write-Host "Using OpenVPN: $OpenVpnPath"
Write-Host ""

# --- Resolve config path --------------------------------------------------
$config = Join-Path $PSScriptRoot 'test-mgmt.ovpn'
if (-not (Test-Path $config)) {
    Write-Error "Config not found: $config"
    return
}

# --- Start OpenVPN --------------------------------------------------------
Write-Host "Starting OpenVPN (management on 127.0.0.1:7505, held)..."
$ovpn = Start-Process -FilePath $OpenVpnPath `
    -ArgumentList "--config `"$config`"" `
    -PassThru -NoNewWindow

# Give it a moment to open the management port.
Start-Sleep -Seconds 2

if ($ovpn.HasExited) {
    Write-Error "OpenVPN exited immediately (exit code $($ovpn.ExitCode)). Run as Administrator?"
    return
}

Write-Host "OpenVPN running (PID $($ovpn.Id)). Connecting CLI..."
Write-Host ""

# --- Build and run the CLI ------------------------------------------------
try {
    cargo run -p openvpn-mgmt-cli -- 127.0.0.1:7505
}
finally {
    # Clean up OpenVPN when the CLI exits.
    if (-not $ovpn.HasExited) {
        Write-Host ""
        Write-Host "Stopping OpenVPN (PID $($ovpn.Id))..."
        Stop-Process -Id $ovpn.Id -Force
    }
}
