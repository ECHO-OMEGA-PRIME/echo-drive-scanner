# Intelligent Drive Scanner service launcher (port 8460).
# Idempotent and secure-by-default: non-loopback access is restricted by the
# application middleware to exact trusted client IPs or an internal token.
$ErrorActionPreference = 'Stop'
$repo = 'C:\Users\bobmc\echo-drive-scanner'
$py   = Join-Path $repo '.venv\Scripts\python.exe'
$busy = Get-NetTCPConnection -LocalPort 8460 -State Listen -ErrorAction SilentlyContinue
if ($busy) { exit 0 }

if (-not $env:DRIVESCAN_HOST) { $env:DRIVESCAN_HOST = '0.0.0.0' }
if (-not $env:DRIVESCAN_PORT) { $env:DRIVESCAN_PORT = '8460' }
if (-not $env:DRIVESCAN_TRUSTED_CLIENTS) {
  # HAMMER loopback plus the FORGE Tailscale identity used by the SDK gate.
  $env:DRIVESCAN_TRUSTED_CLIENTS = '127.0.0.1,::1,100.113.87.107'
}
if (-not $env:DRIVESCAN_PROTECTED_PATHS) {
  # Fail-safe baseline. Operators should extend this with every personal root.
  $env:DRIVESCAN_PROTECTED_PATHS = @(
    'C:\Users\bobmc\Documents\personal',
    'C:\Users\bobmc\OneDrive\Personal',
    'C:\ECHO_OMEGA_PRIME\MEMORY_CORE',
    'C:\ECHO_OMEGA_PRIME\VAULT'
  ) -join [IO.Path]::PathSeparator
}

New-Item -ItemType Directory -Force -Path (Join-Path $repo 'logs') | Out-Null
Start-Process -FilePath $py `
  -ArgumentList '-m','uvicorn','dashboard.server:app','--host',$env:DRIVESCAN_HOST,'--port',$env:DRIVESCAN_PORT `
  -WorkingDirectory $repo -WindowStyle Hidden `
  -RedirectStandardOutput (Join-Path $repo 'logs\service_out.log') `
  -RedirectStandardError  (Join-Path $repo 'logs\service_err.log')
