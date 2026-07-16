# echo-drive-scanner dashboard/API launcher (port 8460). Idempotent: no-op if already listening.
$ErrorActionPreference = 'SilentlyContinue'
$repo = 'C:\Users\bobmc\echo-drive-scanner'
$py   = Join-Path $repo '.venv\Scripts\python.exe'
$busy = Get-NetTCPConnection -LocalPort 8460 -State Listen -ErrorAction SilentlyContinue
if ($busy) { exit 0 }
New-Item -ItemType Directory -Force -Path (Join-Path $repo 'logs') | Out-Null
Start-Process -FilePath $py `
  -ArgumentList '-m','uvicorn','dashboard.server:app','--host','0.0.0.0','--port','8460' `
  -WorkingDirectory $repo -WindowStyle Hidden `
  -RedirectStandardOutput (Join-Path $repo 'logs\service_out.log') `
  -RedirectStandardError  (Join-Path $repo 'logs\service_err.log')
