# Start the local recon backend in the current console window, or from the
# "arlx-backend" scheduled task.
#
# Why this script exists:
#   * python stdout/stderr used to be thrown away - crashes left no trace;
#   * a backend that lost its listening socket but kept the pipeline running
#     looked "healthy" to everything. This script keeps a watchdog: it probes
#     /api/health every 20s and force-restarts the backend after 3 misses.
#
# NOTE: keep this file pure ASCII. Windows PowerShell 5.1 reads .ps1 in the
# ANSI code page, so UTF-8 Chinese text breaks the parser.
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$env:PYTHONPATH = $root
$env:PYTHONIOENCODING = 'utf-8'
$env:PYTHONDONTWRITEBYTECODE = '1'
if (-not $env:ARLX_HOST) { $env:ARLX_HOST = '127.0.0.1' }
if (-not $env:ARLX_PORT) { $env:ARLX_PORT = '5399' }

$port = [int]$env:ARLX_PORT
$healthUrl = 'http://127.0.0.1:{0}/api/health' -f $port

$logDir = Join-Path $root 'logs'
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir | Out-Null }
$stamp = Get-Date -Format 'yyyyMMdd'
$logFile = Join-Path $logDir ('server-{0}.log' -f $stamp)
$outLog = Join-Path $logDir ('server-{0}.out.log' -f $stamp)
$errLog = Join-Path $logDir ('server-{0}.err.log' -f $stamp)

function Write-Log([string]$msg) {
    $line = '[{0}] {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $msg
    Add-Content -Path $logFile -Value $line -Encoding UTF8
    Write-Host $line
}

function Test-Health {
    try {
        # 10s: during a port scan the loop can legitimately stall for a few
        # seconds; a 5s probe turns that into a "dead" verdict and kills a
        # running task mid-flight.
        $code = & curl.exe --noproxy '*' -s -o NUL -m 10 -w '%{http_code}' $healthUrl 2>$null
        return ("$code".Trim() -eq '200')
    } catch {
        return $false
    }
}

$busy = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
if ($busy) {
    Write-Log ('port {0} already listening (pid {1}) - backend seems up: http://{2}:{0}/' -f $port, $busy[0].OwningProcess, $env:ARLX_HOST)
    Start-Sleep -Seconds 8
    exit 0
}

Write-Log ('backend start -> http://{0}:{1}/   login: admin / arlpass' -f $env:ARLX_HOST, $port)
Write-Log ('python out: {0}' -f $outLog)
Write-Log ('python err: {0}' -f $errLog)

$py = (Get-Command python -ErrorAction Stop).Source
$proc = $null
$fail = 0

while ($true) {
    if ((-not $proc) -or $proc.HasExited) {
        if ($proc) {
            $proc.Refresh()
            Write-Log ('backend exited (pid={0}, exit={1}); restart in 5s' -f $proc.Id, $proc.ExitCode)
            Start-Sleep -Seconds 5
        }
        $proc = Start-Process -FilePath $py `
            -ArgumentList @('-u', '-X', 'faulthandler', '-m', 'arlx.server') `
            -NoNewWindow -PassThru `
            -RedirectStandardOutput $outLog -RedirectStandardError $errLog
        Write-Log ('python started pid={0}' -f $proc.Id)
        Start-Sleep -Seconds 12
        $fail = 0
        continue
    }

    Start-Sleep -Seconds 20
    if (Test-Health) {
        $fail = 0
        continue
    }

    $fail++
    Write-Log ('health check failed ({0} in a row): {1}' -f $fail, $healthUrl)
    # 5 misses: a busy scan can be unresponsive for a minute or two. Killing at
    # 3 used to abort a healthy long-running task (task stuck at "service
    # restarted, task interrupted"). Only a genuinely wedged loop reaches 5.
    if ($fail -ge 5) {
        Write-Log ('5 misses in a row -> force restart, kill pid={0}' -f $proc.Id)
        & taskkill.exe /T /F /PID $proc.Id 2>&1 | Out-Null
        Start-Sleep -Seconds 3
        $proc = $null
        $fail = 0
    }
}
