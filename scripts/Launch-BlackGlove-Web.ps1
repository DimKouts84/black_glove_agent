#Requires -Version 5.1
<#
.SYNOPSIS
    One-click launcher for Black Glove web app (local-first).

.DESCRIPTION
    Bootstraps .venv and frontend build on first run, then starts black-glove serve
    and opens the default browser.

.PARAMETER SkipBrowser
    Do not open the browser after the server starts.

.PARAMETER ForceRebuild
    Rebuild the React frontend even if static bundle exists.
#>
param(
    [switch]$SkipBrowser,
    [switch]$ForceRebuild
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path $PSScriptRoot -Parent
Set-Location $ProjectRoot

function Write-Status([string]$Message, [string]$Color = "Cyan") {
    Write-Host $Message -ForegroundColor $Color
}

function Write-Ok([string]$Message) {
    Write-Host "[OK] $Message" -ForegroundColor Green
}

function Write-Fail([string]$Message) {
    Write-Host "[FAIL] $Message" -ForegroundColor Red
}

function Open-DefaultBrowser([string]$Url) {
    Write-Ok "Opening $Url in your default browser"
    Start-Process $Url
}

function Wait-ForExitOnError {
    Write-Host ''
    Read-Host 'Press Enter to close'
    exit 1
}

Write-Status "Black Glove Web Launcher" "Cyan"
Write-Status "Project: $ProjectRoot" "DarkGray"

# --- Find Python for bootstrap (system python before venv exists) ---
$BootstrapPython = $null
$VenvPython = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
if (Test-Path $VenvPython) {
    $BootstrapPython = $VenvPython
} elseif (Get-Command python -ErrorAction SilentlyContinue) {
    $BootstrapPython = (Get-Command python).Source
} else {
    Write-Fail "Python not found. Install Python 3.8+ from https://www.python.org/downloads/"
    Wait-ForExitOnError
}

$env:PYTHONPATH = Join-Path $ProjectRoot "src"

# --- Status check ---
Write-Status "Checking bootstrap status..."
$StatusJson = & $BootstrapPython -m agent.bootstrap status --project-root $ProjectRoot 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Fail "Bootstrap status check failed: $StatusJson"
    Wait-ForExitOnError
}
$Status = $StatusJson | ConvertFrom-Json

# --- Ensure venv + deps + frontend ---
if (-not $Status.deps_ok -or (-not $Status.static_built) -or $ForceRebuild) {
    Write-Status "Bootstrapping (first run may take a few minutes)..."
    $EnsureArgs = @("-m", "agent.bootstrap", "ensure-all", "--project-root", $ProjectRoot)
    if ($ForceRebuild) { $EnsureArgs += "--force-rebuild" }
    & $BootstrapPython @EnsureArgs
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "Bootstrap failed. See errors above."
        Wait-ForExitOnError
    }
    $StatusJson = & $BootstrapPython -m agent.bootstrap status --project-root $ProjectRoot
    $Status = $StatusJson | ConvertFrom-Json
    Write-Ok "Bootstrap complete"
} else {
    Write-Ok "Environment ready (venv + static bundle)"
}

$VenvPython = $Status.venv_python
$BindHost = $Status.web_host
$Port = [int]$Status.web_port
$Url = "http://${BindHost}:$Port"

# --- Reuse existing server if healthy ---
if ($Status.server_running) {
    Write-Ok "Server already running at $Url"
    if (-not $SkipBrowser) {
        Open-DefaultBrowser $Url
    }
    exit 0
}

# --- Port conflict check (something listening but not Black Glove) ---
try {
    $Tcp = New-Object System.Net.Sockets.TcpClient
    $Tcp.Connect($BindHost, $Port)
    $Tcp.Close()
    Write-Fail "Port $Port is in use but Black Glove health check failed."
    Write-Host "Stop the other process or change web_port in config.yaml" -ForegroundColor Yellow
    Wait-ForExitOnError
} catch {
    # Port free - expected
}

# --- Start server with browser open in background ---
Write-Status "Starting Black Glove at $Url ..."

$BlackGlove = Join-Path $ProjectRoot ".venv\Scripts\black-glove.exe"
if (-not (Test-Path $BlackGlove)) {
    $BlackGlove = Join-Path $ProjectRoot ".venv\Scripts\black-glove.cmd"
}
if (-not (Test-Path $BlackGlove)) {
  $ServeCmd = $VenvPython
  $ServeArgs = @("-m", "agent", "serve", "--host", $BindHost, "--port", "$Port")
} else {
  $ServeCmd = $BlackGlove
  $ServeArgs = @("serve", "--host", $BindHost, "--port", "$Port")
}

if (-not $SkipBrowser) {
    $BrowserJob = Start-Job -ScriptBlock {
        param($H, $P, $OpenUrl)
        $deadline = (Get-Date).AddSeconds(45)
        while ((Get-Date) -lt $deadline) {
            try {
                $r = Invoke-RestMethod -Uri "http://${H}:$P/api/health" -TimeoutSec 2
                if ($r.status -eq "ok") {
                    Start-Process $OpenUrl
                    return
                }
            } catch { }
            Start-Sleep -Milliseconds 500
        }
    } -ArgumentList $BindHost, $Port, $Url
}

Write-Ok 'Server starting - close this window to stop'
Write-Host ''
$serveExit = 0
try {
    & $ServeCmd @ServeArgs
    $serveExit = $LASTEXITCODE
} catch {
    Write-Fail "Server failed to start: $($_.Exception.Message)"
    if (-not $SkipBrowser -and $BrowserJob) {
        Stop-Job $BrowserJob -ErrorAction SilentlyContinue
        Remove-Job $BrowserJob -Force -ErrorAction SilentlyContinue
    }
    Wait-ForExitOnError
}

if ($serveExit -ne 0) {
    Write-Fail "Server exited with code $serveExit"
    if (-not $SkipBrowser -and $BrowserJob) {
        Stop-Job $BrowserJob -ErrorAction SilentlyContinue
        Remove-Job $BrowserJob -Force -ErrorAction SilentlyContinue
    }
    Wait-ForExitOnError
}

if (-not $SkipBrowser -and $BrowserJob) {
    Stop-Job $BrowserJob -ErrorAction SilentlyContinue
    Remove-Job $BrowserJob -Force -ErrorAction SilentlyContinue
}
