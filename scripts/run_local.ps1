param(
    [int]$Port = 8000,
    [switch]$Reload
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

if (-not (Test-Path ".venv")) {
    python -m venv .venv
}
$python = Join-Path $root ".venv\Scripts\python.exe"

& $python -m pip install -q --upgrade pip
& $python -m pip install -q -r requirements-dev.txt

if (-not (Test-Path ".env")) {
    Copy-Item .env.example .env
    Write-Host "Created .env from .env.example - set SUB_TOKEN before exposing the service."
}

if (Test-Path (Join-Path $root "bin\sing-box.exe")) {
    $env:SINGBOX_PATH = "bin\sing-box.exe"
}

$uvicornArgs = @("-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "$Port", "--no-access-log")
if ($Reload) { $uvicornArgs += "--reload" }
& $python @uvicornArgs
