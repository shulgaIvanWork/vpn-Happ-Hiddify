param(
    [string]$Version = "1.14.4",
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$bin = Join-Path $root "bin"
New-Item -ItemType Directory -Force $bin | Out-Null
$exe = Join-Path $bin "sing-box.exe"

if ((Test-Path $exe) -and -not $Force) {
    & $exe version
    exit 0
}

$arch = if ([Environment]::Is64BitOperatingSystem) { "amd64" } else { "386" }
$url = "https://github.com/SagerNet/sing-box/releases/download/v$Version/sing-box-$Version-windows-$arch.zip"
$zip = Join-Path $env:TEMP "sing-box-$Version.zip"
$tmp = Join-Path $env:TEMP "sing-box-$Version"

Write-Host "Downloading $url"
Invoke-WebRequest -Uri $url -OutFile $zip
if (Test-Path $tmp) { Remove-Item $tmp -Recurse -Force }
Expand-Archive -Path $zip -DestinationPath $tmp -Force

$found = Get-ChildItem $tmp -Recurse -Filter "sing-box.exe" | Select-Object -First 1
if (-not $found) { throw "sing-box.exe not found in archive" }
Copy-Item $found.FullName $exe -Force
& $exe version
