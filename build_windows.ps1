param(
    [switch]$SkipInstaller
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $projectRoot

$pythonPath = Join-Path $projectRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $pythonPath)) {
    python -m venv (Join-Path $projectRoot ".venv")
    if ($LASTEXITCODE -ne 0) { throw "Could not create the project virtual environment." }
}

& $pythonPath -m pip install --upgrade pip
if ($LASTEXITCODE -ne 0) { throw "Could not update pip." }
& $pythonPath -m pip install -r requirements-build.txt
if ($LASTEXITCODE -ne 0) { throw "Could not install Python build requirements." }

Push-Location (Join-Path $projectRoot "web")
try {
    npm.cmd ci
    if ($LASTEXITCODE -ne 0) { throw "Could not install web interface dependencies." }
    npm.cmd run build
    if ($LASTEXITCODE -ne 0) { throw "Could not build the web interface." }
}
finally {
    Pop-Location
}

& $pythonPath -m PyInstaller --clean --noconfirm (Join-Path $projectRoot "avantis_firewall.spec")
if ($LASTEXITCODE -ne 0) { throw "Could not package Avantis FireWall." }

$applicationBundle = Join-Path $projectRoot "dist\Avantis FireWall"
Write-Host "Application bundle created at: $applicationBundle"

if ($SkipInstaller) {
    Write-Host "Installer compilation skipped by request."
    exit 0
}

$compiler = $env:ISCC
if (-not $compiler) {
    $command = Get-Command ISCC.exe -ErrorAction SilentlyContinue
    if ($command) { $compiler = $command.Source }
}
if (-not $compiler) {
    $programRoots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}) | Where-Object { $_ }
    $candidates = foreach ($programRoot in $programRoots) {
        Get-ChildItem -Path $programRoot -Directory -Filter "Inno Setup *" -ErrorAction SilentlyContinue |
            Sort-Object Name -Descending |
            ForEach-Object { Join-Path $_.FullName "ISCC.exe" }
    }
    $compiler = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
}
if (-not $compiler -or -not (Test-Path $compiler)) {
    throw "Application bundle is ready, but Inno Setup 6 or newer is required to create the installer. Install Inno Setup and run this script again."
}

& $compiler (Join-Path $projectRoot "installer\Avantis FireWall.iss")
if ($LASTEXITCODE -ne 0) { throw "Inno Setup could not create the installer." }
Write-Host "Installer created in: $(Join-Path $projectRoot 'dist\installer')"
