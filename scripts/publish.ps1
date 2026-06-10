# IXF local publish script
# Usage: powershell -ExecutionPolicy Bypass -File scripts/publish.ps1
# Reads PYPI_API_TOKEN from .env (never hardcoded)

param(
    [string]$DistDir = "dist"
)

# Load .env
$EnvFile = Join-Path $PSScriptRoot ".." ".env"
if (-not (Test-Path $EnvFile)) {
    Write-Error ".env not found. Copy .env.example to .env and set PYPI_API_TOKEN."
    exit 1
}
Get-Content $EnvFile | ForEach-Object {
    if ($_ -match '^\s*([^#=]+)=(.+)$') {
        [System.Environment]::SetEnvironmentVariable($Matches[1].Trim(), $Matches[2].Trim(), 'Process')
    }
}

$token = [System.Environment]::GetEnvironmentVariable('PYPI_API_TOKEN', 'Process')
if (-not $token -or $token -like '*REPLACE*') {
    Write-Error "PYPI_API_TOKEN not set in .env or still has placeholder value."
    exit 1
}

# Build if dist is empty
if (-not (Get-ChildItem $DistDir -ErrorAction SilentlyContinue)) {
    Write-Host "Building distribution..."
    python -m build
}

# Upload
$env:TWINE_USERNAME = "__token__"
$env:TWINE_PASSWORD = $token
Write-Host "Uploading to PyPI..."
twine upload "$DistDir/*" --skip-existing

# Clear sensitive env vars
Remove-Item Env:TWINE_USERNAME -ErrorAction SilentlyContinue
Remove-Item Env:TWINE_PASSWORD -ErrorAction SilentlyContinue
