# Build a standalone ATHENA ITD executable for Windows.
# Usage:  powershell -ExecutionPolicy Bypass -File packaging\build.ps1
# Output: dist\athena.exe  (plus release\athena-windows-x64.zip)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

Write-Host "==> Creating build virtualenv"
python -m venv .build-venv
& .\.build-venv\Scripts\Activate.ps1

Write-Host "==> Installing project + PyInstaller"
pip install --upgrade pip | Out-Null
pip install . pyinstaller | Out-Null

Write-Host "==> Running PyInstaller"
pyinstaller packaging\athena.spec --noconfirm --distpath dist --workpath build\pyi

Write-Host "==> Packaging archive"
New-Item -ItemType Directory -Force -Path release | Out-Null
Compress-Archive -Path dist\athena.exe -DestinationPath release\athena-windows-x64.zip -Force
Write-Host "==> Done: dist\athena.exe  and  release\athena-windows-x64.zip"
deactivate
