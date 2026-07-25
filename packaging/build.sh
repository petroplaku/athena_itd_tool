#!/usr/bin/env bash
# Build a standalone ATHENA ITD binary for Linux or macOS.
# Usage:  ./packaging/build.sh
# Output: dist/athena   (plus a dist/athena-<os>-<arch>.tar.gz archive)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

echo "==> Creating build virtualenv"
python3 -m venv .build-venv
# shellcheck disable=SC1091
source .build-venv/bin/activate

echo "==> Installing project + PyInstaller"
pip install --upgrade pip >/dev/null
pip install . pyinstaller >/dev/null

echo "==> Running PyInstaller"
pyinstaller packaging/athena.spec --noconfirm --distpath dist --workpath build/pyi

echo "==> Packaging archive"
mkdir -p release
tar -czf "release/athena-${OS}-${ARCH}.tar.gz" -C dist athena
echo "==> Done: dist/athena  and  release/athena-${OS}-${ARCH}.tar.gz"
deactivate
