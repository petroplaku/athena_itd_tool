#!/usr/bin/env bash
# Build a standalone Aegis UBA binary for Linux or macOS.
# Usage:  ./packaging/build.sh
# Output: dist/aegis   (plus a dist/aegis-<os>-<arch>.tar.gz archive)
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
pyinstaller packaging/aegis.spec --noconfirm --distpath dist --workpath build/pyi

echo "==> Packaging archive"
mkdir -p release
tar -czf "release/aegis-${OS}-${ARCH}.tar.gz" -C dist aegis
echo "==> Done: dist/aegis  and  release/aegis-${OS}-${ARCH}.tar.gz"
deactivate
