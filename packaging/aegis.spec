# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec — builds a single self-contained `aegis` binary.

Bundles the web templates + report templates as data, and force-collects the
heavier runtime deps (scikit-learn, uvicorn, fastapi) that PyInstaller's static
analysis can otherwise miss. Produces a onefile executable named per-OS by the
build scripts (aegis / aegis.exe).

    pyinstaller packaging/aegis.spec --noconfirm
"""
from PyInstaller.utils.hooks import collect_all, collect_submodules

datas = []
binaries = []
hiddenimports = []

for pkg in ("sklearn", "uvicorn", "fastapi", "starlette", "pydantic",
            "pandas", "numpy", "scipy", "httpx", "anyio", "jinja2",
            "joblib", "multipart", "dateutil", "platformdirs"):
    d, b, h = collect_all(pkg)
    datas += d
    binaries += b
    hiddenimports += h

# Application package data (HTML templates).
d, b, h = collect_all("aegis_uba")
datas += d
binaries += b
hiddenimports += h

hiddenimports += collect_submodules("uvicorn")

block_cipher = None

a = Analysis(
    ["entry.py"],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib", "PyQt5", "PySide6", "pytest"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="aegis",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
