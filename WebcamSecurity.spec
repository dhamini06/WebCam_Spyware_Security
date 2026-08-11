# -*- mode: python ; coding: utf-8 -*-
import os
from PyInstaller.utils.hooks import collect_data_files

# Works from any clone location - paths are resolved relative to this file.
PROJECT_ROOT = os.path.abspath(SPECPATH)

datas = [('assets', 'assets'), ('database', 'database'), ('logs', 'logs'), ('reports', 'reports'), ('temp', 'temp'), ('intruder_images', 'intruder_images'), ('models', 'models')]
datas += collect_data_files('customtkinter')
datas += collect_data_files('cv2')


a = Analysis(
    [os.path.join(PROJECT_ROOT, 'main.py')],
    pathex=[PROJECT_ROOT],
    binaries=[],
    datas=datas,
    hiddenimports=['customtkinter', 'PIL', 'cv2', 'numpy', 'scipy', 'cryptography', 'bcrypt', 'reportlab', 'requests'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='WebcamSecurity',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
