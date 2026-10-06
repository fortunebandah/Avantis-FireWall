from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, copy_metadata

project_root = Path(SPECPATH).resolve()
data_files = [
    (str(project_root / "web" / "dist"), "web/dist"),
    (str(project_root / "Images"), "Images"),
    (str(project_root / "avantis-dns-blocklist.txt"), "."),
]
data_files += collect_data_files("webview")
data_files += collect_data_files("qtpy")
hidden_imports = [
    "webview.platforms.qt",
    "qtpy.QtCore",
    "qtpy.QtGui",
    "qtpy.QtWidgets",
    "qtpy.QtNetwork",
    "qtpy.QtWebChannel",
    "qtpy.QtWebEngineCore",
    "qtpy.QtWebEngineWidgets",
    "PySide6.QtCore",
    "PySide6.QtGui",
    "PySide6.QtWidgets",
    "PySide6.QtNetwork",
    "PySide6.QtWebChannel",
    "PySide6.QtWebEngineCore",
    "PySide6.QtWebEngineWidgets",
    "PySide6.QtPrintSupport",
]
data_files += copy_metadata("pywebview")

a = Analysis(
    [str(project_root / "app.py")],
    pathex=[str(project_root)],
    binaries=[],
    datas=data_files,
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["PyQt5", "PyQt6", "PySide2"],
    noarchive=False,
    optimize=1,
)
a.datas = [
    entry for entry in a.datas
    if not (
        entry[0].replace("\\", "/").lower().startswith("pyside6/translations/")
        or "qtwebengine_devtools_resources" in entry[0].lower()
        or "qtwebengine_devtools_resources" in entry[1].lower()
    )
]
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="Avantis FireWall",
    icon=str(project_root / "Images" / "avantis-app.ico"),
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
collection = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="Avantis FireWall",
)
