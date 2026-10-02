# PyInstaller spec: one onedir bundle with a GUI and a console executable.
#
#   serial-deck(.exe)       GUI entry (windowed on Windows/macOS): opens the app.
#   serial-deck-cli(.exe)   console entry: hub, mcp (stdio), console, flash, ...
#
# Build from the repo root:  pyinstaller --noconfirm packaging/serial-deck.spec
# Env: SERIAL_DECK_CODESIGN_IDENTITY / SERIAL_DECK_ENTITLEMENTS (macOS signing).

import os
import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_all, collect_submodules, copy_metadata

ROOT = Path(SPECPATH).parent
ICONS = ROOT / "packaging" / "icons"
IS_WIN, IS_MAC = sys.platform == "win32", sys.platform == "darwin"

datas, binaries, hiddenimports = [], [], []
for package in ("esptool", "espefuse", "espsecure", "webview", "mcp", "mcp_types",
                "pydantic", "pydantic_core", "anyio", "serial"):
    try:
        d, b, h = collect_all(package)
    except Exception:  # an optional package missing on this platform
        continue
    datas += d
    binaries += b
    hiddenimports += h
for dist in ("esptool", "mcp", "pydantic", "pydantic_core", "anyio", "pyserial", "pywebview",
             "serial-deck"):
    try:
        datas += copy_metadata(dist)
    except Exception:
        pass
hiddenimports += collect_submodules("serial_deck")
hiddenimports += collect_submodules("serial.tools")
if IS_WIN:
    for package in ("clr_loader", "pythonnet"):
        try:
            d, b, h = collect_all(package)
            datas, binaries, hiddenimports = datas + d, binaries + b, hiddenimports + h
        except Exception:
            pass
datas.append((str(ROOT / "serial_deck" / "web_assets"), "serial_deck/web_assets"))

# Tk's shared libraries: python.org/uv builds keep them next to libpython,
# where PyInstaller's binary dependency scan does not look for _tkinter.
if not IS_WIN:
    import sysconfig
    libdir = Path(sysconfig.get_config_var("LIBDIR") or "")
    for pattern in ("libtcl*.so*", "libtk*.so*", "libtcl*.dylib", "libtk*.dylib"):
        for lib in libdir.glob(pattern):
            binaries.append((str(lib), "."))

analysis = Analysis(
    [str(ROOT / "serial_deck" / "launcher.py")],
    pathex=[str(ROOT)],
    datas=datas,
    binaries=binaries,
    hiddenimports=hiddenimports,
    excludes=["tests", "pytest", "IPython", "matplotlib", "numpy"],
    noarchive=False,
)
pyz = PYZ(analysis.pure)

icon = str(ICONS / ("serial-deck.ico" if IS_WIN else "serial-deck.icns" if IS_MAC else "serial-deck.png"))
sign = dict(codesign_identity=os.environ.get("SERIAL_DECK_CODESIGN_IDENTITY") or None,
            entitlements_file=os.environ.get("SERIAL_DECK_ENTITLEMENTS") or None) if IS_MAC else {}

gui = EXE(pyz, analysis.scripts, [], exclude_binaries=True, name="serial-deck",
          console=not (IS_WIN or IS_MAC), icon=icon, **sign)
cli = EXE(pyz, analysis.scripts, [], exclude_binaries=True, name="serial-deck-cli",
          console=True, icon=icon, **sign)
bundle = COLLECT(gui, cli, analysis.binaries, analysis.datas, name="serial-deck")

if IS_MAC:
    from serial_deck import __version__
    app = BUNDLE(
        bundle,
        name="Serial Deck.app",
        icon=icon,
        bundle_identifier="io.github.tungpttech-ai.serial-deck",
        version=__version__,
        info_plist={
            "CFBundleName": "Serial Deck",
            "CFBundleDisplayName": "Serial Deck",
            "CFBundleShortVersionString": __version__,
            "CFBundleVersion": __version__,
            "LSMinimumSystemVersion": os.environ.get("MACOSX_DEPLOYMENT_TARGET", "12.0"),
            "NSHighResolutionCapable": True,
            # The console EXE is collected last; without this PyInstaller marks
            # the whole app background-only (no Dock icon, no menu bar).
            "LSBackgroundOnly": False,
            "LSUIElement": False,
            "LSApplicationCategoryType": "public.app-category.developer-tools",
        },
    )
