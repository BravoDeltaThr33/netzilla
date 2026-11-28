"""Build netzilla.exe: netzilla in a window of its own, as one Windows program.

On Windows, in the folder that holds pyproject.toml:

    py -m pip install . pyinstaller
    py packaging\\build_exe.py

and netzilla.exe is in the dist folder. GitHub builds it the same way on
every push (.github/workflows/windows-exe.yml) and keeps it with the run.

The .exe opens netzilla in its own window (netzilla.window): no terminal,
no Python to install. Windows tools that netzilla runs (ping, tracert,
netsh, nslookup…) are part of Windows already.

Run on Linux or macOS it builds a netzilla program for that system instead,
which is a quick way to check that the build itself works.
"""

from __future__ import annotations

import argparse
import importlib
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORK = ROOT / "build" / "exe"

# The details Windows shows under the .exe's Properties → Details.
VERSION_INFO = """\
VSVersionInfo(
  ffi=FixedFileInfo(filevers={numbers}, prodvers={numbers}, mask=0x3f, flags=0x0,
                    OS=0x40004, fileType=0x1, subtype=0x0, date=(0, 0)),
  kids=[
    StringFileInfo([StringTable('040904B0', [
      StringStruct('FileDescription', 'netzilla'),
      StringStruct('FileVersion', '{version}'),
      StringStruct('InternalName', 'netzilla'),
      StringStruct('OriginalFilename', 'netzilla.exe'),
      StringStruct('ProductName', 'netzilla'),
      StringStruct('ProductVersion', '{version}'),
      StringStruct('LegalCopyright', 'MIT License')])]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
"""

ENTRY = '''"""netzilla.exe starts here."""
import sys

from netzilla.window import main

if __name__ == "__main__":
    sys.exit(main())
'''


def pyinstaller_command(version: str, icon: Path | None, onedir: bool,
                        windows: bool) -> list[str]:
    command = [
        sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean",
        "--name", "netzilla", "--windowed",
        "--onedir" if onedir else "--onefile",
        "--distpath", str(ROOT / "dist"),
        "--workpath", str(WORK / "pyinstaller"),
        "--specpath", str(WORK),
        # netzilla's styles, tables, pictures and its font
        "--collect-data", "netzilla",
        "--collect-submodules", "netzilla",
        # Pillow finds tkinter by name for the window's picture
        "--hidden-import", "PIL.ImageTk",
        "--hidden-import", "PIL._tkinter_finder",
        # Textual loads its widgets and parts of itself by name
        "--collect-submodules", "textual",
        "--collect-data", "textual",
        # DASH and the Bluetooth check show these versions
        "--copy-metadata", "textual",
        "--copy-metadata", "bleak",
        "--exclude-module", "pytest",
        "--exclude-module", "IPython",
    ]
    if icon is not None:
        command += ["--icon", str(icon)]
    if windows:
        # Bluetooth on Windows goes through WinRT, loaded by name.
        command += ["--collect-submodules", "bleak",
                    "--collect-submodules", "winrt",
                    "--version-file", str(WORK / "version.txt")]
    command.append(str(WORK / "netzilla_exe.py"))
    return command


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build netzilla.exe with PyInstaller.")
    parser.add_argument("--onedir", action="store_true",
                        help="a folder with netzilla.exe and its files instead of one "
                             ".exe (starts a little faster)")
    args = parser.parse_args(argv)

    try:
        importlib.import_module("PyInstaller")
    except ImportError:
        print("PyInstaller is not installed: py -m pip install pyinstaller", file=sys.stderr)
        return 1
    try:
        from netzilla import __version__
        from netzilla.window.icon import save_ico
    except ImportError as error:
        print(f"netzilla is not installed here ({error}): py -m pip install .",
              file=sys.stderr)
        return 1

    windows = sys.platform == "win32"
    if WORK.exists():
        shutil.rmtree(WORK)
    WORK.mkdir(parents=True)
    (WORK / "netzilla_exe.py").write_text(ENTRY, encoding="utf-8")
    numbers = tuple(int(part) for part in __version__.split(".")[:3]) + (0,)
    (WORK / "version.txt").write_text(
        VERSION_INFO.format(numbers=numbers, version=__version__), encoding="utf-8")
    icon = None
    if windows or sys.platform == "darwin":
        icon = WORK / "netzilla.ico"
        save_ico(icon)

    print(f"Building netzilla {__version__} with PyInstaller…", flush=True)
    done = subprocess.run(pyinstaller_command(__version__, icon, args.onedir, windows),
                          cwd=ROOT)
    if done.returncode:
        return done.returncode
    name = "netzilla.exe" if windows else "netzilla"
    built = ROOT / "dist" / ("netzilla" if args.onedir else "") / name
    print(f"\nBuilt {built}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
