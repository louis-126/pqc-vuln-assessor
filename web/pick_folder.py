"""Open a native 'select folder' dialog and print the chosen ABSOLUTE path.

Run as a subprocess by the web app's /api/browse route. Uses native OS tools:
- macOS: AppleScript osascript (100% native, no Tkinter dependencies or Cocoa crashes)
- Windows: PowerShell FolderBrowserDialog / Tkinter
- Linux: Zenity / Kdialog / Tkinter
"""
import os
import shutil
import subprocess
import sys
from pathlib import Path


def _pick_macos() -> str | None:
    """Use native macOS AppleScript folder picker via osascript.
    Guaranteed native on macOS without Tkinter issues."""
    cmd = [
        "osascript",
        "-e",
        'POSIX path of (choose folder with prompt "Select a source folder to scan")',
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if r.returncode == 0:
            return r.stdout.strip()
        # User cancelled
        if "User canceled" in (r.stderr or "") or "execution error" in (r.stderr or ""):
            return ""
    except Exception as e:
        print(f"osascript failed: {e}", file=sys.stderr)
    return None


def _pick_windows() -> str | None:
    """Use native Windows PowerShell FolderBrowserDialog."""
    ps_cmd = (
        "[System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms') | Out-Null; "
        "$f = New-Object System.Windows.Forms.FolderBrowserDialog; "
        "$f.Description = 'Select a source folder to scan'; "
        "if ($f.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { Write-Host $f.SelectedPath }"
    )
    cmd = ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if r.returncode == 0:
            return r.stdout.strip()
    except Exception as e:
        print(f"powershell picker failed: {e}", file=sys.stderr)
    return None


def _pick_linux() -> str | None:
    """Use Zenity or Kdialog on Linux if available."""
    if shutil.which("zenity"):
        try:
            r = subprocess.run(
                ["zenity", "--file-selection", "--directory", "--title=Select a source folder to scan"],
                capture_output=True, text=True, timeout=300,
            )
            if r.returncode == 0:
                return r.stdout.strip()
            if r.returncode == 1:
                return ""
        except Exception:
            pass
    if shutil.which("kdialog"):
        try:
            r = subprocess.run(
                ["kdialog", "--getexistingdirectory", os.path.expanduser("~"), "--title", "Select a source folder to scan"],
                capture_output=True, text=True, timeout=300,
            )
            if r.returncode == 0:
                return r.stdout.strip()
        except Exception:
            pass
    return None


def _pick_tkinter() -> str | None:
    """Tkinter fallback for any platform."""
    try:
        import tkinter as tk
        from tkinter import filedialog
        root = tk.Tk()
        root.withdraw()
        try:
            root.attributes("-topmost", True)
        except Exception:
            pass
        root.focus_force()
        path = filedialog.askdirectory(
            title="Select a source folder to scan",
            initialdir=os.path.expanduser("~"),
        )
        try:
            root.update()
        except Exception:
            pass
        root.destroy()
        return path or ""
    except Exception as e:
        print(f"tkinter fallback failed: {e}", file=sys.stderr)
        return None


def main() -> int:
    path = None
    if sys.platform == "darwin":
        path = _pick_macos()
    elif sys.platform == "win32":
        path = _pick_windows()
    elif sys.platform.startswith("linux"):
        path = _pick_linux()

    if path is None:
        path = _pick_tkinter()

    if path is None:
        print("no folder dialog available on this machine — type or paste the path instead", file=sys.stderr)
        return 3

    if path:
        path = str(Path(path).expanduser().resolve())

    sys.stdout.write(path or "")
    return 0


if __name__ == "__main__":
    sys.exit(main())

