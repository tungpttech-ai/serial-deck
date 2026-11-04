"""Opt-in stable-release updates, staged before an idle shutdown and native install."""
from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

try:
    from . import __version__, ipc, runtime
    from .deckconfig import JsonFile, private_dir, write_private
except ImportError:
    from __init__ import __version__
    import ipc, runtime
    from deckconfig import JsonFile, private_dir, write_private

REPO = "tungpttech-ai/serial-deck"
API_URL = f"https://api.github.com/repos/{REPO}/releases/latest"
RELEASE_URL = f"https://github.com/{REPO}/releases/latest"
CHECK_INTERVAL = 24 * 3600
MAX_DOWNLOAD = 2 * 1024**3
_install_helper = None


def version_tuple(value):
    if not isinstance(value, str):
        raise ValueError("release version must be a string")
    match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", value)
    if not match:
        raise ValueError("release must have a stable vX.Y.Z version")
    return tuple(map(int, match.groups()))


def install_kind():
    if not runtime.frozen():
        # Running from a checkout can put its egg-info before the installed
        # editable dist-info, hiding direct_url.json. Protect the source itself.
        if (Path(__file__).resolve().parent.parent / "pyproject.toml").is_file():
            return "editable"
        try:
            direct = json.loads(importlib.metadata.distribution("serial-deck").read_text("direct_url.json") or "{}")
        except (importlib.metadata.PackageNotFoundError, ValueError):
            direct = {}
        if direct.get("dir_info", {}).get("editable"):
            return "editable"
        return "pip" if sys.prefix != sys.base_prefix else "system-python"
    if sys.platform == "win32":
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    if sys.platform.startswith("linux"):
        if os.environ.get("APPIMAGE"):
            return "appimage"
        if str(Path(sys.executable).resolve()).startswith("/opt/serial-deck/"):
            return "deb"
    return "unsupported"


def asset_name(kind, version):
    if kind == "pip":
        return f"serial_deck-{version}-py3-none-any.whl"
    if kind == "windows":
        return f"SerialDeck-{version}-Setup.exe"
    if kind == "macos":
        arch = "arm64" if platform.machine().lower() in ("arm64", "aarch64") else "x86_64"
        return f"SerialDeck-{version}-macos-{arch}.dmg"
    if kind == "appimage":
        return f"SerialDeck-{version}-x86_64.AppImage"
    if kind == "deb":
        return f"serial-deck_{version}_amd64.deb"
    raise ValueError(f"automatic installation is unavailable for {kind}")


def read_url(url, limit):
    request = urllib.request.Request(url, headers={"User-Agent": f"SerialDeck/{__version__}", "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(request, timeout=20) as response:
        body = response.read(limit + 1)
    if len(body) > limit:
        raise ValueError("update metadata exceeds size limit")
    return body


def release_asset(release, kind):
    if not isinstance(release, dict):
        raise ValueError("release metadata must be an object")
    tag = release.get("tag_name", "")
    version_tuple(tag)
    if release.get("draft") or release.get("prerelease"):
        raise ValueError("only stable published releases may be installed")
    version = tag.removeprefix("v")
    name = asset_name(kind, version)
    assets = release.get("assets", [])
    if not isinstance(assets, list) or not all(isinstance(a, dict) for a in assets):
        raise ValueError("release assets must be a list of objects")
    asset = next((a for a in assets if a.get("name") == name), None)
    prefix = f"https://github.com/{REPO}/releases/download/{tag}/"
    if not asset or asset.get("browser_download_url") != prefix + name:
        raise ValueError(f"release has no official {name}")
    size = asset.get("size")
    if type(size) is not int or not 0 < size <= MAX_DOWNLOAD:
        raise ValueError("invalid update download size")
    digest = asset.get("digest", "")
    if isinstance(digest, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        checksum = digest[7:]
    else:
        manifest = next((a for a in assets if a.get("name") == "SHA256SUMS.txt"), {})
        if manifest.get("browser_download_url") != prefix + "SHA256SUMS.txt":
            raise ValueError("release has no SHA-256 checksum")
        entries = [line.split() for line in read_url(prefix + "SHA256SUMS.txt", 1024 * 1024).decode("utf-8").splitlines()]
        checksum = next((parts[0] for parts in entries if len(parts) == 2 and parts[1].lstrip("*") == name), "")
        if not re.fullmatch(r"[0-9a-f]{64}", checksum):
            raise ValueError("release checksum is missing or invalid")
    return {"version": version, "name": name, "url": prefix + name, "size": size, "sha256": checksum}


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def stage_download(asset, root):
    root = private_dir(root / ("v" + asset["version"]))
    target = root / asset["name"]
    if target.is_file() and target.stat().st_size == asset["size"] and sha256(target) == asset["sha256"]:
        return target
    if shutil.disk_usage(root).free < asset["size"] * 4 + 64 * 1024**2:
        raise OSError("not enough free disk space to stage and install update")
    temp = target.with_suffix(target.suffix + ".part")
    request = urllib.request.Request(asset["url"], headers={"User-Agent": f"SerialDeck/{__version__}"})
    total, digest = 0, hashlib.sha256()
    try:
        with urllib.request.urlopen(request, timeout=30) as response, temp.open("wb") as output:
            if os.name == "posix":
                os.chmod(temp, 0o600)
            while block := response.read(1024 * 1024):
                total += len(block)
                if total > asset["size"]:
                    raise ValueError("update download exceeds advertised size")
                digest.update(block)
                output.write(block)
        if total != asset["size"] or digest.hexdigest() != asset["sha256"]:
            raise ValueError("update SHA-256 or size mismatch; installation refused")
        temp.replace(target)
    finally:
        temp.unlink(missing_ok=True)
    return target


# Native helpers run outside the installed app and wait for its process to exit.
# No app files, config, cache, or local source are removed by the updater itself.
WINDOWS_HELPER = r'''
$p = Get-Content -LiteralPath $env:SERIAL_DECK_UPDATE_PLAN -Raw | ConvertFrom-Json
try {
  if (Get-Process -Id $p.pid -ErrorAction SilentlyContinue) { Wait-Process -Id $p.pid -Timeout 180 -ErrorAction Stop }
  $r = Start-Process -FilePath $p.program -ArgumentList $p.arguments -Wait -PassThru
  if ($r.ExitCode -ne 0) { throw "Installer exit code $($r.ExitCode)" }
  $result = @{state='updated'; message='Update installed'; version=$p.version}
} catch { $result = @{state='error'; message=$_.Exception.Message; version=$p.version} }
$result | ConvertTo-Json | Set-Content -LiteralPath $p.result -Encoding UTF8
if ([string]::IsNullOrEmpty($p.restart_arguments)) {
  Start-Process -FilePath $p.restart_program
} else {
  Start-Process -FilePath $p.restart_program -ArgumentList $p.restart_arguments
}
'''
UNIX_WAIT = '''
tries=0
while kill -0 "$1" 2>/dev/null; do
  tries=$((tries + 1))
  [ "$tries" -lt 180 ] || exit 1
  sleep 1
done
'''


# Copy to root-owned staging before verification so a user-writable download
# cannot change between the privileged checksum check and apt reading it.
DEB_INSTALL = r'''
set -eu
stage=$(/usr/bin/mktemp --suffix=.deb /tmp/serial-deck-update.XXXXXX)
trap '/bin/rm -f -- "$stage"' EXIT
/bin/cp -- "$1" "$stage"
printf '%s  %s\n' "$2" "$stage" | /usr/bin/sha256sum --check --status
/usr/bin/apt-get install --yes --no-remove "$stage"
'''


def launch_installer(kind, artifact, root, version, expected_digest=None):
    """Prepare a detached native helper. Caller shuts down only after this succeeds."""
    global _install_helper
    root = private_dir(root)
    result = root / "install-result.json"
    result.unlink(missing_ok=True)
    if runtime.frozen():
        restart = [sys.executable, *sys.argv[1:]]
    else:
        restart = [sys.executable, *sys.argv]
    if kind == "appimage":
        target = Path(os.environ["APPIMAGE"]).resolve()
        if not os.access(target.parent, os.W_OK):
            raise PermissionError("AppImage directory is not writable")
        restart = [str(target), *(["--appimage-extract-and-run"] if runtime.appimage_extracted() else []), *sys.argv[1:]]
    elif kind == "macos":
        target = next((p for p in Path(sys.executable).resolve().parents if p.suffix == ".app"), None)
        if target is None or not os.access(target.parent, os.W_OK):
            raise PermissionError("app folder is not writable; move Serial Deck to a writable Applications folder")
        restart = ["/usr/bin/open", str(target), "--args", *sys.argv[1:]]
    elif kind == "windows":
        target = Path(sys.executable).parent
    if kind == "pip":
        command = [sys.executable, "-m", "pip", "install", "--upgrade", f"serial-deck[app,mcp] @ {artifact.as_uri()}"]
    elif kind == "deb":
        checksum = expected_digest or sha256(artifact)
        if not re.fullmatch(r"[0-9a-f]{64}", checksum):
            raise ValueError("invalid package checksum")
        command = ["pkexec", "/bin/sh", "-c", DEB_INSTALL, "serial-deck-update", str(artifact), checksum]
        if not shutil.which("pkexec"):
            raise RuntimeError("pkexec is required for the OS package installation prompt")
    elif kind == "windows":
        command = [str(artifact), "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", f"/DIR={target}", f"/LOG={root / 'setup.log'}"]
    else:
        command = []
    env = runtime.host_env()
    env["PYINSTALLER_RESET_ENVIRONMENT"] = "1"
    if kind == "windows" or (kind == "pip" and sys.platform == "win32"):
        plan = {"pid": os.getpid(), "program": command[0], "arguments": subprocess.list2cmdline(command[1:]),
                "restart_program": restart[0], "restart_arguments": subprocess.list2cmdline(restart[1:]),
                "result": str(result), "version": version}
        plan_path = root / "install-plan.json"
        write_private(plan_path, json.dumps(plan))
        env["SERIAL_DECK_UPDATE_PLAN"] = str(plan_path)
        # A normal PowerShell command; execution policy and OS protections stay in force.
        powershell = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe"
        args = [str(powershell), "-NoProfile", "-NonInteractive", "-Command", WINDOWS_HELPER]
        flags = {"creationflags": subprocess.CREATE_NO_WINDOW | subprocess.DETACHED_PROCESS}
    else:
        if kind == "appimage":
            staged = target.with_name(target.name + ".update")
            # The file is on the destination filesystem so the final replace is atomic.
            shutil.copyfile(artifact, staged)
            if sha256(staged) != sha256(artifact):
                staged.unlink(missing_ok=True)
                raise ValueError("AppImage staging copy checksum mismatch")
            os.chmod(staged, 0o755)
            install = f"mv -f {shlex.quote(str(staged))} {shlex.quote(str(target))}"
        elif kind == "macos":
            mount = root / "mount"
            mount.mkdir(exist_ok=True)
            staged = target.with_name(f".SerialDeck-update-{version}.app")
            # ponytail: retain versioned bundle backups; add boot-confirmed pruning
            # when long-lived installs need to reclaim these old app bundles.
            backup = target.with_name(f".SerialDeck-previous-{__version__}.app")
            if staged.exists() or backup.exists():
                raise RuntimeError("previous app update staging exists; inspect it before retrying")
            q = lambda p: shlex.quote(str(p))
            install = (f"/usr/bin/hdiutil attach -nobrowse -readonly -mountpoint {q(mount)} {q(artifact)} && "
                       f"/usr/bin/ditto {q(mount / 'Serial Deck.app')} {q(staged)} && "
                       f"/usr/bin/codesign --verify --deep --strict {q(staged)} && "
                       f"mv {q(target)} {q(backup)} && "
                       f"(mv {q(staged)} {q(target)} || {{ mv {q(backup)} {q(target)}; exit 1; }})")
        else:
            install = shlex.join(command)
        success = json.dumps({"state": "updated", "message": "Update installed", "version": version})
        failure = json.dumps({"state": "error", "message": "Update installation failed; see install.log", "version": version})
        script = "#!/bin/sh\n" + UNIX_WAIT
        script += f"if ( {install} ); then\n  printf '%s\\n' {shlex.quote(success)} > {shlex.quote(str(result))}\nelse\n  printf '%s\\n' {shlex.quote(failure)} > {shlex.quote(str(result))}\nfi\n"
        if kind == "macos":
            script += f"/usr/bin/hdiutil detach {shlex.quote(str(mount))} || true\n"
        script += "nohup " + shlex.join(restart) + " &\n"
        helper = root / "install.sh"
        write_private(helper, script)
        args = ["/bin/sh", str(helper), str(os.getpid())]
        flags = {"start_new_session": True}
    with (root / "install.log").open("ab") as log:
        if os.name == "nt" and runtime.frozen() and kind in ("windows", "pip"):
            # A short-lived bundle helper clears SetDllDirectory in its own
            # process, starts PowerShell detached, and exits before Setup runs.
            # Keeping a host-exec process waiting would lock the installation.
            bootstrap = [runtime.console_executable(), "host-exec", "--detach", "--", *args]
            result = subprocess.run(bootstrap, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=log, timeout=20, check=True, creationflags=subprocess.CREATE_NO_WINDOW)
            return int(result.stdout.strip())
        _install_helper = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=log, stderr=log, env=env, **flags)
        return _install_helper.pid


class Updater:
    def __init__(self, settings, blocker, prepare, restart):
        self.settings, self.blocker, self.prepare, self.restart = settings, blocker, prepare, restart
        self.store = JsonFile("update-state.json", {})
        cache_root = os.environ.get("XDG_CACHE_HOME")
        if not cache_root:
            cache_root = (os.environ.get("LOCALAPPDATA") or Path.home() / "AppData/Local") if sys.platform == "win32" else (
                Path.home() / "Library/Caches" if sys.platform == "darwin" else Path.home() / ".cache")
        self.root = Path(cache_root) / "serial-deck" / "updates"
        self.release = None
        self.stop = threading.Event()
        self.wake = threading.Event()
        self.force = False
        self.thread = None
        self.guard = threading.Lock()

    def status(self):
        data = self.store.load()
        if data.get("state") == "restarting" and not ipc.pid_alive(data.get("helper_pid")):
            try:
                result = json.loads(Path(data["result"]).read_text(encoding="utf-8-sig"))
                data = self._set(**{k: result[k] for k in ("state", "message") if k in result}, helper_pid=None)
            except (OSError, ValueError, KeyError):
                data = self._set(state="error", message="Update helper exited without a result; see install.log", helper_pid=None)
        return {**data, "installed": __version__, "kind": install_kind(), "enabled": self.settings.get()["auto_update"],
                "release_url": RELEASE_URL}

    def _set(self, **changes):
        data = {**self.store.load(), **changes}
        self.store.save(data)
        return data

    def check(self, force=False):
        private_dir(self.store.path.parent)
        lock = ipc.FileLock(self.store.path.parent / "update.lock")
        if not lock.acquire(blocking=False):
            return
        try:
            state = self.store.load()
            if ipc.pid_alive(state.get("helper_pid")):
                return
            if state.get("result"):
                try:
                    result = json.loads(Path(state["result"]).read_text(encoding="utf-8-sig"))
                    self._set(**{k: result[k] for k in ("state", "message") if k in result}, helper_pid=None)
                except (OSError, ValueError):
                    pass
            self._set(state="checking", message="Checking stable releases")
            if force or self.release is None or time.time() - state.get("checked_at", 0) >= CHECK_INTERVAL:
                release = json.loads(read_url(API_URL, 2 * 1024**2))
                if not isinstance(release, dict):
                    raise ValueError("release metadata must be an object")
                version_tuple(release.get("tag_name", ""))
                if release.get("draft") or release.get("prerelease"):
                    raise ValueError("latest release must be stable and published")
                self.release = release
                self._set(checked_at=time.time())
            latest = self.release["tag_name"].removeprefix("v")
            self._set(latest=latest)
            if version_tuple(latest) <= version_tuple(__version__):
                self._set(state="current", message="Already on the latest stable release")
                return
            if not self.settings.get()["auto_update"]:
                self._set(state="available", message="New stable release available; enable auto update to install")
                return
            kind = install_kind()
            if kind in ("editable", "system-python", "unsupported"):
                self._set(state="blocked", message=f"{kind} install is protected; local source will not be replaced")
                return
            reason = self.blocker()
            if reason:
                self._set(state="deferred", message=reason)
                return
            asset = release_asset(self.release, kind)
            self._set(state="downloading", message=f"Downloading {asset['name']}")
            artifact = stage_download(asset, self.root)
            if self.stop.is_set() or not self.settings.get()["auto_update"]:
                self._set(state="ready", message="Verified update staged; installation disabled or app is closing")
                return
            reason = self.blocker()
            if reason:
                self._set(state="deferred", message=reason)
                return
            if sha256(artifact) != asset["sha256"]:
                raise ValueError("staged update checksum changed; installation refused")
            self.prepare()  # atomically stop only an idle hub; refusal aborts installation
            pid = launch_installer(kind, artifact, artifact.parent, latest, asset["sha256"])
            self._set(state="restarting", helper_pid=pid, result=str(artifact.parent / "install-result.json"),
                      message="Verified update ready; closing app for installation")
            self.restart()
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
            self._set(state="error", message=str(exc), checked_at=time.time())
        finally:
            lock.release()

    def start(self, force=False):
        with self.guard:
            self.force |= force
            if self.thread is None:
                self.thread = threading.Thread(target=self._run, name="serial-deck-updater", daemon=True)
                self.thread.start()
            self.wake.set()

    def _run(self):
        while not self.stop.is_set():
            with self.guard:
                force, self.force = self.force, False
            state = self.store.load()
            interval = 60 if state.get("state") in ("deferred", "ready") else (900 if state.get("state") == "error" else CHECK_INTERVAL)
            if force or (self.settings.get()["auto_update"] and time.time() - state.get("attempted_at", 0) >= interval):
                self._set(attempted_at=time.time())
                self.check(force)
            self.wake.wait(60)
            self.wake.clear()

    def close(self):
        self.stop.set()
        self.wake.set()
        if self.thread is not None and self.thread is not threading.current_thread():
            self.thread.join(timeout=1)
