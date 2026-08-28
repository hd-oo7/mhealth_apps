#!/usr/bin/env python3
"""One-time-per-emulator-session setup: generate/reuse the mitmproxy CA and
install it into the connected device's trust store, then deploy and start
frida-server matching the device's architecture.

This talks to whatever device `adb` currently resolves to -- normally the
reviewer's own host-side emulator, reached via ADB_SERVER_SOCKET pointing at
the host's adb server (see docker/README.md). It does not, and cannot,
manage the emulator itself: launch flags and the Google Play Store login are
the reviewer's own one-time setup, done before this container is run.

    python3 setup_device.py            # run all steps, report what needs
                                        # manual attention
    python3 setup_device.py --check    # report status only, change nothing
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

MITM_HOME = Path.home() / ".mitmproxy"
MITM_CA_PEM = MITM_HOME / "mitmproxy-ca-cert.pem"
FRIDA_SERVER_REMOTE = "/data/local/tmp/frida-server"


def run(cmd, **kwargs):
    return subprocess.run(cmd, capture_output=True, text=True, **kwargs)


def adb(*args, check=False):
    result = run(["adb", *args])
    if check and result.returncode != 0:
        raise RuntimeError(f"adb {' '.join(args)} failed: {result.stderr.strip()}")
    return result


def step_device_connected() -> str | None:
    out = adb("devices", "-l").stdout
    lines = [l for l in out.splitlines()[1:] if l.strip()]
    connected = [l for l in lines if "\tdevice" in l or " device " in l]
    if not connected:
        print("[FAIL] No authorized device visible to adb.")
        print(f"       adb devices -l said:\n{out}")
        print("       Check: is ADB_SERVER_SOCKET set correctly (should point at the")
        print("       host's adb server, e.g. tcp:host.docker.internal:5038), and is")
        print("       the host's adb server bound to more than localhost")
        print("       (`adb -a -P 5038 nodaemon server start` on the host -- a")
        print("       separate port from Android Studio's own 5037, so the two")
        print("       don't fight over the binding)?")
        return None
    serial = connected[0].split()[0]
    print(f"[OK] Device visible: {serial}")
    return serial


def step_generate_ca() -> bool:
    if MITM_CA_PEM.exists():
        print(f"[OK] mitmproxy CA already present at {MITM_CA_PEM}")
        return True
    print("[..] No mitmproxy CA yet; generating one (starting mitmdump briefly)...")
    MITM_HOME.mkdir(parents=True, exist_ok=True)
    proc = subprocess.Popen(["mitmdump", "-q"], stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    import time
    for _ in range(20):
        if MITM_CA_PEM.exists():
            break
        time.sleep(0.5)
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
    if MITM_CA_PEM.exists():
        print(f"[OK] Generated {MITM_CA_PEM}")
        return True
    print("[FAIL] mitmproxy did not generate a CA in time.")
    return False


def _hash_old(pem_path: Path) -> str | None:
    result = run(["openssl", "x509", "-inform", "PEM", "-subject_hash_old",
                 "-in", str(pem_path)])
    if result.returncode != 0:
        return None
    return result.stdout.strip().splitlines()[0]


def _adb_root_works() -> bool:
    result = adb("root")
    return "cannot run as root" not in (result.stdout + result.stderr).lower()


def _su_works() -> bool:
    """True if a Magisk (or similar) `su` grants root non-interactively.

    Distinct from `_adb_root_works`: Magisk grants root to `su -c ...`
    invocations via its own daemon/policy, but does not unlock `adbd`
    itself -- `adb root` still fails on the same device. A device can have
    exactly one, both, or neither working.
    """
    result = adb("shell", "su", "-c", "id")
    return "uid=0" in result.stdout


def _wait_for_boot(timeout_s: int = 150) -> bool:
    import time
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        devices = adb("devices").stdout
        online = any(line.endswith("\tdevice") for line in devices.splitlines())
        if online:
            booted = adb("shell", "getprop", "sys.boot_completed").stdout.strip()
            if booted == "1":
                return True
        time.sleep(3)
    return False


def _install_ca_via_magisk_module(remote_name: str, local_der: Path) -> bool:
    """Fallback CA install for devices where `su` works but `adb root`
    doesn't (a Magisk-rooted Play Store image, not a true userdebug/eng
    build -- see docker/README.md's AVD setup section).
    """
    import shutil
    import tempfile
    import time

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        module_dir = tmp / "mscanca"
        certs_dir = module_dir / "system" / "etc" / "security" / "cacerts"
        certs_dir.mkdir(parents=True)
        shutil.copy(local_der, certs_dir / remote_name)
        (module_dir / "module.prop").write_text(
            "id=mscanca\n"
            "name=mSCAN mitmproxy CA\n"
            "version=v1\n"
            "versionCode=1\n"
            "author=mscan\n"
            "description=Installs the mitmproxy CA into the system trust store"
            " via Magisk overlay\n"
        )
        zip_path = tmp / "mscanca.zip"
        shutil.make_archive(str(zip_path.with_suffix("")), "zip", module_dir)

        remote_zip = "/data/local/tmp/mscanca_module.zip"
        adb("shell", "rm", "-rf", "/data/local/tmp/mscanca_module.zip")
        push = adb("push", str(zip_path), remote_zip)
        if push.returncode != 0:
            print(f"[FAIL] Could not push Magisk module zip: {push.stderr.strip()}")
            return False

        install = adb("shell", "su", "-c", f"magisk --install-module {remote_zip}")
        if install.returncode != 0 or "done" not in install.stdout.lower():
            print(f"[FAIL] `magisk --install-module` failed: "
                  f"{(install.stdout + install.stderr).strip()}")
            return False

        print("[..] Module installed; rebooting device to apply the /system "
              "overlay (this takes ~15-30s)...")
        adb("reboot")
        time.sleep(3)  # give the device a moment to actually go down before polling
        if not _wait_for_boot():
            print("[FAIL] Device did not come back online within the timeout "
                  "after reboot.")
            return False
        return True


def step_install_ca_system(check_only: bool) -> str:
    digest = _hash_old(MITM_CA_PEM)
    if not digest:
        print("[FAIL] Could not compute CA hash (is openssl installed?).")
        return "unknown"
    remote_name = f"{digest}.0"

    existing = adb("shell", f"ls /system/etc/security/cacerts/{remote_name} 2>/dev/null")
    if remote_name in existing.stdout:
        print(f"[OK] CA already installed in system trust store ({remote_name}).")
        return "installed"

    if check_only:
        print(f"[--] CA not yet installed in system trust store (would push {remote_name}).")
        return "missing"

    local_der = MITM_HOME / remote_name
    conv = run(["openssl", "x509", "-inform", "PEM", "-outform", "DER",
               "-in", str(MITM_CA_PEM), "-out", str(local_der)])
    if conv.returncode != 0:
        print(f"[FAIL] PEM->DER conversion failed: {conv.stderr}")
        return "unknown"

    if _adb_root_works():
        import time
        time.sleep(1)
        adb("remount")
        push = adb("push", str(local_der), f"/system/etc/security/cacerts/{remote_name}")
        if push.returncode != 0:
            print(f"[FAIL] Could not push CA into system cacerts: {push.stderr.strip()}")
            return "unknown"
        adb("shell", "chmod", "644", f"/system/etc/security/cacerts/{remote_name}")
        print(f"[OK] Installed CA as /system/etc/security/cacerts/{remote_name}")
        return "installed"

    if _su_works():
        print("[..] `adb root` unavailable but Magisk `su` works; installing "
              "the CA as a Magisk module instead.")
        if _install_ca_via_magisk_module(remote_name, local_der):
            verify = adb("shell", f"ls /system/etc/security/cacerts/{remote_name} 2>/dev/null")
            if remote_name in verify.stdout:
                print(f"[OK] Installed CA as /system/etc/security/cacerts/{remote_name} "
                      "(via Magisk module).")
                return "installed"
        print("[FAIL] Magisk module CA install did not verify after reboot.")
        return "unknown"

    print("[FAIL] Neither `adb root` nor `su` grants root on this device. "
          "System-level CA install needs either a userdebug/eng AVD image or "
          "a Magisk-rooted one with its Superuser 'Automatic response' set to "
          "'Grant' (see docker/README.md). Skipping this step.")
    return "needs_root"


def step_frida_server(check_only: bool) -> str:
    running = adb("shell", "pgrep", "-f", "frida-server")
    if running.stdout.strip():
        print(f"[OK] frida-server already running (pid {running.stdout.strip()}).")
        return "running"

    if check_only:
        print("[--] frida-server not currently running on the device.")
        return "not_running"

    abi = adb("shell", "getprop", "ro.product.cpu.abi").stdout.strip()
    arch_map = {"arm64-v8a": "arm64", "armeabi-v7a": "arm",
               "x86_64": "x86_64", "x86": "x86"}
    arch = arch_map.get(abi)
    if not arch:
        print(f"[FAIL] Unrecognized device ABI '{abi}'; cannot pick a frida-server build.")
        return "unknown_arch"

    try:
        import frida
        version = frida.__version__
    except ImportError:
        print("[FAIL] frida (client) not importable; is it installed in this image?")
        return "no_client"

    url = (f"https://github.com/frida/frida/releases/download/{version}/"
          f"frida-server-{version}-android-{arch}.xz")
    print(f"[..] Downloading frida-server {version} for {arch} from {url}")
    local_xz = Path(f"/tmp/frida-server-{version}-{arch}.xz")
    dl = run(["curl", "-fsSL", "--retry", "5", "--retry-all-errors",
             "-o", str(local_xz), url])
    if dl.returncode != 0 or not local_xz.exists():
        print(f"[FAIL] Could not download matching frida-server ({dl.stderr.strip()}). "
              "If frida-tools was recently upgraded, a matching prebuilt server "
              "release may not exist yet for this arch; see docker/README.md.")
        return "download_failed"

    run(["xz", "-d", "-f", str(local_xz)])
    local_bin = local_xz.with_suffix("")
    adb("push", str(local_bin), FRIDA_SERVER_REMOTE, check=True)
    adb("shell", "chmod", "755", FRIDA_SERVER_REMOTE)

    if _adb_root_works():
        adb("shell", f"nohup {FRIDA_SERVER_REMOTE} >/dev/null 2>&1 &")
    elif _su_works():
        adb("shell", "su", "-c", f"nohup {FRIDA_SERVER_REMOTE} >/dev/null 2>&1 &")
    else:
        print("[FAIL] Neither `adb root` nor `su` grants root on this device; "
              "frida-server needs root to instrument other processes.")
        return "needs_root"

    import time
    time.sleep(1)
    running = adb("shell", "pgrep", "-f", "frida-server")
    if running.stdout.strip():
        print(f"[OK] frida-server started (pid {running.stdout.strip()}).")
        return "running"
    print(f"[WARN] frida-server pushed but does not appear to be running. "
          f"On a non-rooted/production device this is expected -- Frida's "
          f"pinning-bypass instrumentation needs root. stderr: {start.stderr.strip()}")
    return "failed_to_start"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="report status only; don't push/install anything")
    args = ap.parse_args()

    print("=== mSCAN device setup ===\n")

    serial = step_device_connected()
    if not serial:
        return 1

    print()
    ca_ok = step_generate_ca()
    ca_status = step_install_ca_system(args.check) if ca_ok else "unknown"

    print()
    frida_status = step_frida_server(args.check)

    print("\n=== Summary ===")
    print(f"  device               : {serial}")
    print(f"  CA in system store   : {ca_status}")
    print(f"  frida-server         : {frida_status}")
    print("\nStill the reviewer's own responsibility (cannot be automated from")
    print("inside this container -- see docker/README.md):")
    print("  - Logged into Google Play Store on the emulator")
    print("  - Emulator launched with a transparent HTTP(S) proxy pointed at")
    print("    this container's mitmdump port (an emulator *launch* flag, e.g.")
    print("    -http-proxy, or an already-verified working equivalent)")
    if ca_status == "needs_root":
        print("  - Emulator image needs to be rootable/userdebug for system CA trust")
    return 0


if __name__ == "__main__":
    sys.exit(main())
