"""Network-traffic capture and extraction for a single app, under the
manual-VPN assumption: the operator has already connected the VPN endpoint
for the target country and started the emulator before running mSCAN.
"""

from __future__ import annotations

import gzip
import json
import os
import re
import select
import subprocess
import sys
import threading
import time
import zlib
from collections import Counter, defaultdict
from pathlib import Path
from typing import Optional

_ROOT_DIR = Path(__file__).resolve().parents[2]

# -------------------------
# Config
# -------------------------
_SDK_ROOT = os.environ.get("ANDROID_SDK_ROOT") or os.environ.get("ANDROID_HOME") \
    or os.path.expanduser("~/Library/Android/sdk")
ADB = os.path.join(_SDK_ROOT, "platform-tools", "adb")

# Captures land in this repo's own data/network_traffic/ regardless of where
# mscan.py itself is invoked from.
NETWORK_TRAFFIC_DIR = str(_ROOT_DIR / "data" / "network_traffic")

PRE_CONSENT_CAPTURE_TIME = 12
POST_CONSENT_CAPTURE_TIME = 30

APP_LAUNCH_TIMEOUT = 3
INSTALL_TIMEOUT = 120

WG_VERIFY_TIMEOUT = 12

# Single-session phases per app-country
STATES = ["pre_consent", "post_consent"]

# Enable interactive countdown for BOTH pre- and post-consent capture
# Commands during countdown:
#   s + Enter  -> skip remaining time
#   + + Enter  -> add 30 seconds
ENABLE_INTERACTIVE_COUNTDOWN = True
PROXY_HOST_PORT = "10.0.2.2:8080"

SYNTHETIC_PROFILE = {
    "first_name": "Test",
    "last_name": "User",
    "full_name": "Test User",
    "email": "test.user.synthetic@example.com",
    "password": "REDACTED_SEE_PRIVATE_ENV",
    "phone": "5555550100",
    "zip": "10001",
    "city": "Tokyo",
    "country": "Japan",
    "dob_year": "1992",
    "dob_month": "06",
    "dob_day": "15",
    "age": "33",
    "height_cm": "170",
    "height_ft": "5",
    "height_in": "7",
    "weight_kg": "70",
    "weight_lb": "154",
    "goal_weight_kg": "68",
    "goal_weight_lb": "150",
    "steps_goal": "8000",
    "water_goal_ml": "2000",
    "calories_goal": "2200",
    "sleep_goal_hours": "8",
    "heart_rate_resting": "68",
    "blood_pressure_systolic": "118",
    "blood_pressure_diastolic": "76",
}

HEALTH_PROGRESS_TEXTS = [
    "Continue", "CONTINUE", "Next", "NEXT", "Let's Start", "Let's Go",
    "Lets Start", "Get Started", "Start", "Start now", "Proceed", "Done",
    "Finish", "Complete", "Save", "OK", "Ok", "Allow", "Agree", "Accept",
    "Ok. I accept", "Skip", "Skip for now", "Maybe later", "Not now",
    "Later", "Close", "Close this", "Continue anyway",
    "Use app without account", "Continue as guest", "Skip login",
    "Remind me later", "No thanks", "Dismiss", "Understood", "Got it",
    "Continue with email", "Use email", "Sign in", "Log in",
    "Create account", "Join now", "Begin", "Enable location",
    "Enable Location",
]

PAYWALL_SKIP_TEXTS = [
    "Skip", "Skip for now", "Maybe later", "Not now", "Later", "No thanks",
    "Dismiss", "Close", "Continue without", "Continue without subscribing",
    "Continue with limited version", "Use free version", "Restore later",
    "Try later", "X",
]

INTEGRATION_SKIP_TEXTS = [
    "Not now", "Maybe later", "Skip", "Skip for now", "Later",
    "Continue without", "Do this later", "I'll do this later",
    "Remind me later", "Not interested", "No thanks",
]

HEALTH_SELECTION_PREFERENCES = {
    "sex": ["Female", "Male", "Other", "Prefer not to say"],
    "gender": ["Female", "Male", "Other", "Non-binary", "Prefer not to say"],
    "goal": ["Improve overall health", "Stay fit", "Maintain weight", "Lose weight", "Build muscle"],
    "activity": ["Moderately active", "Lightly active", "Active", "Beginner", "Intermediate"],
    "diet": ["No preference", "Balanced", "High protein", "Mediterranean"],
    "unit": ["Metric", "kg", "cm", "Imperial", "lb", "ft"],
}

BLACKLIST_ACTION_WORDS = {
    "delete", "remove account", "unsubscribe", "buy now", "start free trial",
    "subscribe", "purchase", "restore purchase", "logout", "log out",
    "sign out", "cancel", "close app", "erase", "factory reset", "report",
}

INSTALL_PRECHECK_POPUP_TEXTS = [
    "Got it", "OK", "Ok", "Dismiss", "Close", "Close this", "Not now",
    "No thanks", "Maybe later", "Later", "Skip", "Skip for now", "Cancel",
]

SAFE_INSTALL_POPUP_TEXTS = {"Got it", "Close"}

MAGISK_PACKAGE = "com.topjohnwu.magisk"

PRESERVED_PACKAGES = {
    MAGISK_PACKAGE,
}

INSTALLATION_IN_PROGRESS = threading.Event()


def begin_install_phase():
    INSTALLATION_IN_PROGRESS.set()


def end_install_phase():
    INSTALLATION_IN_PROGRESS.clear()


def install_phase_active() -> bool:
    return INSTALLATION_IN_PROGRESS.is_set()


# -------------------------
# General helpers
# -------------------------
def run_cmd(cmd, check: bool = True, timeout: Optional[int] = None):
    try:
        result = subprocess.run(
            cmd,
            check=check,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            shell=isinstance(cmd, str),
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        err = e.stderr.strip() if e.stderr else ""
        print(f"[CMD FAIL] {cmd}\n{err}")
        return None
    except subprocess.TimeoutExpired:
        print(f"[CMD TIMEOUT] {cmd}")
        return None
    except Exception as e:
        print(f"[CMD ERROR] {cmd}\n{e}")
        return None


def ensure_emulator_running():
    try:
        output = subprocess.check_output([ADB, "devices"]).decode().splitlines()
        devices = [line.split("\t")[0] for line in output if "\tdevice" in line]
        emulator = next((d for d in devices if d.startswith("emulator")), None)
        if not emulator:
            print("[FATAL] No emulator detected. Please start the emulator before running.")
            sys.exit(1)
        print(f"[OK] Emulator detected: {emulator}")
        return emulator
    except Exception as e:
        print(f"[FATAL] Failed to check emulator status: {e}")
        sys.exit(1)


def log_exists(app_id: str, country: str, state: str) -> bool:
    filename = f"{app_id}_{country}_{state}.log"
    return os.path.exists(os.path.join(NETWORK_TRAFFIC_DIR, filename))


def all_logs_exist_for_app_country(app_id: str, country: str) -> bool:
    return all(log_exists(app_id, country, state) for state in STATES)


# -------------------------
# VPN verification (no connect/disconnect -- see module docstring)
# -------------------------
def check_wg_interface() -> bool:
    output = run_cmd(["sudo", "wg", "show"], check=False, timeout=10)
    return bool(output and "interface:" in output.lower())


def get_ip_and_location():
    response = run_cmd(["curl", "-s", "http://ip-api.com/json"], check=False, timeout=10)
    if not response:
        return None
    try:
        data = json.loads(response)
        return {
            "ip": data.get("query"),
            "country": data.get("country"),
            "countryCode": data.get("countryCode"),
        }
    except json.JSONDecodeError:
        return None


def verify_connection(expected_code: str) -> bool:
    wg_ok = check_wg_interface()
    info = get_ip_and_location()
    if not info:
        print("[WG FAIL] Unable to fetch IP/location info")
        return False

    actual_code = (info.get("countryCode") or "").upper()
    actual_ip = info.get("ip")
    print(f"[WG INFO] IP={actual_ip}, countryCode={actual_code}, expected={expected_code}")

    if wg_ok and actual_code == expected_code:
        print(f"[WG SUCCESS] Connected to {expected_code}")
        return True

    print(f"[WG FAIL] Expected {expected_code}, got {actual_code}")
    return False


# -------------------------
# Install helpers
# -------------------------
def detect_paid_app_reason(d) -> Optional[str]:
    paid_button_texts = ["Buy", "Purchase", "Pre-order", "Preorder"]

    for text in paid_button_texts:
        try:
            if d(text=text).exists(timeout=0.05) or d(textContains=text).exists(timeout=0.05):
                return "paid_app"
        except Exception:
            pass

    price_patterns = [
        r"^[\$€£¥₹]\s?\d+([.,]\d{1,2})?$",
        r"^R\$\s?\d+([.,]\d{1,2})?$",
        r"^\d+([.,]\d{1,2})?\s?[€£¥₹]$",
    ]

    for pattern in price_patterns:
        try:
            if d(textMatches=pattern).exists(timeout=0.1):
                return "paid_app"
        except Exception:
            pass

    return None


def is_app_installed(device: str, app_id: str) -> bool:
    try:
        result = subprocess.run(
            [ADB, "-s", device, "shell", "pm", "path", app_id],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=8,
        )
        return result.returncode == 0 and result.stdout.strip().startswith("package:")
    except Exception:
        return False


def get_install_block_reason(d) -> Optional[str]:
    blockers = {
        "This phone isn't compatible with this app": "not_compatible_with_phone",
        "Your device isn't compatible with this version": "not_compatible_with_device",
        "This item isn't available in your country": "not_available_in_country",
        "This app won't work for your device": "app_wont_work_for_device",
        "This app is not available for your device": "app_wont_work_for_device",
        "This app isn't available for your device": "app_wont_work_for_device",
        "This app is available only for your other devices": "app_wont_work_for_device",
        "Can't install app": "cant_install_app",
        "Can't install": "cant_install",
        "Item not found": "item_not_found",
        "This item is not available": "item_not_available",
    }

    for text, reason in blockers.items():
        try:
            if d(textContains=text).exists(timeout=0.02):
                return reason
        except Exception:
            pass

    return None


def wait_for_install(device: str, app_id: str, d=None, timeout: int = INSTALL_TIMEOUT):
    start = time.time()
    interval = 0.2

    while time.time() - start < timeout:
        if is_app_installed(device, app_id):
            return True, None

        if d is not None:
            block_reason = get_install_block_reason(d)
            if block_reason:
                print(f"[FAIL] Install blocked for {app_id}: {block_reason}")
                return False, block_reason

        time.sleep(interval)
        interval = min(interval * 1.4, 1.5)

    return False, "install_timeout"


def list_third_party_apps(device: str) -> set[str]:
    try:
        result = subprocess.run(
            [ADB, "-s", device, "shell", "pm", "list", "packages", "-3"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=20,
        )
        packages = set()
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("package:"):
                packages.add(line.replace("package:", "").strip())
        return packages
    except Exception as e:
        print(f"[ERROR] list_third_party_apps: {e}")
        return set()


def uninstall_package(device: str, package: str) -> bool:
    if package in PRESERVED_PACKAGES:
        return True

    try:
        result = subprocess.run(
            [ADB, "-s", device, "shell", "pm", "uninstall", "--user", "0", package],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=20,
        )

        stdout = (result.stdout or "").strip()
        stderr = (result.stderr or "").strip()

        if "Success" in stdout:
            print(f"[CLEAN] Uninstalled {package}")
            return True

        print(f"[WARN] Could not uninstall {package}: {stderr or stdout or 'unknown error'}")
        return False

    except Exception as e:
        print(f"[ERROR] uninstall {package}: {e}")
        return False


def uninstall_all_third_party_apps(
    device: str,
    keep_packages: Optional[set[str]] = None,
):
    keep = set(PRESERVED_PACKAGES)
    if keep_packages:
        keep.update(keep_packages)

    installed_apps = list_third_party_apps(device)
    removable_apps = [pkg for pkg in sorted(installed_apps) if pkg not in keep]

    print(f"[CLEANUP] Removing {len(removable_apps)} package(s)")
    for pkg in removable_apps:
        uninstall_package(device, pkg)


def clear_popup_before_install_if_present(d, max_rounds: int = 2, settle_time: float = 0.05) -> bool:
    found_any = False

    for _ in range(max_rounds):
        clicked_any = False

        for text in INSTALL_PRECHECK_POPUP_TEXTS:
            try:
                obj = None
                if d(text=text).exists(timeout=0.05):
                    obj = d(text=text)
                elif d(textContains=text).exists(timeout=0.05):
                    obj = d(textContains=text)

                if obj:
                    found_any = True
                    if text in SAFE_INSTALL_POPUP_TEXTS:
                        try:
                            obj.click()
                            clicked_any = True
                            time.sleep(settle_time)
                        except Exception:
                            pass
            except Exception:
                pass

        if not clicked_any:
            break

    return found_any


def click_install_or_update_button(d) -> tuple[bool, Optional[str]]:
    install_candidates = [
        ("Install", d(text="Install")),
        ("Update", d(text="Update")),
    ]

    for label, obj in install_candidates:
        try:
            if obj.exists(timeout=2):
                obj.click()
                print(f"[OK] {label} button clicked")
                return True, None
        except Exception as e:
            print(f"[WARN] Failed clicking {label}: {e}")

    paid_reason = detect_paid_app_reason(d)
    if paid_reason:
        print("[FAIL] App is not free (price/purchase button detected)")
        return False, paid_reason

    return False, "no_install_button"


def install_app(device: str, app_id: str, d):
    begin_install_phase()
    try:
        if is_app_installed(device, app_id):
            return True, None

        subprocess.run(
            [
                ADB, "-s", device, "shell", "am", "start",
                "-a", "android.intent.action.VIEW",
                "-d", f"market://details?id={app_id}",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        time.sleep(0.5)

        clear_popup_before_install_if_present(d)

        early_reason = get_install_block_reason(d)
        if early_reason:
            print(f"[FAIL] Cannot install {app_id}: {early_reason}")
            return False, early_reason

        if d(text="Open").exists(timeout=1.5):
            return True, None

        clicked, click_reason = click_install_or_update_button(d)
        if not clicked:
            late_reason = get_install_block_reason(d)
            if late_reason:
                print(f"[FAIL] Cannot install {app_id}: {late_reason}")
                return False, late_reason

            paid_reason = detect_paid_app_reason(d)
            if paid_reason:
                return False, paid_reason

            print(f"[FAIL] No Install/Update button: {app_id}")
            return False, click_reason or "no_install_button"

        success, reason = wait_for_install(device, app_id, d=d, timeout=INSTALL_TIMEOUT)
        if success:
            print(f"[DONE] Installed {app_id}")
            return True, None

        print(f"[FAIL] Install failed: {app_id} ({reason})")
        return False, reason

    except Exception as e:
        print(f"[ERROR] install {app_id}: {e}")
        return False, "install_failed"
    finally:
        end_install_phase()


# -------------------------
# Traffic capture
# -------------------------
def capture_traffic(app_id: str, country: str, state: str):
    filename = f"{app_id}_{country}_{state}.log"
    path = os.path.join(NETWORK_TRAFFIC_DIR, filename)
    proc = subprocess.Popen(
        ["mitmdump", "-w", path],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return proc, path


def stop_capture(proc):
    if proc:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        except Exception:
            pass


def countdown_sleep(seconds: int, label: str):
    if seconds <= 0:
        return
    for remaining in range(seconds, 0, -1):
        print(f"[{label}] {remaining}s remaining...", end="\r", flush=True)
        time.sleep(1)
    print(f"[{label}] Done.{' ' * 20}")


def interactive_countdown_sleep(seconds: int, label: str):
    deadline = time.time() + seconds
    print(f"[{label}] Interactive capture controls enabled.")
    print(f"[{label}] Type 's' + Enter to skip, or '+' + Enter to add 30 seconds.")

    last_displayed = None
    while True:
        remaining = max(0, int(round(deadline - time.time())))
        if remaining != last_displayed:
            print(
                f"\r[{label}] Remaining: {remaining:3d}s   (s + Enter = skip, + + Enter = add 30s)",
                end="",
                flush=True,
            )
            last_displayed = remaining

        if remaining <= 0:
            break

        try:
            ready, _, _ = select.select([sys.stdin], [], [], 0.2)
        except Exception:
            ready = []

        if ready:
            cmd = sys.stdin.readline().strip().lower()
            if cmd == "s":
                print(f"\n[{label}] Skipped by user.", flush=True)
                return
            if cmd == "+":
                deadline += 30
                print(f"\n[{label}] Added 30 seconds.", flush=True)
                last_displayed = None

    print(f"\n[{label}] Done.", flush=True)


def sleep_with_mode(seconds: int, label: str):
    if ENABLE_INTERACTIVE_COUNTDOWN:
        interactive_countdown_sleep(seconds, label)
    else:
        countdown_sleep(seconds, label)


# -------------------------
# UI handling
# -------------------------
class UIActionTracker:
    def __init__(self):
        self.last_action_time = 0.0
        self.last_action_label = None
        self.last_screen_signature = None
        self.same_screen_rounds = 0
        self.screen_actions = {}
        self.screen_seen_count = {}

    def record_action(self, label: str):
        self.last_action_time = time.time()
        self.last_action_label = label

    def recently_clicked(self, label: str, cooldown: float = 0.15) -> bool:
        if not label or self.last_action_label != label:
            return False
        return (time.time() - self.last_action_time) < cooldown

    def has_screen_action(self, screen_sig: str, action_key: str) -> bool:
        if not screen_sig or not action_key:
            return False
        return action_key in self.screen_actions.get(screen_sig, set())

    def record_screen_action(self, screen_sig: str, action_key: str):
        if not screen_sig or not action_key:
            return
        self.screen_actions.setdefault(screen_sig, set()).add(action_key)

    def mark_screen_seen(self, screen_sig: str):
        if not screen_sig:
            return
        self.screen_seen_count[screen_sig] = self.screen_seen_count.get(screen_sig, 0) + 1


def safe_click(
    obj,
    label: str = "",
    tracker: Optional[UIActionTracker] = None,
) -> bool:
    if install_phase_active():
        return False

    if tracker and label and tracker.recently_clicked(label):
        return False

    try:
        obj.click()
        if label:
            print(f"\n[UI] Clicked: {label}", flush=True)
        if tracker and label:
            tracker.record_action(label)
        return True
    except Exception:
        try:
            clicked = obj.click_exists(timeout=0.01)
            if not clicked:
                return False
            if label:
                print(f"\n[UI] Clicked: {label}", flush=True)
            if tracker and label:
                tracker.record_action(label)
            return True
        except Exception:
            return False


def text_variants(text: str) -> list[str]:
    base = text.strip()
    variants = {base, base.lower(), base.upper(), base.capitalize(), base.title()}
    return [v for v in variants if v]


def contains_text_case_insensitive(d, keyword: str, timeout: float = 0):
    variants = {
        keyword,
        keyword.lower(),
        keyword.upper(),
        keyword.capitalize(),
        keyword.title(),
    }
    for v in variants:
        try:
            if d(textContains=v).exists(timeout=timeout):
                return v
        except Exception:
            pass
    return None


def get_obj_info(obj) -> dict:
    try:
        return obj.info or {}
    except Exception:
        return {}


def get_info_blob(info: dict) -> str:
    text = (info.get("text") or "").strip()
    hint = (info.get("hint") or "").strip()
    desc = (info.get("contentDescription") or "").strip()
    rid = (info.get("resourceName") or "").strip()
    cls = (info.get("className") or "").strip()
    return " ".join(part for part in [text, hint, desc, rid, cls] if part).lower()


def normalize_text(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").strip().lower())


def looks_like_login_screen(d) -> bool:
    login_signals = [
        "sign in", "log in", "login", "password", "email", "username",
        "use email", "continue with email", "forgot password",
    ]
    hits = 0
    for signal in login_signals:
        if contains_text_case_insensitive(d, signal, timeout=0.01):
            hits += 1
    return hits >= 2 or bool(find_password_field(d))


def enumerate_by_selectors(selectors, max_count: int = 20):
    seen = set()
    objects = []

    for sel in selectors:
        try:
            count = min(sel.count, max_count)
        except Exception:
            count = 0

        for i in range(count):
            try:
                obj = sel[i]
                info = get_obj_info(obj)
                key = (
                    info.get("resourceName") or "",
                    info.get("className") or "",
                    info.get("text") or "",
                    info.get("contentDescription") or "",
                    str(info.get("bounds") or ""),
                )
                if key in seen:
                    continue
                seen.add(key)
                objects.append(obj)
            except Exception:
                pass

    return objects


def enumerate_edit_texts(d, max_count: int = 16):
    selectors = [
        d(className="android.widget.EditText"),
        d(resourceIdMatches=".*edit.*"),
        d(resourceIdMatches=".*input.*"),
        d(resourceIdMatches=".*text.*"),
    ]
    return enumerate_by_selectors(selectors, max_count=max_count)


def enumerate_clickable_candidates(d, max_count: int = 40):
    selectors = [
        d(className="android.widget.Button"),
        d(className="android.widget.TextView"),
        d(className="android.view.View"),
        d(className="android.widget.CheckedTextView"),
        d(className="android.widget.RadioButton"),
        d(className="android.widget.CheckBox"),
        d(className="android.widget.Switch"),
        d(className="androidx.recyclerview.widget.RecyclerView"),
        d(resourceIdMatches=".*button.*"),
        d(resourceIdMatches=".*card.*"),
        d(resourceIdMatches=".*item.*"),
    ]
    return enumerate_by_selectors(selectors, max_count=max_count)


def enumerate_picker_widgets(d, max_count: int = 12):
    selectors = [
        d(className="android.widget.NumberPicker"),
        d(className="android.widget.DatePicker"),
        d(className="android.widget.TimePicker"),
        d(className="android.widget.SeekBar"),
        d(className="android.widget.Spinner"),
        d(className="android.widget.NumberPicker$CustomEditText"),
    ]
    return enumerate_by_selectors(selectors, max_count=max_count)


def find_email_field(d):
    for obj in enumerate_edit_texts(d):
        info = get_obj_info(obj)
        blob = get_info_blob(info)
        if any(k in blob for k in ["email", "e-mail", "username", "user id", "user"]):
            return obj

    fields = enumerate_edit_texts(d)
    if len(fields) >= 1 and not find_password_field(d):
        return fields[0]
    return None


def find_password_field(d):
    for obj in enumerate_edit_texts(d):
        info = get_obj_info(obj)
        blob = get_info_blob(info)
        if info.get("password", False) or "password" in blob or "passcode" in blob or "pin" in blob:
            return obj
    return None


def find_submit_button(d):
    submit_texts = ["Sign in", "Log in", "Login", "Continue", "Next", "Submit", "Done", "OK", "Ok"]

    for txt in submit_texts:
        for variant in text_variants(txt):
            try:
                if d(text=variant).exists(timeout=0.01):
                    return d(text=variant), variant
                if d(textContains=variant).exists(timeout=0.01):
                    return d(textContains=variant), variant
            except Exception:
                pass
    return None, None


def set_text_if_needed(obj, value: str, label: str = "") -> bool:
    if not value:
        return False

    try:
        info = get_obj_info(obj)
        existing = (info.get("text") or "").strip()
        if existing == value:
            return False
    except Exception:
        pass

    try:
        obj.click()
    except Exception:
        pass

    try:
        obj.clear_text()
    except Exception:
        pass

    try:
        obj.set_text(value)
        print(f"\n[UI] Filled: {label}", flush=True)
        return True
    except Exception:
        return False


def choose_synthetic_value(blob: str) -> Optional[str]:
    blob = normalize_text(blob)

    mapping = [
        (["first name", "firstname", "given name"], SYNTHETIC_PROFILE["first_name"]),
        (["last name", "lastname", "surname", "family name"], SYNTHETIC_PROFILE["last_name"]),
        (["full name", "name"], SYNTHETIC_PROFILE["full_name"]),
        (["email", "e-mail", "username"], SYNTHETIC_PROFILE["email"]),
        (["password", "passcode"], SYNTHETIC_PROFILE["password"]),
        (["phone", "mobile", "telephone"], SYNTHETIC_PROFILE["phone"]),
        (["zip", "postal", "postcode"], SYNTHETIC_PROFILE["zip"]),
        (["city"], SYNTHETIC_PROFILE["city"]),
        (["country"], SYNTHETIC_PROFILE["country"]),
        (["date of birth", "birth date", "birthday", "dob"], f"{SYNTHETIC_PROFILE['dob_year']}-{SYNTHETIC_PROFILE['dob_month']}-{SYNTHETIC_PROFILE['dob_day']}"),
        (["age", "years old"], SYNTHETIC_PROFILE["age"]),
        (["height (cm)", "height cm", "height"], SYNTHETIC_PROFILE["height_cm"]),
        (["ft"], SYNTHETIC_PROFILE["height_ft"]),
        (["inch", "inches"], SYNTHETIC_PROFILE["height_in"]),
        (["goal weight"], SYNTHETIC_PROFILE["goal_weight_kg"]),
        (["weight", "body weight"], SYNTHETIC_PROFILE["weight_kg"]),
        (["steps", "step goal"], SYNTHETIC_PROFILE["steps_goal"]),
        (["water", "hydration"], SYNTHETIC_PROFILE["water_goal_ml"]),
        (["calories", "kcal"], SYNTHETIC_PROFILE["calories_goal"]),
        (["sleep", "bedtime", "hours of sleep"], SYNTHETIC_PROFILE["sleep_goal_hours"]),
        (["resting heart rate", "heart rate"], SYNTHETIC_PROFILE["heart_rate_resting"]),
        (["systolic"], SYNTHETIC_PROFILE["blood_pressure_systolic"]),
        (["diastolic"], SYNTHETIC_PROFILE["blood_pressure_diastolic"]),
    ]

    for keywords, value in mapping:
        if any(k in blob for k in keywords):
            if "lb" in blob and "weight" in blob:
                return SYNTHETIC_PROFILE["weight_lb"]
            if "goal weight" in blob and "lb" in blob:
                return SYNTHETIC_PROFILE["goal_weight_lb"]
            if "ft" in blob and "height" in blob:
                return SYNTHETIC_PROFILE["height_ft"]
            return value
    return None


def fill_login_form_if_present(d, tracker: Optional[UIActionTracker] = None, screen_sig: str = "") -> bool:
    if not looks_like_login_screen(d):
        return False

    email_field = find_email_field(d)
    password_field = find_password_field(d)

    if not email_field and not password_field:
        return False

    acted = False

    if email_field and SYNTHETIC_PROFILE["email"] and not (tracker and tracker.has_screen_action(screen_sig, "filled_email")):
        if set_text_if_needed(email_field, SYNTHETIC_PROFILE["email"], "login:email"):
            acted = True
            if tracker:
                tracker.record_action("login:email")
                tracker.record_screen_action(screen_sig, "filled_email")

    if password_field and SYNTHETIC_PROFILE["password"] and not (tracker and tracker.has_screen_action(screen_sig, "filled_password")):
        if set_text_if_needed(password_field, SYNTHETIC_PROFILE["password"], "login:password"):
            acted = True
            if tracker:
                tracker.record_action("login:password")
                tracker.record_screen_action(screen_sig, "filled_password")

    submit_obj, submit_label = find_submit_button(d)
    should_submit = bool(submit_obj) and (acted or (email_field and password_field) or (password_field and SYNTHETIC_PROFILE["password"]))

    if should_submit and submit_obj:
        if safe_click(submit_obj, f"login:{submit_label}", tracker):
            if tracker:
                tracker.record_screen_action(screen_sig, "submitted_login")
            return True

    return acted


def get_screen_signature(d, max_nodes: int = 16) -> str:
    parts = []
    selectors = [
        d(className="android.widget.Button"),
        d(className="android.widget.TextView"),
        d(className="android.widget.EditText"),
        d(className="android.widget.CheckBox"),
        d(className="android.widget.RadioButton"),
        d(className="android.widget.Switch"),
        d(className="android.widget.SeekBar"),
        d(className="android.webkit.WebView"),
    ]

    for sel in selectors:
        try:
            count = min(sel.count, max_nodes)
        except Exception:
            count = 0

        for i in range(count):
            try:
                info = sel[i].info
                text = (info.get("text") or "").strip()
                desc = (info.get("contentDescription") or "").strip()
                rid = (info.get("resourceName") or "").strip()
                cls = (info.get("className") or "").strip()
                if text or desc or rid or cls:
                    parts.append(f"{text}|{desc}|{rid}|{cls}")
            except Exception:
                pass

    return " || ".join(parts[:max_nodes])


def click_first_matching_text(
    d,
    texts: list[str],
    exact_first: bool = True,
    timeout: float = 0.02,
    tracker: Optional[UIActionTracker] = None,
    prefix: str = "",
) -> bool:
    for text in texts:
        for variant in text_variants(text):
            try:
                if exact_first and d(text=variant).exists(timeout=timeout):
                    label = f"{prefix}{variant}" if prefix else variant
                    return safe_click(d(text=variant), label, tracker)
            except Exception:
                pass

    for text in texts:
        for variant in text_variants(text):
            try:
                if d(textContains=variant).exists(timeout=timeout):
                    label = f"{prefix}{variant}" if prefix else variant
                    return safe_click(d(textContains=variant), label, tracker)
            except Exception:
                pass

    return False


def click_obj_center_by_bounds(d, obj, label: str, tracker: Optional[UIActionTracker] = None) -> bool:
    if install_phase_active():
        return False
    try:
        info = get_obj_info(obj)
        bounds = info.get("bounds") or {}
        left = int(bounds.get("left", 0))
        right = int(bounds.get("right", 0))
        top = int(bounds.get("top", 0))
        bottom = int(bounds.get("bottom", 0))
        if right <= left or bottom <= top:
            return False
        x = (left + right) // 2
        y = (top + bottom) // 2
        d.click(x, y)
        print(f"\n[UI] Clicked: {label}", flush=True)
        if tracker:
            tracker.record_action(label)
        return True
    except Exception:
        return False


def click_checkbox_for_terms(d, tracker: Optional[UIActionTracker] = None) -> bool:
    consent_keywords = [
        "terms of service", "terms and conditions", "privacy policy",
        "privacy notice", "consent", "i agree", "i accept", "Ok, I accept",
        "accept terms", "agree to terms", "i have read and agree",
        "by continuing", "required", "required to continue",
        "must accept",
    ]
    marketing_keywords = ["marketing", "newsletter", "promo", "email me", "offers"]

    def has_consent_context(blob: str) -> bool:
        return any(kw in blob for kw in consent_keywords)

    selectors = [
        d(className="android.widget.CheckBox"),
        d(className="android.widget.Switch"),
        d(resourceIdMatches=".*checkbox.*"),
        d(descriptionContains="checkbox"),
        d(descriptionContains="agree"),
        d(descriptionContains="consent"),
    ]

    for sel in selectors:
        try:
            count = min(sel.count, 16)
        except Exception:
            count = 0

        for i in range(count):
            try:
                obj = sel[i]
                info = obj.info
                blob = get_info_blob(info)
                if any(bad in blob for bad in marketing_keywords):
                    continue
                if not info.get("checkable", False) or info.get("checked", False):
                    continue
                if not has_consent_context(blob):
                    continue
                if safe_click(obj, "terms:checkbox", tracker):
                    return True
            except Exception:
                pass

    return False


def tap_google_account_chooser(d, timeout: float = 0.6, tracker: Optional[UIActionTracker] = None) -> bool:
    if not SYNTHETIC_PROFILE["email"]:
        return False

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if d(textContains=SYNTHETIC_PROFILE["email"]).exists(timeout=0.02):
                if safe_click(d(textContains=SYNTHETIC_PROFILE["email"]), f"account:{SYNTHETIC_PROFILE['email']}", tracker):
                    return True
        except Exception:
            pass

        selectors = [
            d(resourceIdMatches=".*account.*"),
            d(className="android.widget.CheckedTextView"),
            d(className="android.widget.TextView"),
        ]

        for sel in selectors:
            try:
                count = min(sel.count, 12)
            except Exception:
                count = 0

            for i in range(count):
                try:
                    obj = sel[i]
                    info = obj.info
                    text = (info.get("text") or "").strip()
                    desc = (info.get("contentDescription") or "").strip()
                    blob = f"{text} {desc}".lower()

                    if SYNTHETIC_PROFILE["email"].lower() in blob:
                        if safe_click(obj, f"account:{text or desc or SYNTHETIC_PROFILE['email']}", tracker):
                            return True
                except Exception:
                    pass
        time.sleep(0.08)

    return False


SOCIAL_AUTH_DENY_KEYWORDS = {
    "facebook", "continue with facebook", "sign in with facebook",
    "sign up with facebook", "login with facebook", "log in with facebook",
    "meta",
}

SOCIAL_AUTH_GOOGLE_KEYWORDS = {
    "google", "continue with google", "sign in with google",
    "sign up with google", "login with google", "log in with google",
    "register with google",
}


def blob_mentions_facebook(blob: str) -> bool:
    blob = normalize_text(blob)
    return any(k in blob for k in SOCIAL_AUTH_DENY_KEYWORDS)


def blob_mentions_google(blob: str) -> bool:
    blob = normalize_text(blob)
    return any(k in blob for k in SOCIAL_AUTH_GOOGLE_KEYWORDS)


def click_google_auth_entry(d, tracker: Optional[UIActionTracker] = None) -> bool:
    google_texts = [
        "Continue with Google", "CONTINUE WITH GOOGLE", "SIGN UP WITH GOOGLE",
        "Sign in with Google", "Sign In with Google", "Login with Google",
        "Log in with Google", "Sign up with Google", "Register with Google",
        "Continue using Google", "Continue via Google", "Via Google",
    ]

    if click_first_matching_text(d, google_texts, exact_first=True, timeout=0.02, tracker=tracker, prefix="google:"):
        tap_google_account_chooser(d, timeout=0.2, tracker=tracker)
        return True

    for obj in enumerate_clickable_candidates(d, max_count=40):
        try:
            info = get_obj_info(obj)
            blob = get_info_blob(info)
            if blob_mentions_facebook(blob):
                continue
            if blob_mentions_google(blob):
                if safe_click(obj, f"google:{(info.get('text') or info.get('contentDescription') or 'google_auth')}", tracker):
                    tap_google_account_chooser(d, timeout=0.2, tracker=tracker)
                    return True
        except Exception:
            pass

    return False


def click_common_progress_buttons(d, tracker: Optional[UIActionTracker] = None) -> bool:
    return click_first_matching_text(d, HEALTH_PROGRESS_TEXTS, exact_first=True, timeout=0.02, tracker=tracker, prefix="progress:")


def score_clickable_candidate(info: dict) -> int:
    blob = get_info_blob(info)
    score = 0

    if not info.get("enabled", True):
        return -999
    if any(bad in blob for bad in BLACKLIST_ACTION_WORDS):
        return -999
    if info.get("checkable", False) and info.get("checked", False):
        return -50

    if info.get("clickable", False):
        score += 4
    if info.get("checkable", False):
        score += 6
    if "radio" in blob or "checkbox" in blob or "switch" in blob:
        score += 7
    if "recyclerview" in blob or "card" in blob or "option" in blob:
        score += 5
    if any(k in blob for k in ["male", "female", "other", "beginner", "intermediate", "advanced"]):
        score += 10
    if any(k in blob for k in ["lose weight", "maintain", "build muscle", "sleep", "steps", "water"]):
        score += 10
    if any(k in blob for k in ["continue", "next", "back", "cancel", "close"]):
        score -= 6
    if len((info.get("text") or "").strip()) > 0:
        score += 2
    return score


def find_best_selectable_option(d):
    candidates = []
    for obj in enumerate_clickable_candidates(d, max_count=50):
        try:
            info = get_obj_info(obj)
            if not info.get("bounds"):
                continue
            score = score_clickable_candidate(info)
            if score <= 0:
                continue
            label = (info.get("text") or info.get("contentDescription") or info.get("resourceName") or "option").strip() or "option"
            candidates.append((score, obj, label))
        except Exception:
            pass

    if not candidates:
        return None

    candidates.sort(key=lambda x: x[0], reverse=True)
    return candidates[0][1], candidates[0][2]


def resolve_disabled_continue_by_selecting_option(d, max_attempts: int = 2, tracker: Optional[UIActionTracker] = None) -> bool:
    for _ in range(max_attempts):
        picked = find_best_selectable_option(d)
        if not picked:
            return False

        obj, label = picked
        if safe_click(obj, f"select_option:{label}", tracker):
            click_common_progress_buttons(d, tracker)
            return True

    return False


def handle_system_permissions(d, tracker: Optional[UIActionTracker] = None) -> bool:
    permission_texts = [
        "While using the app", "Only this time", "Allow",
        "Allow only while using the app", "Precise", "Approximate",
        "OK", "Ok", "Got it", "Allow all the time",
    ]

    for txt in permission_texts:
        for variant in text_variants(txt):
            try:
                if d(text=variant).exists(timeout=0.02):
                    return safe_click(d(text=variant), f"permission:{variant}", tracker)
                if d(textContains=variant).exists(timeout=0.02):
                    return safe_click(d(textContains=variant), f"permission:{variant}", tracker)
            except Exception:
                pass

    return False


def is_health_questionnaire_screen(d) -> bool:
    keywords = [
        "weight", "height", "age", "birthday", "date of birth",
        "gender", "sex", "activity level", "goal", "steps", "sleep",
        "water", "calories", "fitness level", "how active", "your goal",
        "units",
    ]
    hits = 0
    for k in keywords:
        if contains_text_case_insensitive(d, k, timeout=0.01):
            hits += 1
    return hits >= 1


def click_preferred_health_options(d, tracker: Optional[UIActionTracker] = None) -> bool:
    for group in HEALTH_SELECTION_PREFERENCES.values():
        if click_first_matching_text(d, group, exact_first=True, timeout=0.02, tracker=tracker, prefix="health_option:"):
            return True

    for obj in enumerate_clickable_candidates(d, max_count=30):
        try:
            info = get_obj_info(obj)
            blob = get_info_blob(info)
            if any(bad in blob for bad in BLACKLIST_ACTION_WORDS):
                continue
            if any(token in blob for token in [
                "lose weight", "maintain weight", "build muscle", "stay fit",
                "moderately active", "lightly active", "female", "male",
                "prefer not to say", "metric", "kg", "cm"
            ]):
                if safe_click(obj, f"health_option:{(info.get('text') or info.get('contentDescription') or 'preferred')}", tracker):
                    return True
        except Exception:
            pass
    return False


def fill_health_profile_fields(d, tracker: Optional[UIActionTracker] = None, screen_sig: str = "") -> bool:
    acted = False
    fields = enumerate_edit_texts(d, max_count=16)

    for idx, obj in enumerate(fields):
        info = get_obj_info(obj)
        blob = get_info_blob(info)
        value = choose_synthetic_value(blob)

        if value is None and len(fields) == 1:
            value = SYNTHETIC_PROFILE["full_name"]
        elif value is None and idx == 0 and len(fields) >= 2:
            value = SYNTHETIC_PROFILE["email"] if looks_like_login_screen(d) else SYNTHETIC_PROFILE["first_name"]
        elif value is None and idx == 1 and len(fields) >= 2:
            value = SYNTHETIC_PROFILE["password"] if looks_like_login_screen(d) else SYNTHETIC_PROFILE["last_name"]

        if not value:
            continue

        action_key = f"filled_field:{idx}:{value}"
        if tracker and tracker.has_screen_action(screen_sig, action_key):
            continue

        if set_text_if_needed(obj, value, f"health_field:{blob[:40] or idx}"):
            acted = True
            if tracker:
                tracker.record_screen_action(screen_sig, action_key)
                tracker.record_action(f"health_field:{idx}")

    if acted:
        click_common_progress_buttons(d, tracker)

    return acted


def set_seekbar_to_middle(d, obj, label: str, tracker: Optional[UIActionTracker] = None) -> bool:
    if install_phase_active():
        return False
    try:
        info = get_obj_info(obj)
        bounds = info.get("bounds") or {}
        left = int(bounds.get("left", 0))
        right = int(bounds.get("right", 0))
        top = int(bounds.get("top", 0))
        bottom = int(bounds.get("bottom", 0))
        if right <= left or bottom <= top:
            return False
        y = (top + bottom) // 2
        x = int(left + (right - left) * 0.55)
        d.click(x, y)
        print(f"\n[UI] Set slider: {label}", flush=True)
        if tracker:
            tracker.record_action(label)
        return True
    except Exception:
        return False


def handle_picker_widgets(d, tracker: Optional[UIActionTracker] = None, screen_sig: str = "") -> bool:
    for obj in enumerate_picker_widgets(d, max_count=12):
        info = get_obj_info(obj)
        cls = (info.get("className") or "").lower()
        label = f"picker:{cls}"
        if tracker and tracker.has_screen_action(screen_sig, label):
            continue

        if "seekbar" in cls:
            if set_seekbar_to_middle(d, obj, label, tracker):
                if tracker:
                    tracker.record_screen_action(screen_sig, label)
                click_common_progress_buttons(d, tracker)
                return True

        if any(x in cls for x in ["datepicker", "timepicker", "numberpicker", "spinner"]):
            if click_obj_center_by_bounds(d, obj, label, tracker):
                if tracker:
                    tracker.record_screen_action(screen_sig, label)
                if click_first_matching_text(d, ["OK", "Ok", "Done", "Set", "Save", "Confirm", "Apply", "Next"], exact_first=True, timeout=0.02, tracker=tracker, prefix="picker_confirm:"):
                    return True
                click_common_progress_buttons(d, tracker)
                return True

    return False


def handle_health_paywall_and_integrations(d, tracker: Optional[UIActionTracker] = None) -> bool:
    paywall_context = [
        "free trial", "subscribe", "premium", "membership", "payment",
        "restore purchase", "unlock all", "go premium", "trial"
    ]
    integration_context = [
        "google fit", "fitbit", "garmin", "oura", "samsung health",
        "apple health", "bluetooth", "wearable", "connect device", "pair"
    ]

    paywall_hit = any(contains_text_case_insensitive(d, k, timeout=0.01) for k in paywall_context)
    integration_hit = any(contains_text_case_insensitive(d, k, timeout=0.01) for k in integration_context)

    if paywall_hit and click_first_matching_text(d, PAYWALL_SKIP_TEXTS, exact_first=True, timeout=0.02, tracker=tracker, prefix="paywall:"):
        return True

    if integration_hit and click_first_matching_text(d, INTEGRATION_SKIP_TEXTS, exact_first=True, timeout=0.02, tracker=tracker, prefix="integration:"):
        return True

    return False


def handle_webview_like_screen(d, tracker: Optional[UIActionTracker] = None) -> bool:
    if install_phase_active():
        return False

    try:
        has_webview = d(className="android.webkit.WebView").exists(timeout=0.01)
    except Exception:
        has_webview = False

    if not has_webview:
        return False

    webview_texts = ["Accept", "Agree", "Continue", "CONTINUE", "Allow", "OK", "Ok", "Next", "Skip", "Not now", "Close", "Done"]
    if click_first_matching_text(d, webview_texts, exact_first=True, timeout=0.02, tracker=tracker, prefix="webview:"):
        return True

    try:
        display = d.window_size()
        width = int(display[0])
        height = int(display[1])
        d.click(int(width * 0.5), int(height * 0.88))
        print("\n[UI] Clicked: webview:bottom_cta", flush=True)
        if tracker:
            tracker.record_action("webview:bottom_cta")
        return True
    except Exception:
        return False


def handle_health_fitness_onboarding(d, tracker: Optional[UIActionTracker] = None, screen_sig: str = "") -> bool:
    if handle_health_paywall_and_integrations(d, tracker):
        return True
    if click_preferred_health_options(d, tracker):
        return True
    if is_health_questionnaire_screen(d):
        if fill_health_profile_fields(d, tracker, screen_sig=screen_sig):
            return True
        if handle_picker_widgets(d, tracker, screen_sig=screen_sig):
            return True
        if resolve_disabled_continue_by_selecting_option(d, max_attempts=1, tracker=tracker):
            return True
    return False


def fallback_click_visible_card_or_button(d, tracker: Optional[UIActionTracker] = None) -> bool:
    for obj in enumerate_clickable_candidates(d, max_count=30):
        try:
            info = get_obj_info(obj)
            score = score_clickable_candidate(info)
            if score < 8:
                continue
            label = (info.get("text") or info.get("contentDescription") or info.get("resourceName") or "candidate").strip() or "candidate"
            if safe_click(obj, f"fallback_candidate:{label}", tracker):
                return True
        except Exception:
            pass
    return False


def is_root_blocked(d) -> bool:
    root_keywords = ["root", "rooted", "jailbreak", "security policy", "tamper"]
    for k in root_keywords:
        found = contains_text_case_insensitive(d, k, timeout=0.02)
        if found:
            print(f"[BLOCKED] Root detection UI found: {found}")
            return True
    return False


def handle_post_consent_ui_step(d, tracker: UIActionTracker) -> bool:
    if install_phase_active():
        return False

    current_sig = get_screen_signature(d)

    if current_sig == tracker.last_screen_signature:
        tracker.same_screen_rounds += 1
    else:
        tracker.same_screen_rounds = 0
        tracker.last_screen_signature = current_sig

    tracker.mark_screen_seen(current_sig)

    if handle_system_permissions(d, tracker):
        return True
    if is_root_blocked(d):
        return False
    if handle_webview_like_screen(d, tracker):
        return True
    if click_checkbox_for_terms(d, tracker):
        return True
    if click_google_auth_entry(d, tracker):
        return True
    if tap_google_account_chooser(d, timeout=0.2, tracker=tracker):
        return True
    if fill_login_form_if_present(d, tracker=tracker, screen_sig=current_sig):
        return True
    if handle_health_fitness_onboarding(d, tracker=tracker, screen_sig=current_sig):
        return True
    if fill_health_profile_fields(d, tracker=tracker, screen_sig=current_sig):
        return True
    if handle_picker_widgets(d, tracker=tracker, screen_sig=current_sig):
        return True
    if click_common_progress_buttons(d, tracker):
        return True

    if tracker.same_screen_rounds >= 1:
        if resolve_disabled_continue_by_selecting_option(d, max_attempts=1, tracker=tracker):
            return True

    fallback_texts = [
        "I already have an account", "I ALREADY HAVE AN ACCOUNT", "I have an account",
        "Get started", "Start now", "Begin", "Join now", "Create account",
        "Sign in", "Log in", "Use email", "Use email instead",
        "Continue with email", "Skip for now", "Maybe later", "Not now",
        "Later", "No thanks", "Dismiss", "Allow",
    ]
    if click_first_matching_text(d, fallback_texts, exact_first=True, timeout=0.02, tracker=tracker, prefix="fallback:"):
        return True

    if tracker.same_screen_rounds >= 2:
        if fallback_click_visible_card_or_button(d, tracker):
            return True

    return False


def stop_before_consent(d) -> bool:
    keywords = ["accept", "agree", "consent", "allow", "privacy", "continue"]
    deadline = time.time() + 3

    while time.time() < deadline:
        for k in keywords:
            found = contains_text_case_insensitive(d, k, timeout=0.02)
            if found:
                print(f"[STATE] Consent-like UI detected ({found}); not clicking")
                return True
        time.sleep(0.1)

    return False


def post_consent_ui_worker(d, tracker: UIActionTracker, stop_event: threading.Event):
    while not stop_event.is_set():
        if install_phase_active():
            stop_event.wait(0.2)
            continue

        try:
            handle_post_consent_ui_step(d, tracker)
        except Exception as e:
            print(f"\n[UI WORKER ERROR] {e}", flush=True)

        stop_event.wait(0.2)


# -------------------------
# Single-session state runner
# -------------------------
def run_country_session(d, app_id: str, country: str):
    try:
        print(f"\n=== {app_id} | {country} | single-session ===")

        if all_logs_exist_for_app_country(app_id, country):
            return True, None

        d.app_clear(app_id)
        d.app_start(app_id)

        if not d.app_wait(app_id, timeout=APP_LAUNCH_TIMEOUT):
            return False, "launch_failed"

        if is_root_blocked(d):
            return False, "root_blocked"

        if not log_exists(app_id, country, "pre_consent"):
            stop_before_consent(d)
            print(f"[CAPTURE] pre_consent ({PRE_CONSENT_CAPTURE_TIME}s)")
            print("[CAPTURE] PRE supports: s + Enter = skip, + + Enter = add 30s")
            proc, path = capture_traffic(app_id, country, "pre_consent")
            try:
                sleep_with_mode(PRE_CONSENT_CAPTURE_TIME, "PRE")
            finally:
                stop_capture(proc)
        else:
            print(f"[SKIP] Existing log: {app_id}_{country}_pre_consent.log")

        if not log_exists(app_id, country, "post_consent"):
            print(f"[CAPTURE] post_consent ({POST_CONSENT_CAPTURE_TIME}s)")
            print("[CAPTURE] POST supports: s + Enter = skip, + + Enter = add 30s")
            proc, path = capture_traffic(app_id, country, "post_consent")
            tracker = UIActionTracker()
            stop_event = threading.Event()
            ui_thread = threading.Thread(
                target=post_consent_ui_worker,
                args=(d, tracker, stop_event),
                daemon=True,
            )

            try:
                ui_thread.start()
                sleep_with_mode(POST_CONSENT_CAPTURE_TIME, "POST")
            finally:
                stop_event.set()
                ui_thread.join(timeout=0.5)
                stop_capture(proc)

            print(f"[DONE] POST_CONSENT finished for {app_id} in {country}.")
        else:
            print(f"[SKIP] Existing log: {app_id}_{country}_post_consent.log")

        return True, None

    except Exception as e:
        print(f"[ERROR] {app_id}-{country}: {e}")
        return False, "session_failed"

    finally:
        try:
            d.app_stop(app_id)
        except Exception:
            pass


# =========================================================
# Log extraction (offline; runs on captured .log files)
# =========================================================
SENSITIVITY_WEIGHTS = {
    "ip address": 1,
    "local_ip": 1,
    "domain": 1,
    "user agent": 1,

    # device / advertising / session identifiers -> canonical device_ids, weight 1
    "device_id": 1,
    "android_id": 1,
    "android_app_set_id": 1,
    "adid": 1,
    "advertising_id": 1,
    "aaid": 1,
    "hardware_id": 1,
    "device_fingerprint_id": 1,
    "identity_id": 1,
    "install_id": 1,
    "app_set_id": 1,
    "guid": 1,
    "uuid": 1,
    "cookie_id": 1,

    "profile_id": 2,

    "email": 2,
    "phone number": 2,
    "name": 2,
    "address": 2,
    "birthdate": 2,
    "geolocation": 2,
    "license number": 2,
    "ssn": 3,
    "sexual orientation": 3,
    "political opinions": 3,
    "religious belief": 3,
    "race": 3,
    "user content": 2,

    # application infrastructure (session/transport artefacts, not user
    # data) -> weight 1, matching mhealth/taxonomy.py's INFRASTRUCTURE_TOKENS
    "api_key": 1,
    "authorization token": 1,
    "bearer token": 1,
    "access_token": 1,
    "refresh_token": 1,
    "cookie": 1,
    "session_id": 1,
    "insert_id": 1,
    "request_id": 1,
    "branch_key": 1,
    "moe_user_id": 1,
    "app_key": 1,
    "trusted_account_key": 1,
    "entity_guid": 1,

    "medical record": 3,
    "health plan": 3,
    "diagnosis": 3,
    "insurance": 3,
    "psychotherapy": 3,
    "fingerprints": 3,
    "voice prints": 3,
    "biometric id": 3,
    "heart rate": 3,
    "blood pressure": 3,
    "glucose levels": 3,
    "symptoms": 3,
    "medication tracking": 3,
    "mental health logs": 3,

    "account_id": 2,
}

SENSITIVE_TYPES = {k for k, v in SENSITIVITY_WEIGHTS.items() if v >= 2}

def _key_value_pattern(*key_names):
    """Match `"key":"value"` / `"key":123` (JSON) or `key=value` (form-encoded).

    Deliberately does NOT match a bare, unquoted `key:` followed by free text
    -- that construction is indistinguishable from ordinary English
    punctuation. Requiring the key itself to be quoted (genuine JSON) for the
    colon form, and requiring no whitespace in the value for the bare form,
    rules out prose false positives.
    """
    keys = "|".join(re.escape(k) for k in key_names)
    return re.compile(
        r'"(?:' + keys + r')"\s*:\s*"?([^",\}\]\n]{1,80})"?'
        r'|\b(?:' + keys + r')\b\s*=\s*([^\s&",\}\]]{1,80})',
        re.I,
    )


domain_url_pattern = re.compile(r"https?://([A-Za-z0-9.-]+\.[A-Za-z]{2,})", re.I)

domain_header_pattern = re.compile(
    r'(?:\bHost\b|\bhost\b|\bauthority\b|\bsni\b)[^A-Za-z0-9.-]{0,20}([A-Za-z0-9.-]+\.[A-Za-z]{2,})',
    re.I,
)

error_patterns = [
    re.compile(p, re.I)
    for p in [
        "server cannot be found",
        "connection timed out",
        "dns error",
        "host unreachable",
        "connection refused",
        "network unreachable",
        "reset by peer",
        "no content",
        "protocol error",
        "bad request",
        "invalid oauth",
    ]
]

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", re.I)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
LOCAL_IP_RE = re.compile(r'"local_ip"\s*:\s*"((?:\d{1,3}\.){3}\d{1,3})"', re.I)
UUID_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}[A-Za-z]?\b",
    re.I,
)
ADDRESS_RE = re.compile(
    r"\b\d{1,5}\s+[A-Za-z0-9\s,.'-]+(?:Street|Ave|Avenue|Road|Rd|Blvd|Drive|Dr|Lane|Ln|Court|Ct|Way|Parkway|Pkwy)\b",
    re.I,
)
UA_RE = re.compile(r"\bUser-Agent\b[^,\n]*[,:\]]\s*([^,\]]+)", re.I)

BIRTHDATE_RE = _key_value_pattern(
    "dob", "date_of_birth", "dateofbirth", "birthdate", "birth_date", "birthday")
PHONE_RE = _key_value_pattern(
    "phone", "phone_number", "phonenumber", "mobile", "mobile_number", "mobilenumber",
    "telephone", "tel", "msisdn", "contact_number", "contactnumber", "cell_phone",
    "cellphone", "user_phone", "userphone")
GEO_RE = _key_value_pattern(
    "latitude", "longitude", "lat", "lng", "lon", "gps_lat", "gps_lon", "gps_latitude", "gps_longitude")
NAME_RE = _key_value_pattern(
    "full_name", "fullname", "first_name", "firstname", "last_name", "lastname",
    "customer_name", "customername", "user_name", "username", "display_name",
    "displayname", "patient_name", "patientname")

HEALTH_PATTERNS = {
    "medical record": _key_value_pattern(
        "mrn", "medical_record_number", "medicalrecordnumber", "medical_record"),
    "health plan": _key_value_pattern(
        "health_plan", "healthplan", "beneficiary_number", "beneficiarynumber"),
    "diagnosis": _key_value_pattern(
        "diagnosis", "medical_test", "medicaltest", "prescription"),
    "insurance": _key_value_pattern(
        "insurance_number", "insurancenumber", "health_insurance", "healthinsurance"),
    "psychotherapy": _key_value_pattern(
        "psychotherapy_notes", "psychotherapynotes"),
    "fingerprints": _key_value_pattern(
        "fingerprint_scan", "fingerprintscan", "biometric_fingerprint", "fingerprint_template"),
    "voice prints": _key_value_pattern(
        "voice_print", "voiceprint", "voice_template"),
    "biometric id": _key_value_pattern(
        "biometric_id", "biometricid"),
    "heart rate": _key_value_pattern(
        "heart_rate", "heartrate", "resting_heart_rate", "restingheartrate"),
    "blood pressure": _key_value_pattern(
        "blood_pressure", "bloodpressure", "systolic", "diastolic",
        "blood_pressure_systolic", "blood_pressure_diastolic"),
    "glucose levels": _key_value_pattern(
        "glucose", "glucose_level", "glucoselevel", "blood_glucose", "bloodglucose"),
    "symptoms": _key_value_pattern(
        "symptom", "symptoms"),
    "medication tracking": _key_value_pattern(
        "medication", "medications", "medication_tracking", "medicationtracking"),
    "mental health logs": _key_value_pattern(
        "mental_health_log", "mentalhealthlog", "mood_log", "moodlog"),
}


KEY_PATTERNS = {
    "device_id": [
        re.compile(r'"device_id"\s*:\s*"([^"]+)"', re.I),
        re.compile(r"\bdevice_id\b[^A-Za-z0-9_-]{0,20}([A-Za-z0-9._:-]{6,})", re.I),
        re.compile(r"\badapty-sdk-device-id\b[^A-Za-z0-9_-]{0,20}([A-Za-z0-9._:-]{6,})", re.I),
    ],
    "android_id": [
        re.compile(r'"android_id"\s*:\s*"([^"]+)"', re.I),
        re.compile(r"\bandroid_id\b[^A-Za-z0-9_-]{0,20}([A-Za-z0-9._:-]{6,})", re.I),
    ],
    "android_app_set_id": [
        re.compile(r'"android_app_set_id"\s*:\s*"([^"]+)"', re.I),
        re.compile(r"\bandroid_app_set_id\b[^A-Za-z0-9_-]{0,20}([A-Za-z0-9._:-]{6,})", re.I),
    ],
    "adid": [
        re.compile(r'"adid"\s*:\s*"([^"]+)"', re.I),
        re.compile(r"\badid\b[^A-Za-z0-9_-]{0,20}([A-Za-z0-9._:-]{6,})", re.I),
        re.compile(r'"google_advertising_id"\s*:\s*"([^"]+)"', re.I),
    ],
    "advertising_id": [
        re.compile(r'"advertising_id"\s*:\s*"([^"]+)"', re.I),
        re.compile(r"\badvertising_id\b[^A-Za-z0-9_-]{0,20}([A-Za-z0-9._:-]{6,})", re.I),
        re.compile(r'"aaid"\s*:\s*"([^"]+)"', re.I),
    ],
    "hardware_id": [
        re.compile(r'"hardware_id"\s*:\s*"([^"]+)"', re.I),
        re.compile(r"\bhardware_id\b[^A-Za-z0-9_-]{0,20}([A-Za-z0-9._:-]{6,})", re.I),
    ],
    "device_fingerprint_id": [
        re.compile(r'"device_fingerprint_id"\s*:\s*"([^"]+)"', re.I),
        re.compile(r"\bdevice_fingerprint_id\b[^A-Za-z0-9_-]{0,20}([A-Za-z0-9._:-]{6,})", re.I),
    ],
    "identity_id": [
        re.compile(r'"identity_id"\s*:\s*"([^"]+)"', re.I),
        re.compile(r"\bidentity_id\b[^A-Za-z0-9_-]{0,20}([A-Za-z0-9._:-]{6,})", re.I),
    ],
    "session_id": [
        re.compile(r'"session_id"\s*:\s*"([^"]+)"', re.I),
        re.compile(r'"session_id"\s*:\s*(\d+)', re.I),
        re.compile(r"\bNR-Session\b[^A-Za-z0-9_-]{0,20}([A-Za-z0-9._=-]{10,})", re.I),
        re.compile(r"\badapty-sdk-session\b[^A-Za-z0-9_-]{0,20}([A-Za-z0-9._:-]{6,})", re.I),
    ],
    "insert_id": [re.compile(r'"insert_id"\s*:\s*"([^"]+)"', re.I)],
    "request_id": [
        re.compile(r"\bRequest-Id\b[^A-Za-z0-9_-]{0,20}([A-Za-z0-9._:-]{6,})", re.I),
        re.compile(r"\bMOE-REQUEST-ID\b[^A-Za-z0-9_-]{0,20}([A-Za-z0-9._:-]{6,})", re.I),
        re.compile(r"\bX-Branch-Request-Id\b[^A-Za-z0-9_-]{0,20}([A-Za-z0-9._:-]{6,})", re.I),
    ],
    "profile_id": [
        re.compile(r"\badapty-sdk-profile-id\b[^A-Za-z0-9_-]{0,20}([A-Za-z0-9._:-]{6,})", re.I),
    ],
    "api_key": [
        re.compile(r'"api_key"\s*:\s*"([^"]+)"', re.I),
        re.compile(r"\bAuthorization\b[^,\n]{0,40}\bApi-Key\s+([A-Za-z0-9._-]{8,})", re.I),
        re.compile(r"\bapi[-_ ]?key\b[^A-Za-z0-9_-]{0,20}([A-Za-z0-9._-]{8,})", re.I),
    ],
    "authorization token": [
        re.compile(r"\bAuthorization\b[^,\n]{0,20}[: ]\s*([A-Za-z][A-Za-z0-9._\-+/=]{12,})", re.I),
    ],
    "bearer token": [
        re.compile(r"\bAuthorization\b[^,\n]{0,20}\bBearer\s+([A-Za-z0-9._\-+/=]{12,})", re.I),
        re.compile(r"\bBearer\s+([A-Za-z0-9._\-+/=]{12,})", re.I),
    ],
    "access_token": [
        re.compile(r'"access_token"\s*:\s*"([^"]+)"', re.I),
        re.compile(r"\baccess_token=([A-Za-z0-9%|._\-+/=]{8,})", re.I),
        re.compile(r"\baccess_token\b[^A-Za-z0-9_-]{0,20}([A-Za-z0-9%|._\-+/=]{8,})", re.I),
    ],
    "refresh_token": [
        re.compile(r'"refresh_token"\s*:\s*"([^"]+)"', re.I),
        re.compile(r"\brefresh_token\b[^A-Za-z0-9_-]{0,20}([A-Za-z0-9._\-+/=]{8,})", re.I),
    ],
    "branch_key": [
        re.compile(r'"branch_key"\s*:\s*"([^"]+)"', re.I),
        re.compile(r"\bbranch_key\b[^A-Za-z0-9_-]{0,20}([A-Za-z0-9._-]{8,})", re.I),
    ],
    "moe_user_id": [
        re.compile(r'"moe_user_id"\s*:\s*"([^"]+)"', re.I),
        re.compile(r"\bmoe_user_id\b[^A-Za-z0-9_-]{0,20}([A-Za-z0-9._:-]{4,})", re.I),
    ],
    "app_key": [
        re.compile(r"\bMOE-APPKEY\b[^A-Za-z0-9_-]{0,20}([A-Za-z0-9._-]{6,})", re.I),
    ],
    "account_id": [re.compile(r'"account_id"\s*:\s*"([^"]+)"', re.I)],
    "trusted_account_key": [re.compile(r'"trusted_account_key"\s*:\s*"([^"]+)"', re.I)],
    "entity_guid": [re.compile(r'"entity_guid"\s*:\s*"([^"]+)"', re.I)],
    "cookie": [
        re.compile(r"\bSet-Cookie\b[^,\n]{0,200}", re.I),
        re.compile(r"\bCookie\b[^,\n]{0,200}", re.I),
    ],
}


def _looks_like_real_value(value):
    """Reject captures that are coincidental byte matches inside undecoded
    binary/gzip payloads rather than real field values.

    The log files are opened as UTF-8 text with errors="replace" (see
    process_single_log), so an embedded compressed binary blob decodes as a
    mix of the Unicode replacement character and whatever raw bytes happen to
    form valid UTF-8. A real field value is overwhelmingly printable
    characters; garbage is not.
    """
    if not value or "�" in value:
        return False
    printable = sum(1 for c in value if c.isprintable())
    return printable / len(value) >= 0.9


def _first_group(match):
    """Pull the first non-empty capture group out of a findall() match.

    The field-anchored patterns (_key_value_pattern) have two alternative
    capture groups (JSON `"key":"value"` vs. bare `key=value`), so findall()
    returns a tuple where exactly one side is populated.
    """
    if isinstance(match, str):
        val = match.strip()
    else:
        val = ""
        for g in match:
            if g:
                val = str(g).strip()
                break
    return val if _looks_like_real_value(val) else ""


def safe_div_pclr(n, d):
    """PCLR-specific ratio: NaN, not 0.0, when nothing sensitive was observed.

    An (app, country) row with zero weight>=2 instances in both pre- and
    post-consent traffic has no sensitive signal to time at all, not "zero
    pre-consent leakage" -- those are different claims. Returning None here
    (mirrors mhealth/metrics.py's compute_pclr, the canonical
    implementation) excludes these rows from any downstream mean rather than
    silently counting them as perfectly-compliant observations.
    """
    return None if d == 0 else n / d


def counter_to_string(counter_obj):
    if not counter_obj:
        return None
    return ";".join(f"{dtype}:{freq}" for dtype, freq in sorted(counter_obj.items()))


def compute_adii_from_counter(type_counter):
    return sum(SENSITIVITY_WEIGHTS.get(data_type, 1) * freq for data_type, freq in type_counter.items())


def compute_weighted_sensitive_sum(type_counter):
    """Sensitivity-weighted transmission of sensitive (weight>=2) categories.

    Feeds PCLR's numerator/denominator (sigma_pre, sigma_pre+sigma_post; see
    the paper's PCLR definition and mhealth/metrics.py's compute_pclr, the
    canonical implementation). Mirrors compute_adii_from_counter's
    weighting so the two never diverge.
    """
    return sum(
        SENSITIVITY_WEIGHTS.get(data_type, 1) * freq
        for data_type, freq in type_counter.items()
        if data_type in SENSITIVE_TYPES
    )


def contains_app_id(domain, app_id):
    domain = domain.lower()
    app_id = str(app_id).lower()

    if domain in {"www.google.com", "google.com", "localhost"}:
        return False

    domain_parts = domain.split(".")[:-1]
    app_parts = [p for p in app_id.split(".") if p]

    for dpart in domain_parts:
        if dpart in {"www", "google"}:
            continue
        for apart in app_parts:
            if len(apart) >= 3 and (dpart in apart or apart in dpart):
                return True

    return False


def classify_data_type(data_type):
    phi_types = {
        "medical record", "health plan", "diagnosis", "insurance",
        "psychotherapy", "fingerprints", "voice prints", "biometric id",
        "heart rate", "blood pressure", "glucose levels", "symptoms",
        "medication tracking", "mental health logs",
    }

    pii_types = {
        "email", "phone number", "name", "address", "birthdate",
        "geolocation", "license number", "ssn", "sexual orientation",
        "political opinions", "religious belief", "race", "user content",
        "ip address", "local_ip", "device_id", "android_id",
        "android_app_set_id", "adid", "advertising_id", "aaid",
        "hardware_id", "device_fingerprint_id", "identity_id",
        "session_id", "insert_id", "request_id", "profile_id",
        "install_id", "app_set_id", "guid", "uuid", "cookie_id",
        "api_key", "authorization token", "bearer token", "access_token",
        "refresh_token", "cookie", "branch_key", "moe_user_id",
        "app_key", "account_id", "trusted_account_key", "entity_guid",
    }

    if data_type in phi_types:
        return "PHI"
    if data_type in pii_types:
        return "PII"
    return "OTHER"


def is_probably_public_ip(ip):
    try:
        parts = [int(x) for x in ip.split(".")]
        if len(parts) != 4 or any(p < 0 or p > 255 for p in parts):
            return False
        if parts[0] in {10, 127}:
            return False
        if parts[0] == 192 and parts[1] == 168:
            return False
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return False
        if parts[0] == 169 and parts[1] == 254:
            return False
        return True
    except Exception:
        return False


def dedupe_nonempty(matches):
    out = []
    seen = set()
    for m in matches:
        if m is None:
            continue
        m = str(m).strip()
        if not m or m in seen:
            continue
        out.append(m)
        seen.add(m)
    return out


def extract_domains(text):
    domains = set()
    for m in domain_url_pattern.findall(text):
        domains.add(m.lower())
    for m in domain_header_pattern.findall(text):
        domains.add(m.lower())
    return domains


def try_decompress_bytes(raw_bytes):
    candidates = []

    try:
        candidates.append(gzip.decompress(raw_bytes).decode("utf-8", errors="replace"))
    except Exception:
        pass

    try:
        candidates.append(zlib.decompress(raw_bytes).decode("utf-8", errors="replace"))
    except Exception:
        pass

    try:
        candidates.append(zlib.decompress(raw_bytes, -zlib.MAX_WBITS).decode("utf-8", errors="replace"))
    except Exception:
        pass

    return candidates


def recover_embedded_gzip_segments(text):
    recovered = []

    try:
        raw = text.encode("latin-1", errors="ignore")
    except Exception:
        return recovered

    magic = b"\x1f\x8b"
    start = 0

    raw_len = len(raw)

    while True:
        idx = raw.find(magic, start)
        if idx == -1:
            break

        for end in [min(raw_len - idx, 65536), min(raw_len - idx, 262144)]:
            sample = raw[idx:idx + end]
            for decoded in try_decompress_bytes(sample):
                if decoded and len(decoded.strip()) >= 8:
                    recovered.append(decoded)

        start = idx + 2

    return recovered


def extract_value_counts_from_text(text):
    type_counter = Counter()
    value_examples = defaultdict(set)

    for email in EMAIL_RE.findall(text):
        type_counter["email"] += 1
        value_examples["email"].add(email)

    for phone in PHONE_RE.findall(text):
        val = _first_group(phone)
        if not val:
            continue
        type_counter["phone number"] += 1
        value_examples["phone number"].add(val)

    for ip in IPV4_RE.findall(text):
        if is_probably_public_ip(ip):
            type_counter["ip address"] += 1
            value_examples["ip address"].add(ip)

    for ip in LOCAL_IP_RE.findall(text):
        type_counter["local_ip"] += 1
        value_examples["local_ip"].add(ip)

    for addr in ADDRESS_RE.findall(text):
        type_counter["address"] += 1
        value_examples["address"].add(addr)

    for bd in BIRTHDATE_RE.findall(text):
        val = _first_group(bd)
        if not val:
            continue
        type_counter["birthdate"] += 1
        value_examples["birthdate"].add(val)

    for geo in GEO_RE.findall(text):
        val = _first_group(geo)
        if not val:
            continue
        type_counter["geolocation"] += 1
        value_examples["geolocation"].add(val)

    for nm in NAME_RE.findall(text):
        val = _first_group(nm)
        if not val:
            continue
        type_counter["name"] += 1
        value_examples["name"].add(val)

    for ua in UA_RE.findall(text):
        type_counter["user agent"] += 1
        value_examples["user agent"].add(ua)

    for uuid_val in UUID_RE.findall(text):
        type_counter["uuid"] += 1
        value_examples["uuid"].add(uuid_val)

    for label, rex in HEALTH_PATTERNS.items():
        for hit in rex.findall(text):
            val = _first_group(hit)
            if not val:
                continue
            type_counter[label] += 1
            value_examples[label].add(val)

    for label, patterns in KEY_PATTERNS.items():
        for rex in patterns:
            for match in rex.findall(text):
                if isinstance(match, tuple):
                    match = next((x for x in match if x), "")
                val = str(match).strip()
                if not val:
                    continue
                type_counter[label] += 1
                value_examples[label].add(val)

    return type_counter, value_examples


def serialize_examples(example_map):
    if not example_map:
        return None
    return ";".join(f"{dtype}=>{example_map[dtype]}" for dtype in sorted(example_map))


def process_single_log(file_path, app_id):
    third_party_domains = set()
    connectivity_issues = set()
    type_counter = Counter()
    extracted_values = defaultdict(set)

    file_size_mb = os.path.getsize(file_path) / (1024 * 1024)

    MAX_LOG_CHARS = 5_000_000
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read(MAX_LOG_CHARS + 1)
    truncated = len(text) > MAX_LOG_CHARS
    if truncated:
        text = text[:MAX_LOG_CHARS]

    text = text.replace("\x00", "")

    for domain in extract_domains(text):
        if not contains_app_id(domain, app_id):
            third_party_domains.add(domain)

    tc, ev = extract_value_counts_from_text(text)
    type_counter.update(tc)

    for k, vals in ev.items():
        extracted_values[k].update(vals)

    for pat in error_patterns:
        if pat.search(text):
            connectivity_issues.add(pat.pattern)

    if truncated:
        connectivity_issues.add(f"truncated_capture_over_{MAX_LOG_CHARS}_chars")

    observed_types = set(type_counter.keys())
    pii_types = {x for x in observed_types if classify_data_type(x) == "PII"}
    phi_types = {x for x in observed_types if classify_data_type(x) == "PHI"}
    other_types = {x for x in observed_types if classify_data_type(x) == "OTHER"}

    sensitive_instances = compute_weighted_sensitive_sum(type_counter)
    all_instances = sum(type_counter.values())

    example_strings = {}
    for dtype, vals in extracted_values.items():
        cleaned = dedupe_nonempty(vals)
        if cleaned:
            example_strings[dtype] = "|".join(sorted(cleaned)[:20])

    return {
        "domains": third_party_domains,
        "observed_types": observed_types,
        "pii_types": pii_types,
        "phi_types": phi_types,
        "other_types": other_types,
        "connectivity_issues": connectivity_issues,
        "type_counter": type_counter,
        "type_examples": example_strings,
        "sensitive_instances": sensitive_instances,
        "all_instances": all_instances,
        "gzip_payload_count": 0,
        "file_size_mb": file_size_mb,
    }


def build_country_row(app_id, country, pre=None, post=None):
    pre_counter = pre["type_counter"] if pre else Counter()
    post_counter = post["type_counter"] if post else Counter()
    total_counter = pre_counter + post_counter

    pre_sensitive = compute_weighted_sensitive_sum(pre_counter)
    total_sensitive = compute_weighted_sensitive_sum(total_counter)

    return {
        "app_id": app_id,
        "country": country,

        "pre_domains": ",".join(sorted(pre["domains"])) if pre and pre["domains"] else None,
        "post_domains": ",".join(sorted(post["domains"])) if post and post["domains"] else None,

        "pre_observed_data_types": ",".join(sorted(pre["observed_types"])) if pre and pre["observed_types"] else None,
        "post_observed_data_types": ",".join(sorted(post["observed_types"])) if post and post["observed_types"] else None,

        "pre_PII": ",".join(sorted(pre["pii_types"])) if pre and pre["pii_types"] else None,
        "post_PII": ",".join(sorted(post["pii_types"])) if post and post["pii_types"] else None,

        "pre_PHI": ",".join(sorted(pre["phi_types"])) if pre and pre["phi_types"] else None,
        "post_PHI": ",".join(sorted(post["phi_types"])) if post and post["phi_types"] else None,

        "pre_OTHER": ",".join(sorted(pre["other_types"])) if pre and pre["other_types"] else None,
        "post_OTHER": ",".join(sorted(post["other_types"])) if post and post["other_types"] else None,

        "pre_sensitive_type_count_in_log": pre["sensitive_instances"] if pre else 0,
        "post_sensitive_type_count_in_log": post["sensitive_instances"] if post else 0,

        "pre_all_type_frequency_in_log": pre["all_instances"] if pre else 0,
        "post_all_type_frequency_in_log": post["all_instances"] if post else 0,

        "pre_type_frequencies": counter_to_string(pre_counter),
        "post_type_frequencies": counter_to_string(post_counter),

        "pre_type_examples": serialize_examples(pre["type_examples"]) if pre else None,
        "post_type_examples": serialize_examples(post["type_examples"]) if post else None,

        "pre_connectivity_issues": ",".join(sorted(pre["connectivity_issues"])) if pre and pre["connectivity_issues"] else None,
        "post_connectivity_issues": ",".join(sorted(post["connectivity_issues"])) if post and post["connectivity_issues"] else None,

        "pre_gzip_payload_count": pre["gzip_payload_count"] if pre else 0,
        "post_gzip_payload_count": post["gzip_payload_count"] if post else 0,

        "app_country_pre_sensitive_instances": pre_sensitive,
        "app_country_total_sensitive_instances": total_sensitive,
        "app_country_ADII": compute_adii_from_counter(total_counter),
        "app_country_PCLR": safe_div_pclr(pre_sensitive, total_sensitive),
    }


# =========================================================
# Module entry points (called by mscan.py)
# =========================================================
def _set_proxy(device: str, value: str) -> None:
    """install_app/run_country_session never touch the device's proxy setting
    themselves, so this is the missing piece: Play Store installs fail
    outright if the global proxy points at a port nothing is listening on
    (confirmed empirically), so the proxy must be OFF during install/uninstall
    and ON only for the capture window. `value` is "host:port" to enable, or
    ":0" to disable.
    """
    subprocess.run(
        [ADB, "-s", device, "shell", "settings", "put", "global", "http_proxy", value],
        check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


class VPNMismatchError(RuntimeError):
    """Raised when the device's actual egress country does not match the
    country the operator claims to have connected. Meant to stop a whole
    batch before it silently mislabels every app in it."""


def verify_vpn(expected_country_code: str) -> dict:
    """Check the device's current egress IP/country against what the
    operator claims. `expected_country_code` is a 2-letter ISO code (e.g.
    "de"); pass None/"us" to skip the WireGuard-interface check for
    no-VPN/US baseline runs, matching the batch pipeline's convention.
    """
    code = expected_country_code.upper()
    if code == "US":
        info = get_ip_and_location()
        return {"ok": info is not None, "info": info}

    ok = verify_connection(code)
    return {"ok": ok, "info": get_ip_and_location()}


def connect_device():
    """Attach to the already-running emulator. Raises/exits (via
    ensure_emulator_running) with a clear message if none is found."""
    import uiautomator2 as u2

    device = ensure_emulator_running()
    d = u2.connect(device)
    return device, d


def capture(app_id: str, country: str, device: str, d) -> dict:
    """Install the app, capture pre- and post-consent traffic, uninstall,
    and return a status dict."""
    _set_proxy(device, ":0")  # ensure it's off for install; a stale on-state
                              # from a prior run would fail the install below
    installed, install_reason = install_app(device, app_id, d)
    if not installed:
        return {"app_id": app_id, "country": country, "captured": False,
                "reason": install_reason}

    _set_proxy(device, PROXY_HOST_PORT)
    try:
        success, reason = run_country_session(d, app_id, country)
    finally:
        _set_proxy(device, ":0")  # off again before uninstall / the next app's install

    uninstall_all_third_party_apps(device)

    return {"app_id": app_id, "country": country, "captured": success,
            "reason": reason}


def extract(app_id: str, country: str) -> dict | None:
    """Run the offline extractor on this app's freshly captured logs and
    return one row in the same schema as context_level.csv (pre/post
    observed data types, type frequencies, contacted domains, ADII, PCLR),
    directly usable by mhealth.metrics.
    """
    traffic_dir = Path(NETWORK_TRAFFIC_DIR)
    pre_path = traffic_dir / f"{app_id}_{country}_pre_consent.log"
    post_path = traffic_dir / f"{app_id}_{country}_post_consent.log"

    pre = process_single_log(str(pre_path), app_id) if pre_path.exists() else None
    post = process_single_log(str(post_path), app_id) if post_path.exists() else None

    if pre is None and post is None:
        return None
    return build_country_row(app_id, country, pre=pre, post=post)


def collect(app_id: str, country: str, device: str, d) -> dict:
    """Capture + extract in one call: the network-traffic arm of the
    consolidated per-app record."""
    status = capture(app_id, country, device, d)
    row = extract(app_id, country) if status["captured"] else None
    if row is not None:
        status.update(row)
    return status
