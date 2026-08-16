import subprocess
import sys
import uiautomator2 as u2
import pandas as pd
import time
import os
import json
import select
import threading
import re
from tqdm import tqdm
from typing import Optional

# -------------------------
# Config
# -------------------------
_SDK_ROOT = os.environ.get("ANDROID_SDK_ROOT") or os.environ.get("ANDROID_HOME") \
    or os.path.expanduser("~/Library/Android/sdk")
ADB = os.path.join(_SDK_ROOT, "platform-tools", "adb")
NETWORK_TRAFFIC_DIR = "../data/network_traffic"
INCOMPATIBLE_CSV = "../data/incompatible_apps.csv"
APPS_CSV = "../data/mhealth_apps_filled.csv"

# Optimized timing defaults
PRE_CONSENT_CAPTURE_TIME = 12
POST_CONSENT_CAPTURE_TIME = 30

APP_LAUNCH_TIMEOUT = 3
INSTALL_TIMEOUT = 120

WG_CONFIG_DIR = "wireguard_configs"
WG_VERIFY_TIMEOUT = 12
WG_RETRY_WAIT = 2
WG_RETRIES = 1

WIFI_SERVICE_NAME = "Wi-Fi"

# Enable interactive countdown for BOTH pre- and post-consent capture
# Commands during countdown:
#   s + Enter  -> skip remaining time
#   + + Enter  -> add 30 seconds
ENABLE_INTERACTIVE_COUNTDOWN = True

# Single-session phases per app-country
STATES = ["pre_consent", "post_consent"]

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

INSTALL_PRECHECK_POPUP_DESCS = ["Close"]

INSTALLATION_IN_PROGRESS = threading.Event()


def begin_install_phase():
    INSTALLATION_IN_PROGRESS.set()


def end_install_phase():
    INSTALLATION_IN_PROGRESS.clear()


def install_phase_active() -> bool:
    return INSTALLATION_IN_PROGRESS.is_set()


# -------------------------
# General Helpers
# -------------------------
def ensure_directory_exists(directory: str) -> None:
    os.makedirs(directory, exist_ok=True)


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


def clear_wifi_dns_servers() -> bool:
    output = run_cmd(
        ["sudo", "networksetup", "-setdnsservers", WIFI_SERVICE_NAME, "Empty"],
        check=False,
        timeout=20,
    )
    return output is not None


def get_device() -> str:
    output = subprocess.check_output([ADB, "devices"]).decode().splitlines()
    devices = [line.split("\t")[0] for line in output if "\tdevice" in line]
    emulator = next((d for d in devices if d.startswith("emulator")), None)
    if not emulator:
        raise RuntimeError("No emulator connected.")
    return emulator


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
# WireGuard Helpers
# -------------------------
def get_country_configs():
    configs = {}
    if not os.path.exists(WG_CONFIG_DIR):
        return configs

    for file in os.listdir(WG_CONFIG_DIR):
        if file.endswith(".conf"):
            country = file.replace(".conf", "").lower()
            configs[country] = {
                "path": os.path.join(WG_CONFIG_DIR, file),
                "expected_code": country.upper(),
            }
    return configs


def connect_wireguard(config_path: str):
    print(f"[WG] Connecting: {config_path}")
    return run_cmd(["sudo", "wg-quick", "up", config_path], check=False, timeout=25)


def disconnect_wireguard(config_path: str):
    print(f"[WG] Disconnecting: {config_path}")
    run_cmd(["sudo", "wg-quick", "down", config_path], check=False, timeout=25)


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


def connect_and_verify_wireguard(config_path: str, expected_code: str, retries: int = WG_RETRIES) -> bool:
    for attempt in range(1, retries + 1):
        connect_wireguard(config_path)

        deadline = time.time() + WG_VERIFY_TIMEOUT
        while time.time() < deadline:
            if verify_connection(expected_code):
                clear_wifi_dns_servers()
                return True
            time.sleep(1)

        print(f"[WG RETRY] Attempt {attempt}/{retries} failed for {expected_code}")
        disconnect_wireguard(config_path)
        time.sleep(WG_RETRY_WAIT)

    return False


# -------------------------
# Incompatibility tracking
# -------------------------
GLOBAL_INCOMPATIBILITY_REASONS = {
    "not_compatible_with_phone",
    "not_compatible_with_device",
    "app_wont_work_for_device",
    "no_enough_space",
    "root_blocked",
    "paid_app",
}


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


def _normalize_country_value(value) -> str:
    if pd.isna(value):
        return ""
    return str(value).strip().lower()


def _upgrade_incompatibility_df(df: pd.DataFrame) -> pd.DataFrame:
    if "app_id" not in df.columns or "reason" not in df.columns:
        return pd.DataFrame(columns=["app_id", "country", "reason"])

    df = df.copy()
    if "country" not in df.columns:
        df["country"] = ""
        known_countries = set(get_country_configs().keys())
        upgraded_countries = []
        upgraded_reasons = []

        for _, row in df.iterrows():
            reason = str(row.get("reason", "") or "").strip()
            lower_reason = reason.lower()

            if lower_reason in GLOBAL_INCOMPATIBILITY_REASONS:
                upgraded_countries.append("")
                upgraded_reasons.append(lower_reason)
                continue

            prefix, sep, remainder = lower_reason.partition("_")
            if sep and prefix in known_countries and remainder:
                upgraded_countries.append(prefix)
                upgraded_reasons.append(remainder)
            else:
                upgraded_countries.append("")
                upgraded_reasons.append(lower_reason)

        df["country"] = upgraded_countries
        df["reason"] = upgraded_reasons
    else:
        df["country"] = df["country"].apply(_normalize_country_value)
        df["reason"] = df["reason"].astype(str).str.strip().str.lower()

    df["app_id"] = df["app_id"].astype(str).str.strip()
    df = df[["app_id", "country", "reason"]].drop_duplicates(subset=["app_id", "country", "reason"])
    return df


def load_incompatibility_data():
    if os.path.exists(INCOMPATIBLE_CSV):
        try:
            df = pd.read_csv(INCOMPATIBLE_CSV)
            return _upgrade_incompatibility_df(df)
        except Exception as e:
            print(f"[WARN] Failed to read CSV: {e}")
    return pd.DataFrame(columns=["app_id", "country", "reason"])


def append_incompatibility(app_id: str, reason: str, country: Optional[str] = None):
    normalized_reason = (reason or "").strip().lower()
    normalized_country = "" if normalized_reason in GLOBAL_INCOMPATIBILITY_REASONS else _normalize_country_value(country)

    df_new = pd.DataFrame(
        [[str(app_id).strip(), normalized_country, normalized_reason]],
        columns=["app_id", "country", "reason"],
    )

    if os.path.exists(INCOMPATIBLE_CSV):
        try:
            df_existing = _upgrade_incompatibility_df(pd.read_csv(INCOMPATIBLE_CSV))
            df_combined = pd.concat([df_existing, df_new], ignore_index=True)
            df_combined = df_combined.drop_duplicates(subset=["app_id", "country", "reason"])
        except Exception as e:
            print(f"[WARN] CSV issue, recreating: {e}")
            df_combined = df_new
    else:
        df_combined = df_new

    df_combined.to_csv(INCOMPATIBLE_CSV, index=False)


def get_globally_incompatible_app_ids(df: pd.DataFrame) -> set[str]:
    if df.empty:
        return set()
    mask = df["reason"].isin(GLOBAL_INCOMPATIBILITY_REASONS)
    return set(df.loc[mask, "app_id"].astype(str).str.strip().tolist())


def get_country_specific_incompatibilities(df: pd.DataFrame) -> set[tuple[str, str]]:
    if df.empty:
        return set()

    pairs = set()
    for _, row in df.iterrows():
        app_id = str(row.get("app_id", "") or "").strip()
        country = _normalize_country_value(row.get("country", ""))
        reason = str(row.get("reason", "") or "").strip().lower()

        if not app_id or not country or reason in GLOBAL_INCOMPATIBILITY_REASONS:
            continue

        pairs.add((app_id, country))

    return pairs


# -------------------------
# Install helpers
# -------------------------
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


# -------------------------
# Install / Uninstall
# -------------------------
MAGISK_PACKAGE = "com.topjohnwu.magisk"

PRESERVED_PACKAGES = {
    MAGISK_PACKAGE,
}


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


SAFE_INSTALL_POPUP_TEXTS = {"Got it", "Close"}


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
# Traffic Capture
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
# UI Handling
# -------------------------
def safe_exists(obj, timeout: float = 0.02) -> bool:
    try:
        return obj.exists(timeout=timeout)
    except Exception:
        return False


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
# Single-session State Runner
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


# -------------------------
# Main Pipeline
# -------------------------
def main():
    device = ensure_emulator_running()
    ensure_directory_exists(NETWORK_TRAFFIC_DIR)

    df = pd.read_csv(APPS_CSV)
    app_ids = df["app_id"].dropna().drop_duplicates().tolist()

    d = u2.connect(device)

    country_configs = get_country_configs()
    if not country_configs:
        print(f"[!] No WireGuard configs found in {WG_CONFIG_DIR}")
        sys.exit(1)

    incompat_df = load_incompatibility_data()
    globally_incompatible_ids = get_globally_incompatible_app_ids(incompat_df)
    country_incompatible_pairs = get_country_specific_incompatibilities(incompat_df)

    countries = sorted(country_configs.keys())

    print(f"[INFO] Total apps: {len(app_ids)}")
    print(f"[INFO] Known globally incompatible apps: {len(globally_incompatible_ids)}")
    print(f"[INFO] Known app-country incompatibilities: {len(country_incompatible_pairs)}")
    print(f"[INFO] Countries: {countries}")

    for country in countries:
        cfg = country_configs[country]
        config_path = cfg["path"]
        expected_code = cfg["expected_code"]

        print(f"\n========== COUNTRY={country.upper()} ==========")

        vpn_used = expected_code.upper() != "US"

        if not vpn_used:
            print("[WG] Skipping VPN for US — running without VPN")
            connected = True
        else:
            connected = connect_and_verify_wireguard(config_path, expected_code, retries=WG_RETRIES)

        if not connected:
            print(f"[SKIP] WireGuard failed for {country.upper()}")
            continue

        try:
            for app_id in tqdm(app_ids, desc=f"{country.upper()}"):
                if app_id in globally_incompatible_ids:
                    continue

                if (app_id, country) in country_incompatible_pairs:
                    continue

                if all_logs_exist_for_app_country(app_id, country):
                    continue

                success, reason = install_app(device, app_id, d)
                if not success:
                    append_incompatibility(app_id, reason, country=country)
                    if reason in GLOBAL_INCOMPATIBILITY_REASONS:
                        globally_incompatible_ids.add(app_id)
                    else:
                        country_incompatible_pairs.add((app_id, country))
                    uninstall_all_third_party_apps(device, app_id)
                    continue

                if not is_app_installed(device, app_id):
                    append_incompatibility(app_id, "not_installed_after_install", country=country)
                    country_incompatible_pairs.add((app_id, country))
                    uninstall_all_third_party_apps(device, app_id)
                    continue

                success, reason = run_country_session(d, app_id, country)
                if not success:
                    append_incompatibility(app_id, reason, country=country)
                    if reason in GLOBAL_INCOMPATIBILITY_REASONS:
                        globally_incompatible_ids.add(app_id)
                    else:
                        country_incompatible_pairs.add((app_id, country))

                uninstall_all_third_party_apps(device, app_id)

        finally:
            uninstall_all_third_party_apps(device=device)

            if vpn_used:
                disconnect_wireguard(config_path)
                time.sleep(0.5)

    print("\n[COMPLETE] All apps processed.")


if __name__ == "__main__":
    main()