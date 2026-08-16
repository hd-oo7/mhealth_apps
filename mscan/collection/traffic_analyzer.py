import os
import re
import gzip
import zlib
import pandas as pd

from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
from tqdm import tqdm


# =========================================================
# Config
# =========================================================
TRAFFIC_DATA_DIR = "../data/network_traffic"
TRAFFIC_RESULTS_PATH = "../data/traffic_results_detailed.csv"
APP_METRICS_PATH = "../data/app_privacy_metrics.csv"
DECLARATIONS_CSV = "../data/app_declared_disclosures.csv"

MAX_WORKERS = max(1, (os.cpu_count() or 2) - 1)
ENABLE_GZIP_RECOVERY = False
CHECKPOINT_COMPACT_AT_END = True


# =========================================================
# Sensitivity weights
# =========================================================
SENSITIVITY_WEIGHTS = {
    "ip address": 1,
    "local_ip": 1,
    "domain": 1,
    "user agent": 1,

    "device_id": 2,
    "android_id": 2,
    "android_app_set_id": 2,
    "adid": 2,
    "advertising_id": 2,
    "aaid": 2,
    "hardware_id": 2,
    "device_fingerprint_id": 2,
    "identity_id": 2,
    "session_id": 2,
    "insert_id": 2,
    "request_id": 2,
    "profile_id": 2,
    "install_id": 2,
    "app_set_id": 2,
    "guid": 2,
    "uuid": 2,
    "cookie_id": 2,

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

    "api_key": 3,
    "authorization token": 3,
    "bearer token": 3,
    "access_token": 3,
    "refresh_token": 3,
    "cookie": 2,

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

    "branch_key": 2,
    "moe_user_id": 2,
    "app_key": 2,
    "account_id": 2,
    "trusted_account_key": 2,
    "entity_guid": 2,
}

SENSITIVE_TYPES = {k for k, v in SENSITIVITY_WEIGHTS.items() if v >= 2}


# =========================================================
# Regex patterns
# =========================================================
filename_pattern = re.compile(
    r"^(?P<app_id>.+)_(?P<country>[a-z]{2,})_(?P<state>pre_consent|post_consent)\.log$",
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

# ---------------------------------------------------------------------------
# Field-anchored patterns.
#
# CHANGED. The previous versions of BIRTHDATE_RE, GEO_RE, NAME_RE, and every
# entry in HEALTH_PATTERNS were bare keyword/shape scans over the ENTIRE raw
# payload text with no check that the match sat in a real user-data field.
# Verified false positives from that version, found in the paper's own
# headline case study (a diabetes-management app): "blood pressure"
# matched a server-pushed news string ("...now supports Omron and
# SberZdorovie blood pressure monitors"), and "fingerprints" matched the
# `X-Session-Fingerprint` fraud-detection HTTP header. NAME_RE
# (`[A-Z][a-z]+\s[A-Z][a-z]+`) matched any two capitalized words at all,
# e.g. UI copy like "Start Now" or "Enable Location".
#
# PHONE_RE got the same treatment later, for the same reason: the bare
# 10-digit shape scan (`\d{3}[-.\s]?\d{3}[-.\s]?\d{4}`, all separators
# optional) matched any bare 10-digit number anywhere in a payload, and
# Unix timestamps in seconds are exactly 10 digits. Verified on the
# released corpus: ~85% of all "phone number" instances fell precisely in
# the plausible-timestamp numeric range (1e9-2e9) and converted to
# plausible collection-period dates; sampling 10 random apps out of 931
# showed the same signature in every one. It was missed in the original
# pass above because it lived in the bare-pattern block, not next to
# BIRTHDATE_RE/GEO_RE/NAME_RE where the fix was actually applied.
#
# Every pattern below now requires the match to sit in a JSON-style
# `"key": "value"` (or `key=value`) position where the key itself names the
# field, mirroring how KEY_PATTERNS already anchors identifier extraction.
# This is deliberately more conservative: a category with no matching
# real-world key convention in a given payload now goes undetected rather
# than triggering on prose, headers, or error strings. That is the correct
# direction per the paper's own stated precision-over-recall design --
# undercounting collection understates our findings rather than inflating
# them. The two categories with an injected, verifiable ground-truth value
# (heart rate, blood pressure -- see SYNTHETIC_PROFILE in the interaction
# scripts) additionally match on the literal synthetic value.
# ---------------------------------------------------------------------------
_SYNTHETIC_HEART_RATE = "68"
_SYNTHETIC_BP_SYSTOLIC = "118"
_SYNTHETIC_BP_DIASTOLIC = "76"


def _key_value_pattern(*key_names):
    """Match `"key":"value"` / `"key":123` (JSON) or `key=value` (form-encoded).

    Deliberately does NOT match a bare, unquoted `key:` followed by free text --
    that construction is indistinguishable from ordinary English punctuation
    ("...alerts for low and high glucose:\n\nyou can set your own
    thresholds..." matched and captured the trailing sentence as a "glucose"
    value in an earlier version of this pattern). Requiring the key itself to
    be quoted (genuine JSON) for the colon form, and requiring no whitespace in
    the value for the bare form, rules out prose false positives: English does
    not write "glucose=118" as a sentence.
    """
    keys = "|".join(re.escape(k) for k in key_names)
    return re.compile(
        r'"(?:' + keys + r')"\s*:\s*"?([^",\}\]\n]{1,80})"?'
        r'|\b(?:' + keys + r')\b\s*=\s*([^\s&",\}\]]{1,80})',
        re.I,
    )


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


# =========================================================
# Helpers
# =========================================================
def _looks_like_real_value(value):
    """Reject captures that are coincidental byte matches inside undecoded
    binary/gzip payloads rather than real field values.

    The log files are opened as UTF-8 text with errors="replace" (see
    process_single_log), so an embedded compressed binary blob decodes as a
    mix of the Unicode replacement character and whatever raw bytes happen to
    form valid UTF-8 -- occasionally including a literal `"key":` sequence by
    coincidence for a short key like "mrn". Verified in practice: three
    "medical record" matches in the initial field-anchored pass were exactly
    this (garbled control-character strings, not text). A real field value is
    overwhelmingly printable characters; garbage is not.
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


def safe_div(n, d):
    return 0.0 if d == 0 else n / d


def normalize_declared_set(value):
    if pd.isna(value) or not str(value).strip():
        return set()
    return {x.strip().lower() for x in str(value).split(",") if x.strip()}


def parse_log_filename(filename):
    m = filename_pattern.match(filename)
    if not m:
        return None
    return {
        "app_id": m.group("app_id"),
        "country": m.group("country").lower(),
        "state": m.group("state").lower(),
    }


def counter_to_string(counter_obj):
    if not counter_obj:
        return None
    return ";".join(f"{dtype}:{freq}" for dtype, freq in sorted(counter_obj.items()))


def parse_type_frequencies(raw_freqs):
    type_counter = Counter()
    if pd.isna(raw_freqs) or not str(raw_freqs).strip():
        return type_counter

    for item in str(raw_freqs).split(";"):
        if not item.strip() or ":" not in item:
            continue
        dtype, freq = item.rsplit(":", 1)
        try:
            type_counter[dtype.strip()] = int(freq.strip())
        except ValueError:
            continue

    return type_counter


def compute_adii_from_counter(type_counter):
    return sum(SENSITIVITY_WEIGHTS.get(data_type, 1) * freq for data_type, freq in type_counter.items())


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

        # PERF (unchanged output): slice directly to each bound instead of
        # first materializing raw[idx:] (the whole remainder of the file)
        # and re-slicing that. For a file with many magic-byte occurrences
        # -- common in large captures, where the 2-byte sequence also turns
        # up by pure chance -- the old form copied up to the entire rest of
        # the file at every occurrence, making this effectively quadratic.
        # raw[idx:idx+end] is byte-for-byte identical to the old
        # raw[idx:][:end] for every reachable value of end below.
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


# =========================================================
# Log processing
# =========================================================
def process_single_log(file_path, app_id):
    third_party_domains = set()
    connectivity_issues = set()
    type_counter = Counter()
    extracted_values = defaultdict(set)

    file_size_mb = os.path.getsize(file_path) / (1024 * 1024)

    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()

    for domain in extract_domains(text):
        if not contains_app_id(domain, app_id):
            third_party_domains.add(domain)

    tc, ev = extract_value_counts_from_text(text)
    type_counter.update(tc)

    for k, vals in ev.items():
        extracted_values[k].update(vals)

    recovered_payloads = recover_embedded_gzip_segments(text) if ENABLE_GZIP_RECOVERY else []

    for payload in recovered_payloads:
        for domain in extract_domains(payload):
            if not contains_app_id(domain, app_id):
                third_party_domains.add(domain)

        tc2, ev2 = extract_value_counts_from_text(payload)
        type_counter.update(tc2)

        for k, vals in ev2.items():
            extracted_values[k].update(vals)

    for pat in error_patterns:
        if pat.search(text):
            connectivity_issues.add(pat.pattern)

    observed_types = set(type_counter.keys())
    pii_types = {x for x in observed_types if classify_data_type(x) == "PII"}
    phi_types = {x for x in observed_types if classify_data_type(x) == "PHI"}
    other_types = {x for x in observed_types if classify_data_type(x) == "OTHER"}

    sensitive_instances = sum(type_counter[t] for t in type_counter if t in SENSITIVE_TYPES)
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
        "gzip_payload_count": len(recovered_payloads),
        "file_size_mb": file_size_mb,
    }


# =========================================================
# CSV schema and output helpers
# =========================================================
def detailed_expected_columns():
    return [
        "app_id",
        "country",
        "pre_domains",
        "post_domains",
        "pre_observed_data_types",
        "post_observed_data_types",
        "pre_PII",
        "post_PII",
        "pre_PHI",
        "post_PHI",
        "pre_OTHER",
        "post_OTHER",
        "pre_sensitive_type_count_in_log",
        "post_sensitive_type_count_in_log",
        "pre_all_type_frequency_in_log",
        "post_all_type_frequency_in_log",
        "pre_type_frequencies",
        "post_type_frequencies",
        "pre_type_examples",
        "post_type_examples",
        "pre_connectivity_issues",
        "post_connectivity_issues",
        "pre_gzip_payload_count",
        "post_gzip_payload_count",
        "app_country_pre_sensitive_instances",
        "app_country_total_sensitive_instances",
        "app_country_ADII",
        "app_country_PCLR",
    ]


def ensure_results_file_exists(results_path):
    if not os.path.exists(results_path):
        os.makedirs(os.path.dirname(results_path), exist_ok=True)
        pd.DataFrame(columns=detailed_expected_columns()).to_csv(results_path, index=False)


def serialize_examples(example_map):
    if not example_map:
        return None
    return ";".join(f"{dtype}=>{example_map[dtype]}" for dtype in sorted(example_map))


def build_country_row(app_id, country, pre=None, post=None):
    pre_counter = pre["type_counter"] if pre else Counter()
    post_counter = post["type_counter"] if post else Counter()
    total_counter = pre_counter + post_counter

    pre_sensitive = sum(freq for t, freq in pre_counter.items() if t in SENSITIVE_TYPES)
    total_sensitive = sum(freq for t, freq in total_counter.items() if t in SENSITIVE_TYPES)

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
        "app_country_PCLR": safe_div(pre_sensitive, total_sensitive),
    }


def has_state_data(row, state):
    prefix = "pre_" if state == "pre_consent" else "post_"
    val = row.get(f"{prefix}type_frequencies")
    return pd.notna(val) and str(val).strip() != "" and str(val).strip().lower() != "nan"


def load_processed_state(results_path):
    processed = defaultdict(lambda: {"pre_consent": False, "post_consent": False})

    if not os.path.exists(results_path):
        return processed

    try:
        df = pd.read_csv(results_path)
    except pd.errors.EmptyDataError:
        return processed

    if df.empty:
        return processed

    for _, row in df.iterrows():
        app_id = str(row["app_id"])
        country = str(row["country"]).lower()
        key = (app_id, country)

        if has_state_data(row, "pre_consent"):
            processed[key]["pre_consent"] = True

        if has_state_data(row, "post_consent"):
            processed[key]["post_consent"] = True

    return processed


def append_rows(rows, results_path):
    if not rows:
        return

    expected_cols = detailed_expected_columns()
    os.makedirs(os.path.dirname(results_path), exist_ok=True)

    write_header = not os.path.exists(results_path) or os.path.getsize(results_path) == 0

    pd.DataFrame(rows, columns=expected_cols).to_csv(
        results_path,
        mode="a",
        header=write_header,
        index=False,
    )


def merge_csv_sets(*values):
    merged = set()
    for val in values:
        if pd.isna(val) or not str(val).strip():
            continue
        merged.update(x.strip() for x in str(val).split(",") if x.strip())
    return ",".join(sorted(merged)) or None


def first_nonempty(*values):
    for val in values:
        if pd.notna(val) and str(val).strip() and str(val).strip().lower() != "nan":
            return val
    return None


def compact_detailed_results_csv(results_path):
    if not os.path.exists(results_path):
        return

    try:
        df = pd.read_csv(results_path)
    except pd.errors.EmptyDataError:
        return

    if df.empty:
        return

    expected_cols = detailed_expected_columns()
    for col in expected_cols:
        if col not in df.columns:
            df[col] = None

    compact_rows = []

    for (app_id, country), g in df.groupby(["app_id", "country"], dropna=False):
        pre_counter = Counter()
        post_counter = Counter()

        for val in g["pre_type_frequencies"]:
            pre_counter.update(parse_type_frequencies(val))

        for val in g["post_type_frequencies"]:
            post_counter.update(parse_type_frequencies(val))

        total_counter = pre_counter + post_counter
        pre_sensitive = sum(freq for t, freq in pre_counter.items() if t in SENSITIVE_TYPES)
        post_sensitive = sum(freq for t, freq in post_counter.items() if t in SENSITIVE_TYPES)
        total_sensitive = sum(freq for t, freq in total_counter.items() if t in SENSITIVE_TYPES)

        compact_rows.append(
            {
                "app_id": app_id,
                "country": country,

                "pre_domains": merge_csv_sets(*g["pre_domains"].tolist()),
                "post_domains": merge_csv_sets(*g["post_domains"].tolist()),

                "pre_observed_data_types": merge_csv_sets(*g["pre_observed_data_types"].tolist()),
                "post_observed_data_types": merge_csv_sets(*g["post_observed_data_types"].tolist()),

                "pre_PII": merge_csv_sets(*g["pre_PII"].tolist()),
                "post_PII": merge_csv_sets(*g["post_PII"].tolist()),

                "pre_PHI": merge_csv_sets(*g["pre_PHI"].tolist()),
                "post_PHI": merge_csv_sets(*g["post_PHI"].tolist()),

                "pre_OTHER": merge_csv_sets(*g["pre_OTHER"].tolist()),
                "post_OTHER": merge_csv_sets(*g["post_OTHER"].tolist()),

                "pre_sensitive_type_count_in_log": pre_sensitive,
                "post_sensitive_type_count_in_log": post_sensitive,

                "pre_all_type_frequency_in_log": sum(pre_counter.values()),
                "post_all_type_frequency_in_log": sum(post_counter.values()),

                "pre_type_frequencies": counter_to_string(pre_counter),
                "post_type_frequencies": counter_to_string(post_counter),

                "pre_type_examples": first_nonempty(*g["pre_type_examples"].tolist()),
                "post_type_examples": first_nonempty(*g["post_type_examples"].tolist()),

                "pre_connectivity_issues": merge_csv_sets(*g["pre_connectivity_issues"].tolist()),
                "post_connectivity_issues": merge_csv_sets(*g["post_connectivity_issues"].tolist()),

                "pre_gzip_payload_count": int(pd.to_numeric(g["pre_gzip_payload_count"], errors="coerce").fillna(0).sum()),
                "post_gzip_payload_count": int(pd.to_numeric(g["post_gzip_payload_count"], errors="coerce").fillna(0).sum()),

                "app_country_pre_sensitive_instances": pre_sensitive,
                "app_country_total_sensitive_instances": total_sensitive,
                "app_country_ADII": compute_adii_from_counter(total_counter),
                "app_country_PCLR": safe_div(pre_sensitive, total_sensitive),
            }
        )

    compact_df = pd.DataFrame(compact_rows, columns=expected_cols).sort_values(["app_id", "country"])

    backup_path = results_path + ".append_backup"
    if os.path.exists(backup_path):
        os.remove(backup_path)

    os.rename(results_path, backup_path)
    compact_df.to_csv(results_path, index=False)

    print(f"[INFO] Compacted detailed results: {len(df)} appended rows -> {len(compact_df)} app-country rows.")
    print(f"[INFO] Append backup saved to: {backup_path}")


# =========================================================
# App metrics
# =========================================================
def load_declarations_map(declarations_csv):
    if not os.path.exists(declarations_csv):
        return {}

    try:
        decl_df = pd.read_csv(declarations_csv)
    except Exception as e:
        print(f"[WARN] Failed to load declarations CSV: {e}")
        return {}

    required_cols = {"app_id", "declared_data_types"}

    if not required_cols.issubset(decl_df.columns):
        print("[WARN] DECLARATIONS_CSV exists but missing: app_id, declared_data_types")
        return {}

    return {
        str(row["app_id"]): normalize_declared_set(row["declared_data_types"])
        for _, row in decl_df.iterrows()
    }


def recompute_app_metrics_from_detailed_csv(detailed_results_path, declarations_csv, app_metrics_path):
    if not os.path.exists(detailed_results_path):
        print("[WARN] No detailed results available; app metrics not generated.")
        return

    declared_map = load_declarations_map(declarations_csv)

    per_app = defaultdict(
        lambda: {
            "domains": set(),
            "countries": set(),
            "observed_types": set(),
            "pii_types": set(),
            "phi_types": set(),
            "other_types": set(),
            "connectivity_issues": set(),
            "type_counter_total": Counter(),
            "type_counter_pre": Counter(),
            "type_counter_post": Counter(),
            "country_rows": 0,
        }
    )

    def split_csv_set(val):
        if pd.isna(val) or not str(val).strip():
            return set()
        return {x.strip() for x in str(val).split(",") if x.strip()}

    try:
        for chunk in pd.read_csv(detailed_results_path, chunksize=5000):
            for _, row in chunk.iterrows():
                app_id = str(row["app_id"])
                country = str(row["country"]).lower()

                pre_counter = parse_type_frequencies(row.get("pre_type_frequencies"))
                post_counter = parse_type_frequencies(row.get("post_type_frequencies"))
                total_counter = pre_counter + post_counter

                per_app[app_id]["countries"].add(country)
                per_app[app_id]["country_rows"] += 1

                per_app[app_id]["domains"].update(split_csv_set(row.get("pre_domains")))
                per_app[app_id]["domains"].update(split_csv_set(row.get("post_domains")))

                per_app[app_id]["observed_types"].update(split_csv_set(row.get("pre_observed_data_types")))
                per_app[app_id]["observed_types"].update(split_csv_set(row.get("post_observed_data_types")))

                per_app[app_id]["pii_types"].update(split_csv_set(row.get("pre_PII")))
                per_app[app_id]["pii_types"].update(split_csv_set(row.get("post_PII")))

                per_app[app_id]["phi_types"].update(split_csv_set(row.get("pre_PHI")))
                per_app[app_id]["phi_types"].update(split_csv_set(row.get("post_PHI")))

                per_app[app_id]["other_types"].update(split_csv_set(row.get("pre_OTHER")))
                per_app[app_id]["other_types"].update(split_csv_set(row.get("post_OTHER")))

                per_app[app_id]["connectivity_issues"].update(split_csv_set(row.get("pre_connectivity_issues")))
                per_app[app_id]["connectivity_issues"].update(split_csv_set(row.get("post_connectivity_issues")))

                per_app[app_id]["type_counter_pre"].update(pre_counter)
                per_app[app_id]["type_counter_post"].update(post_counter)
                per_app[app_id]["type_counter_total"].update(total_counter)

    except pd.errors.EmptyDataError:
        print("[WARN] Detailed results file is empty; app metrics not generated.")
        return

    app_rows = []

    for app_id, info in per_app.items():
        observed_types = set(info["observed_types"])
        declared_types = declared_map.get(app_id, set())
        undeclared_observed = observed_types - declared_types

        s_pre = sum(freq for t, freq in info["type_counter_pre"].items() if t in SENSITIVE_TYPES)
        s_total = sum(freq for t, freq in info["type_counter_total"].items() if t in SENSITIVE_TYPES)

        app_rows.append(
            {
                "app_id": app_id,
                "countries_observed": ",".join(sorted(info["countries"])) or None,
                "domains": ",".join(sorted(info["domains"])) or None,
                "observed_data_types": ",".join(sorted(observed_types)) or None,
                "declared_data_types": ",".join(sorted(declared_types)) or None,
                "undeclared_observed_data_types": ",".join(sorted(undeclared_observed)) or None,
                "PII": ",".join(sorted(info["pii_types"])) or None,
                "PHI": ",".join(sorted(info["phi_types"])) or None,
                "OTHER": ",".join(sorted(info["other_types"])) or None,
                "pre_sensitive_instances": s_pre,
                "total_sensitive_instances": s_total,
                "ADII": compute_adii_from_counter(info["type_counter_total"]),
                "DGI": safe_div(len(undeclared_observed), len(observed_types)) if declared_map else None,
                "PCLR": safe_div(s_pre, s_total),
                "connectivity_issues": ",".join(sorted(info["connectivity_issues"])) or None,
                "country_rows_processed": info["country_rows"],
            }
        )

    app_df = pd.DataFrame(app_rows)

    if not app_df.empty:
        app_df = app_df.sort_values("app_id")

    os.makedirs(os.path.dirname(app_metrics_path), exist_ok=True)
    app_df.to_csv(app_metrics_path, index=False)

    print(f"[INFO] App metrics saved to: {app_metrics_path}")


# =========================================================
# Inventory
# =========================================================
def remove_empty_log_files(directory):
    removed = 0

    for filename in os.listdir(directory):
        if not filename.endswith(".log"):
            continue

        file_path = os.path.join(directory, filename)

        try:
            if os.path.getsize(file_path) == 0:
                os.remove(file_path)
                removed += 1
                continue

            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                if not f.read().strip():
                    os.remove(file_path)
                    removed += 1

        except Exception as e:
            print(f"[WARN] Failed to check/remove {file_path}: {e}")

    print(f"[INFO] Removed {removed} empty .log files.")
    return removed


def collect_log_inventory(directory):
    valid_groups = defaultdict(dict)
    invalid_filenames = []
    all_logs = sorted(f for f in os.listdir(directory) if f.endswith(".log"))

    for filename in all_logs:
        parsed = parse_log_filename(filename)

        if not parsed:
            invalid_filenames.append(filename)
            continue

        key = (parsed["app_id"], parsed["country"])
        state = parsed["state"]

        if state in valid_groups[key]:
            print(
                f"[WARN] Multiple files detected for {key} / {state}. "
                f"Keeping {valid_groups[key][state]} and ignoring {filename}."
            )
            continue

        valid_groups[key][state] = filename

    return all_logs, valid_groups, invalid_filenames


def build_app_index(valid_groups, valid_log_files):
    valid_log_files = set(valid_log_files)
    app_index = defaultdict(list)

    for (app_id, country), state_files in valid_groups.items():
        for state, filename in state_files.items():
            if filename in valid_log_files:
                app_index[app_id].append(
                    {
                        "app_id": app_id,
                        "country": country,
                        "state": state,
                        "filename": filename,
                    }
                )

    return dict(sorted(app_index.items(), key=lambda x: x[0]))


def print_processing_summary(total_logs, valid_log_count, invalid_count, apps_seen, apps_processed, files_processed, rows_appended):
    print("\n[SUMMARY] Log processing coverage")
    print(f"[SUMMARY] Total .log files present: {total_logs}")
    print(f"[SUMMARY] Valid .log files matching expected pattern: {valid_log_count}")
    print(f"[SUMMARY] Invalid filename format: {invalid_count}")
    print(f"[SUMMARY] App IDs discovered: {apps_seen}")
    print(f"[SUMMARY] App IDs processed in this run: {apps_processed}")
    print(f"[SUMMARY] Files processed in this run: {files_processed}")
    print(f"[SUMMARY] Rows appended in this run: {rows_appended}")


# =========================================================
# Multiprocessing workers
# =========================================================
def process_one_log_worker(args):
    app_id, country, state, filename, traffic_data_dir = args
    file_path = os.path.join(traffic_data_dir, filename)

    result = process_single_log(file_path, app_id)

    return {
        "app_id": app_id,
        "country": country,
        "state": state,
        "filename": filename,
        "result": result,
    }


def process_one_app_parallel(app_id, app_items, processed_state, traffic_data_dir, max_workers):
    tasks = []

    for item in app_items:
        country = item["country"]
        state = item["state"]
        filename = item["filename"]

        key = (app_id, country)

        if processed_state[key][state]:
            continue

        tasks.append((app_id, country, state, filename, traffic_data_dir))

    if not tasks:
        return [], 0

    results_by_country = defaultdict(dict)
    files_processed = 0

    workers = min(max_workers, len(tasks))

    with ProcessPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(process_one_log_worker, task) for task in tasks]

        for future in as_completed(futures):
            item = future.result()

            country = item["country"]
            state = item["state"]
            result = item["result"]

            results_by_country[country][state] = result
            processed_state[(app_id, country)][state] = True
            files_processed += 1

    rows = []

    for country, states in results_by_country.items():
        pre = states.get("pre_consent")
        post = states.get("post_consent")
        rows.append(build_country_row(app_id, country, pre=pre, post=post))

    return rows, files_processed


# =========================================================
# Main
# =========================================================
def main():
    if not os.path.isdir(TRAFFIC_DATA_DIR):
        raise FileNotFoundError(f"TRAFFIC_DATA_DIR does not exist: {TRAFFIC_DATA_DIR}")

    print(f"[INFO] MAX_WORKERS={MAX_WORKERS}")
    print(f"[INFO] ENABLE_GZIP_RECOVERY={ENABLE_GZIP_RECOVERY}")

    remove_empty_log_files(TRAFFIC_DATA_DIR)

    all_logs, valid_groups, invalid_filenames = collect_log_inventory(TRAFFIC_DATA_DIR)

    valid_log_files = [
        f for f in all_logs
        if f not in set(invalid_filenames)
        and not f.endswith("_fresh.log")
    ]

    if not valid_log_files:
        print(f"[WARN] No valid .log files found in {TRAFFIC_DATA_DIR}")
        return False

    ensure_results_file_exists(TRAFFIC_RESULTS_PATH)

    processed_state = load_processed_state(TRAFFIC_RESULTS_PATH)
    app_index = build_app_index(valid_groups, valid_log_files)

    apps_processed = 0
    files_processed_total = 0
    rows_appended_total = 0

    print(
        f"[INFO] Starting multiprocessing app-level processing | "
        f"valid_logs={len(valid_log_files)} | app_ids={len(app_index)}"
    )

    for app_id, app_items in tqdm(app_index.items(), desc="Processing app_ids", unit="app"):
        has_unprocessed = False

        for item in app_items:
            key = (item["app_id"], item["country"])
            state = item["state"]

            if not processed_state[key][state]:
                has_unprocessed = True
                break

        if not has_unprocessed:
            continue

        print(f"\n[APP-START] app_id={app_id} | files={len(app_items)}", flush=True)

        rows, files_processed = process_one_app_parallel(
            app_id=app_id,
            app_items=app_items,
            processed_state=processed_state,
            traffic_data_dir=TRAFFIC_DATA_DIR,
            max_workers=MAX_WORKERS,
        )

        append_rows(rows, TRAFFIC_RESULTS_PATH)

        apps_processed += 1
        files_processed_total += files_processed
        rows_appended_total += len(rows)

        print(
            f"[APP-DONE] app_id={app_id} | "
            f"files_processed={files_processed} | "
            f"rows_appended={len(rows)}",
            flush=True,
        )

    if CHECKPOINT_COMPACT_AT_END:
        compact_detailed_results_csv(TRAFFIC_RESULTS_PATH)

    recompute_app_metrics_from_detailed_csv(
        TRAFFIC_RESULTS_PATH,
        DECLARATIONS_CSV,
        APP_METRICS_PATH,
    )

    print_processing_summary(
        total_logs=len(all_logs),
        valid_log_count=len(valid_log_files),
        invalid_count=len(invalid_filenames),
        apps_seen=len(app_index),
        apps_processed=apps_processed,
        files_processed=files_processed_total,
        rows_appended=rows_appended_total,
    )

    print("Traffic analysis complete.")

    return files_processed_total > 0


if __name__ == "__main__":
    print("[INFO] Starting traffic analysis run...")

    try:
        processed_anything = main()
    except Exception as e:
        print(f"[FATAL] Run failed: {e}")
        processed_anything = False

    if processed_anything:
        print("[INFO] Processing completed successfully.")
    else:
        print("[INFO] No new files processed.")