"""
Canonical data-type taxonomy, sensitivity weights, and the observed->declared
crosswalk.

This module is the single authority for how a raw network token or a Google
Play Data Safety label maps onto a canonical user-data category. Every metric
that compares observed against declared behaviour must go through it.

WHY THIS EXISTS
---------------
The original pipeline compared observed tokens against disclosure labels by
*surface string*. Observed tokens are fine-grained (`adid`, `android_id`,
`uuid`); disclosure labels are coarse (`device or other ids`). They almost never
match literally, so the Disclosure Gap Index saturated near 1.0 (mean 0.826,
median 0.829, 56.9% of apps above 0.8) and was measuring vocabulary mismatch
rather than non-disclosure. This crosswalk mirrors the one built independently in
`analysis_scripts/12_verification_and_corrections.py` (see that file's
module docstring and Section 3.4 / Appendix D of the paper for the full
derivation and the judgment calls it documents); this module is kept
byte-for-byte consistent with it on every token that materially affects the
published DGI/ADII/PCLR numbers, so a freshly mSCAN-audited app is directly
comparable to the paper's results.
"""

from __future__ import annotations

# --------------------------------------------------------------------------
# Canonical categories. Both sides of the disclosure comparison are projected
# onto this set before any set difference is taken.
# --------------------------------------------------------------------------
CANONICAL_CATEGORIES = (
    "device_ids",
    "user_ids",
    "email",
    "name",
    "phone",
    "address",
    "dob",
    "location",
    "health",
    "biometric",
)

# --------------------------------------------------------------------------
# Sensitivity weights (paper Appendix: PII/PHI classification).
#   1 = general device / interaction data
#   2 = personal identifiers and sensitive attributes
#   3 = health and biometric (GDPR special category, HIPAA PHI)
# Applied to canonical categories so that weighting is independent of how many
# distinct raw tokens happen to map into a category.
# --------------------------------------------------------------------------
SENSITIVITY_WEIGHTS = {
    "device_ids": 1,
    "user_ids": 2,
    "email": 2,
    "name": 2,
    "phone": 2,
    "address": 2,
    "dob": 2,
    "location": 2,
    "health": 3,
    "biometric": 3,
}

# Types counted as "sensitive" for the pre-consent leakage denominator.
SENSITIVE_CATEGORIES = frozenset(
    c for c, w in SENSITIVITY_WEIGHTS.items() if w >= 2
)

# --------------------------------------------------------------------------
# Application infrastructure. These are transport/session artefacts, not user
# data, and are excluded from the disclosure comparison entirely: no disclosure
# vocabulary has a category for "bearer token", so counting them as undisclosed
# user data inflates DGI without meaning.
#
# They ARE still visible to the traffic pipeline; this set only governs the
# declared-vs-observed comparison.
# --------------------------------------------------------------------------
INFRASTRUCTURE_TOKENS = frozenset({
    "bearer token", "access_token", "refresh_token", "auth_token",
    "request_id", "session_id", "api_key", "csrf_token",
    # Added to match analysis_scripts/12_verification_and_corrections.py, the
    # crosswalk the paper's published DGI/ADII numbers are actually derived
    # from. All six are high-frequency in the corpus (cookie: 12,056 rows;
    # user agent: 23,365; branch_key: 797; insert_id: 961; local_ip: 796,
    # out of 23,391 app-country rows), so this is not a cosmetic change: an
    # earlier version of this module treated them as observed "device_ids"
    # user data instead of infrastructure, which would inflate ADII and DGI
    # for nearly every app relative to the published results.
    "cookie", "user agent", "branch_key", "insert_id", "local_ip",
    # Present in the corpus (73/73/34/30 rows respectively) but never given a
    # canonical mapping on either side, so treating them as infrastructure
    # here (rather than leaving them silently unmapped) makes the exclusion
    # explicit instead of incidental.
    "trusted_account_key", "entity_guid", "moe_user_id", "app_key",
})

# --------------------------------------------------------------------------
# Observed network tokens -> canonical categories.
#
# `ip address` -> device_ids, matching analysis_scripts/12_verification_and_
# corrections.py (the crosswalk the paper's published DGI/ADII numbers are
# derived from). An earlier version of this module mapped it to `location`
# instead (arguably also defensible -- IP is "Approximate location" under
# GDPR/Data Safety), but that disagreement would make mSCAN's own DGI/ADII
# for a freshly-audited app not directly comparable to the paper's numbers,
# since ip address is observed in effectively every (app, country) pair.
# Revisiting this classification is a legitimate methodological question for
# a future revision, but it is out of scope to change now without
# re-deriving every published DGI/ADII figure, table, and archetype in the
# paper a second time.
#
# `user agent`, `cookie`, `branch_key`, and `insert_id` are session/transport
# artefacts, not user data (see INFRASTRUCTURE_TOKENS above), and are
# intentionally absent from this dict rather than mapped here.
# --------------------------------------------------------------------------
OBSERVED_TO_CANONICAL = {
    # device / advertising identifiers
    "adid": "device_ids",
    "aaid": "device_ids",
    "idfa": "device_ids",
    "android_id": "device_ids",
    "advertising_id": "device_ids",
    "device_id": "device_ids",
    "hardware_id": "device_ids",
    "android_app_set_id": "device_ids",
    "gsf_id": "device_ids",
    "imei": "device_ids",
    "uuid": "device_ids",
    "ip address": "device_ids",
    # account identifiers
    "account_id": "user_ids",
    "profile_id": "user_ids",
    "user_id": "user_ids",
    "username": "user_ids",
    # direct identifiers
    "email": "email",
    "name": "name",
    "phone number": "phone",
    "address": "address",
    "birthdate": "dob",
    # location
    "geolocation": "location",
    # health
    "medical record": "health",
    "diagnosis": "health",
    "symptoms": "health",
    "medication": "health",
    "medication tracking": "health",     # traffic_analyzer.py's HEALTH_PATTERNS
    "heart rate": "health",              # label; "medication" (no taxonomy
    "blood pressure": "health",          # entry) is a separate, older spelling
    "glucose levels": "health",
    "fitness": "health",
    "health plan": "health",
    "insurance": "health",
    "psychotherapy": "health",
    "mental health logs": "health",
    # biometric
    "fingerprints": "biometric",
    "face_id": "biometric",
    "voice prints": "biometric",
    "biometric id": "biometric",
}

# --------------------------------------------------------------------------
# Google Play Data Safety categories -> canonical categories.
# Labels with no user-data counterpart (crash logs, diagnostics, app
# interactions, purchase history, ...) are intentionally absent: they describe
# telemetry we do not attempt to observe, so including them would let an app
# "cover" an observed category it never actually declared.
# --------------------------------------------------------------------------
#   This dict was previously missing most alias spellings (e.g., "billing
#   address", "telephone number", any "date of birth" entry at all, and
#   the entire biometric category), which understates declared coverage and
#   biases DGI upward for anything not spelled exactly like the eleven
#   original entries. Expanded to match
#   analysis_scripts/12_verification_and_corrections.py's DISCLOSED_TO_CANON
#   so mSCAN's DGI is not systematically higher than the paper's.
DECLARED_TO_CANONICAL = {
    # device / advertising identifiers
    "device or other ids": "device_ids",
    "device identifiers": "device_ids",
    "unique device identifiers": "device_ids",
    "device identifier": "device_ids",
    "cookie identifiers": "device_ids",
    "online identifiers": "device_ids",
    "mobile advertising identifiers": "device_ids",
    "advertising identifiers": "device_ids",
    "advertising identifier": "device_ids",
    "ad identifiers": "device_ids",
    "adv identifiers": "device_ids",
    "mobile ids": "device_ids",
    "marketing ids": "device_ids",
    "analytics ids": "device_ids",
    "anonymous ids": "device_ids",
    "ip address": "device_ids",
    "ip addresses": "device_ids",
    "device information": "device_ids",
    "mac address": "device_ids",
    # account identifiers
    "user ids": "user_ids",
    "account identifiers": "user_ids",
    "anonymous account identifier": "user_ids",
    "username": "user_ids",
    # direct identifiers
    "email": "email",
    "email address": "email",
    "emails": "email",
    "e-mail address": "email",
    "email addresses": "email",
    "e-mail addresses": "email",
    "name": "name",
    "first name": "name",
    "phone number": "phone",
    "telephone number": "phone",
    "address": "address",
    "physical address": "address",
    "billing address": "address",
    "shipping address": "address",
    "postal address": "address",
    "mailing address": "address",
    "home address": "address",
    "street address": "address",
    "date of birth": "dob",
    "birth date": "dob",
    "birthday": "dob",
    "birthdate": "dob",
    # location
    "approximate location": "location",
    "precise location": "location",
    "location": "location",
    "location data": "location",
    # health
    "fitness info": "health",
    "health info": "health",
    "health data": "health",
    "health information": "health",
    "diagnosis year": "health",
    "diagnostic test results": "health",
    # biometric
    "biometric information": "biometric",
    "biometric data": "biometric",
    "biometric identifiers": "biometric",
    "biometrics": "biometric",
    "fingerprint scan": "biometric",
}

# Policy-extraction artefacts that are not data-type declarations.
INVALID_DECLARATION_TOKENS = frozenset({
    "", "nan", "none", "null", "n/a", "na", "no", "no content",
    "not mentioned", "not applicable", "not at all", "unknown",
})


def canonicalize_observed(tokens, drop_infrastructure=True):
    """Project raw observed tokens onto canonical categories.

    Unmapped tokens are dropped rather than passed through, so DGI can never be
    inflated by a token vocabulary the disclosure side has no way to express.
    """
    out = set()
    for t in tokens:
        t = str(t).strip().lower()
        if drop_infrastructure and t in INFRASTRUCTURE_TOKENS:
            continue
        cat = OBSERVED_TO_CANONICAL.get(t)
        if cat:
            out.add(cat)
    return out


def canonicalize_declared(tokens):
    """Project Data Safety / policy tokens onto canonical categories."""
    out = set()
    for t in tokens:
        t = str(t).strip().lower()
        if t in INVALID_DECLARATION_TOKENS:
            continue
        cat = DECLARED_TO_CANONICAL.get(t)
        if cat:
            out.add(cat)
    return out


def weight_of(category):
    """Sensitivity weight for a canonical category (default 1)."""
    return SENSITIVITY_WEIGHTS.get(category, 1)
