"""
Canonical data-type taxonomy, sensitivity weights, and the observed->declared
crosswalk.

This module is the single authority for how a raw network token or a Google
Play Data Safety label maps onto a canonical user-data category. Every metric
that compares observed against declared behaviour must go through it.

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

INFRASTRUCTURE_TOKENS = frozenset({
    "bearer token", "access_token", "refresh_token", "auth_token",
    "request_id", "session_id", "api_key", "csrf_token",
    "cookie", "user agent", "branch_key", "insert_id", "local_ip",
    "trusted_account_key", "entity_guid", "moe_user_id", "app_key",
})

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
