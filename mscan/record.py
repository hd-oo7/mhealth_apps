"""Consolidates the four per-source dicts (Data Safety, privacy policy,
permissions/trackers, network traffic) into one record per app, in the same
field vocabulary the rest of the mhealth pipeline uses, and optionally
computes ADII/DGI/PCLR for the audited (app, country) pair directly via
mhealth.metrics.
"""

from __future__ import annotations

import sys
from pathlib import Path

# mhealth/ lives inside this package (mscan/mhealth/) so record.py is
# self-contained; the sys.path bootstrap makes `import mhealth` resolve
# whether record.py is imported via mscan.py (which already adds this
# directory to sys.path) or standalone.
_MSCAN_DIR = Path(__file__).resolve().parent
if str(_MSCAN_DIR) not in sys.path:
    sys.path.insert(0, str(_MSCAN_DIR))


def build_record(app_id: str, country: str, data_safety: dict | None,
                  privacy_policy: dict | None, permissions_trackers: dict | None,
                  network_traffic: dict | None) -> dict:
    """Merge the four sources' output into one row. `data_safety_data_collected` /
    `data_safety_data_shared` prefer the privacy policy's LLM-parsed answers when
    present and fall back to the Data Safety label, mirroring how the two
    sources are combined for the full corpus (\\S3.2: "we ... rely only on
    the Data Safety label for the declared side" when no policy text was
    retrievable).
    """
    data_safety = data_safety or {}
    privacy_policy = privacy_policy or {}
    permissions_trackers = permissions_trackers or {}
    network_traffic = network_traffic or {}

    record = {
        "app_id": app_id,
        "country": country,

        # Declared side (Data Safety + privacy policy)
        "data_safety_data_collected": privacy_policy.get("data_safety_data_collected") or data_safety.get("data_safety_data_collected"),
        "data_safety_data_shared": privacy_policy.get("data_safety_data_shared") or data_safety.get("data_safety_data_shared"),
        "data_safety_security_practices": data_safety.get("data_safety_security_practices"),
        "policy_retrieved": privacy_policy.get("policy_retrieved"),
        "disclosure_rating": privacy_policy.get("disclosure_rating"),

        # Static APK artifacts
        "permissions": permissions_trackers.get("permissions"),
        "num_permissions": permissions_trackers.get("num_permissions"),
        "dangerous_permissions": permissions_trackers.get("dangerous_permissions"),
        "num_dangerous_permissions": permissions_trackers.get("num_dangerous_permissions"),
        "trackers": permissions_trackers.get("trackers"),
        "num_trackers": permissions_trackers.get("num_trackers"),

        # Observed side (network traffic)
        "traffic_captured": network_traffic.get("captured", False),
        "traffic_skip_reason": network_traffic.get("reason"),
        "pre_observed_data_types": network_traffic.get("pre_observed_data_types"),
        "post_observed_data_types": network_traffic.get("post_observed_data_types"),
        "pre_type_frequencies": network_traffic.get("pre_type_frequencies"),
        "post_type_frequencies": network_traffic.get("post_type_frequencies"),
        "pre_domains": network_traffic.get("pre_domains"),
        "post_domains": network_traffic.get("post_domains"),
    }
    return record


def compute_metrics(record: dict) -> dict:
    """ADII / DGI / PCLR for this one (app, country), using the exact same
    functions the full-corpus pipeline uses (mhealth.metrics), so a single
    audited app's numbers are directly comparable to the paper's published
    corpus-level statistics (Section 7.1). Requires network traffic to have
    been captured; returns an empty dict otherwise rather than a misleading
    zero/NaN row.
    """
    if not record.get("traffic_captured"):
        return {}

    from mhealth.metrics import compute_adii, compute_dgi, compute_pclr

    return {
        "ADII": compute_adii(record),
        "DGI": compute_dgi(record),
        "PCLR": compute_pclr(record),
    }
