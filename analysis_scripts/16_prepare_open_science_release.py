"""Build the anonymized, app-country-state-level metrics dataset released with
this paper's artifacts (Open Science appendix, item 2): every row of
data/mhealth_apps_metrics.csv that underlies the paper's tables and figures,
keyed by the same sequential anonymized identifier used in
data/anonymized_app_list.csv (analysis_scripts/15), with the real app_id and
all columns that identify or fingerprint a specific application removed.

Why columns are dropped (not just app_id):
  - app_name, developer_name, developer_id, developer_email,
    developer_website, privacy_policy_link, privacy_policy_file: direct
    identifiers, excluded per the Ethics appendix's no-re-identification
    commitment (same rule analysis_scripts/15 already applies).
  - pre_domains, post_domains, domains, pre_domains_set, post_domains_set:
    a first-party API domain (e.g. "api.<appname>.com") can fingerprint a
    specific app even under an anonymized ID, and domains are not among the
    data types the paper's Open Science section lists as released.
  - pre_type_examples, post_type_examples: NOT normalized data -- these hold
    literal captured values from network traffic (real IP addresses, session
    tokens, UUIDs, and in this corpus, residual synthetic-profile credentials
    from before the profile was redacted -- see code/wireguard_vpn.py). This
    is exactly the "raw network traffic captures" category the Ethics
    appendix says is withheld; every other column already expresses the same
    information as normalized type/category sets.
  - privacy_policy_contact_provided_detail(_set): the LLM policy-extraction
    pipeline occasionally captured the developer's verbatim contact email
    here (e.g. "info@neuronation.de"), which identifies the app directly.
    The coarser privacy_policy_contact_provided (whether *a* contact method
    was disclosed at all) carries no such risk and is retained.

Everything else (metrics, permissions/trackers, Data Safety and privacy-policy
extractions, Play Store metadata used by the regression) is retained at full
precision, matching the paper's Open Science commitment to withhold nothing
required to independently verify its quantitative claims.

This is the anonymization step itself, so it needs the authors' internal raw
corpus (real app_id), which is not released. Running it regenerates the
already-shipped data/mhealth_apps_metrics_anonymized.csv.

Run: python3 analysis_scripts/16_prepare_open_science_release.py
"""

import ast
import re
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = ROOT / "data" / "mhealth_apps_metrics.csv"          # internal corpus, not released
OUT_PATH = ROOT / "data" / "mhealth_apps_metrics_anonymized.csv"  # released output

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
BEARER_RE = re.compile(r"ya29\.[A-Za-z0-9_-]{20,}")

DROP_COLUMNS = [
    # direct identifiers
    "app_name", "developer_name", "developer_id", "developer_email",
    "developer_website", "privacy_policy_link", "privacy_policy_file",
    # app-fingerprinting risk, not among the paper's stated released data types
    "pre_domains", "post_domains", "domains",
    "pre_domains_set", "post_domains_set",
    # literal captured values (raw traffic), not normalized categories
    "pre_type_examples", "post_type_examples",
    # verbatim contact email captured by the LLM extraction pipeline
    "privacy_policy_contact_provided_detail", "privacy_policy_contact_provided_detail_set",
]

# Set/list-literal columns that feed DGI and are load-bearing for
# reproducibility, so they're scrubbed token-by-token rather than dropped
# outright. The policy-extraction pipeline occasionally folded a verbatim
# contact string (e.g. "email: info@neuronation.de") into these sets as if
# it were a declared data type; only that token is dropped, not the set.
TOKEN_SET_COLUMNS = [
    "observed_set_final", "disclosed_set_final", "missing_set", "misleading_set",
    "data_safety_data_collected_set", "data_safety_data_shared_set",
]


def scrub_token_set(cell):
    """Drop any email- or bearer-token-shaped element from a stringified
    Python set/list, leaving the rest of the set intact. Returns
    (possibly-rewritten cell, whether anything was actually removed)."""
    if not isinstance(cell, str) or not cell.strip():
        return cell, False
    try:
        tokens = ast.literal_eval(cell)
    except (ValueError, SyntaxError):
        return cell, False
    if not isinstance(tokens, (set, list, tuple)):
        return cell, False
    flagged = {t for t in tokens if EMAIL_RE.search(str(t)) or BEARER_RE.search(str(t))}
    if not flagged:
        return cell, False
    kept = set(tokens) - flagged
    # Sorted explicitly rather than relying on repr(set(...)): Python's set
    # iteration order depends on per-process string hash randomization, so
    # an unsorted repr would make re-running this script non-reproducible
    # byte-for-byte even though the token content is unchanged.
    formatted = "{" + ", ".join(repr(t) for t in sorted(kept, key=str)) + "}" if kept else "set()"
    return formatted, True


def main():
    if not DATA_PATH.exists():
        raise FileNotFoundError(
            f"{DATA_PATH} not found. This script regenerates the released "
            "mhealth_apps_metrics_anonymized.csv from the authors' internal "
            "raw corpus, which does not ship with this repository -- see the "
            "module docstring."
        )
    df = pd.read_csv(DATA_PATH, low_memory=False)
    assert df.app_id.nunique() == 931, f"expected 931 apps, got {df.app_id.nunique()}"

    # Same mapping as analysis_scripts/15_anonymized_app_list.py: sorted
    # unique app_id -> app_0001, app_0002, ..., so the two released files
    # cross-reference by anon_app_id.
    anon_map = {
        app_id: f"app_{i:04d}"
        for i, app_id in enumerate(sorted(df["app_id"].unique()), start=1)
    }
    df.insert(0, "anon_app_id", df["app_id"].map(anon_map))

    present = [c for c in DROP_COLUMNS if c in df.columns]
    missing = [c for c in DROP_COLUMNS if c not in df.columns]
    if missing:
        print(f"NOTE: expected-but-absent columns (already not in source): {missing}")
    df = df.drop(columns=["app_id"] + present)

    scrubbed_counts = {}
    for col in TOKEN_SET_COLUMNS:
        if col not in df.columns:
            continue
        results = df[col].apply(scrub_token_set)
        df[col] = results.apply(lambda r: r[0])
        scrubbed_counts[col] = int(results.apply(lambda r: r[1]).sum())

    # Belt-and-suspenders: fail loudly if any email-address-shaped token or
    # OAuth-bearer-token-shaped token survives in any remaining column,
    # rather than silently shipping it. Pattern-based (not a hardcoded
    # value) so it catches any credential-shaped residue, not just a
    # specific known one.
    for col in df.columns:
        if df[col].dtype != object:
            continue
        sample = df[col].astype(str)
        for pattern in (EMAIL_RE.pattern, BEARER_RE.pattern):
            hits = sample.str.contains(pattern, regex=True, na=False)
            if hits.any():
                raise SystemExit(
                    f"REFUSING TO WRITE: {hits.sum()} credential-shaped value(s) "
                    f"found in column '{col}' (pattern: {pattern})"
                )

    df.to_csv(OUT_PATH, index=False)
    print(f"Wrote {OUT_PATH}")
    print(f"  rows: {len(df)}  apps: {df['anon_app_id'].nunique()}  columns: {len(df.columns)}")
    print(f"  dropped columns: {['app_id'] + present}")
    print(f"  token-scrubbed rows per column: {scrubbed_counts}")


if __name__ == "__main__":
    main()
