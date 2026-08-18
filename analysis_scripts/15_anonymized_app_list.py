"""Generate the anonymized app-level list released with this paper's artifacts
(Open Science appendix, item 5): one row per app in the 931-app corpus, keyed
by a sequential anonymized identifier rather than the real Play Store app_id,
app name, or developer identity.

Why this script exists: a pre-submission review found no artifact in the
repository actually listing the selected apps, even in anonymized form --
the Open Science section committed to releasing this, but nothing generated
it. This script closes that gap. It also serves as a directly inspectable
answer to "how many apps were successfully measured, in how many countries,
and why do some have fewer" (Appendix C.4-adjacent question raised during
review): the per-app country-coverage count and category are both in the
output.

Excluded by design (per the Ethics appendix's no-re-identification
commitment): app_id, app_name, developer_name, developer_id, developer_email,
developer_website, and the privacy_policy_link. Only aggregate/category-level
fields are retained. downloads_int is bucketed rather than reported exactly,
since an exact install count combined with category and country-coverage
could narrow a widely-installed app to a small candidate set.

This is the anonymization step itself, so -- unlike most of analysis_scripts/
-- it needs the authors' internal raw corpus (real app_id) and Play Store
metadata dump, neither of which is released (that's the whole point). It's
included for transparency into how data/anonymized_app_list.csv, which *is*
released, was produced; running it requires those two internal files and
will just regenerate that already-shipped output.

Run: python3 analysis_scripts/15_anonymized_app_list.py
"""

from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = ROOT / "data" / "mhealth_apps_metrics.csv"      # internal corpus, not released
META_PATH = ROOT / "data" / "updated_mhealth_apps.csv"      # internal Play Store metadata, not released
OUT_PATH = ROOT / "data" / "anonymized_app_list.csv"        # released output

DOWNLOAD_BUCKETS = [0, 1_000, 10_000, 100_000, 1_000_000, 10_000_000, np.inf]
DOWNLOAD_LABELS = ["<1K", "1K-10K", "10K-100K", "100K-1M", "1M-10M", "10M+"]


def main():
    for path in (DATA_PATH, META_PATH):
        if not path.exists():
            raise FileNotFoundError(
                f"{path} not found. This script regenerates the released "
                "anonymized_app_list.csv from the authors' internal raw corpus "
                "and Play Store metadata dump, neither of which ships with this "
                "repository -- see the module docstring."
            )
    df = pd.read_csv(DATA_PATH, low_memory=False)
    assert df.app_id.nunique() == 931, f"expected 931 apps, got {df.app_id.nunique()}"

    coverage = df.groupby("app_id")["country"].nunique().rename("n_countries_observed")
    metrics = df.groupby("app_id").agg(
        ADII_mean=("ADII", "mean"), DGI_mean=("DGI", "mean"),
        PCLR_mean=("PCLR", "mean"), AS_mean=("AS", "mean"),
    )

    meta = pd.read_csv(META_PATH, low_memory=False)[
        ["app_id", "categories", "downloads_int", "ad_supported", "offersIAP", "top_grossing"]
    ].drop_duplicates("app_id").set_index("app_id")

    out = coverage.to_frame().join(metrics).join(meta)
    out["downloads_bucket"] = pd.cut(
        out["downloads_int"], bins=DOWNLOAD_BUCKETS, labels=DOWNLOAD_LABELS, right=False
    )
    out = out.drop(columns=["downloads_int"])

    # Sequential anonymized identifier. Order is alphabetical by the real
    # app_id purely for a stable, reproducible ordering across re-runs; it
    # carries no information about collection order, popularity, or category.
    out = out.sort_index().reset_index(drop=True)
    out.insert(0, "anon_app_id", [f"app_{i:04d}" for i in range(1, len(out) + 1)])

    out.to_csv(OUT_PATH, index=False)
    print(f"Wrote {OUT_PATH} ({len(out)} apps)")
    print("\nCountry-coverage distribution (n_countries_observed):")
    print(out["n_countries_observed"].value_counts().sort_index())
    print(f"\napps with <3 countries observed: {(out['n_countries_observed'] < 3).sum()}")
    print("\ncategory breakdown:")
    print(out["categories"].value_counts())


if __name__ == "__main__":
    main()
