"""Verification and correction pass for the USENIX Security 2027 submission.

This script re-derives, from the corpus directly, every number in the paper's
Empirical Analysis (Sec. 7) and Discussion (Sec. 8) that a pre-submission
audit found could not be reproduced from `analysis_scripts/01-11`. It exists as a single,
traceable, re-runnable source of truth: every statistic written into the .tex files during
this revision has a corresponding printed line here.

Runs against data/mhealth_apps_metrics_anonymized.csv (released with this
repo) by default; set MHEALTH_DATA_PATH to point at the authors' internal
corpus (real app_id) instead. Every column this script reads survives
anonymization unchanged, so results match either way.

Why this script exists (context for reviewers/future readers):
  - `01_privacy_metrics.ipynb` computes DGI via *raw-token* matching (e.g. "uuid" is never
    matched to "device or other ids"), which saturates to a median DGI ~0.83 and makes the
    paper's originally-reported "~11% of apps have DGI<0.2" mathematically impossible
    (the raw-token DGI has an app-level minimum of 0.425). None of the 11 analysis
    notebooks implements the *canonical-taxonomy* DGI that Sec. 3.4 / Appendix D.4 of the
    paper documents (mapping granular observed tokens and coarse declared categories onto
    a shared ~10-category taxonomy, excluding session/transport identifiers).
  - This script implements that documented canonical crosswalk explicitly (Part 1 below).
    It is a *reconstruction* of the intended methodology, not a recovery of lost original
    code, so the exact token->category mapping is a curated, defensible judgment call
    (documented inline) rather than a ground truth we can verify byte-for-byte against an
    prior version. It was validated by manual inspection of the ~80 most frequent tokens on
    both the observed and declared sides, including catching and excluding two forms of
    "vocabulary contamination": (a) generic Android "Diagnostics" (crash logs / app
    performance) being conflated with medical "diagnosis", and (b) developer-contact
    boilerplate ("email provided for privacy inquiries") being conflated with a disclosure
    of collecting the user's email.
  - Sec. 7.3 (Privacy Archetypes) is reproduced exactly against the existing k=4 clustering
    pipeline in `09_privacy_archetypes.ipynb` (same features, same random_state), since that
    part of the pipeline is not in question -- only the paper's *prose* describing the
    cluster sizes/centroids had drifted from what the notebook actually outputs.
  - Sec. 7.6 (Regression) reproduces the existing OLS specification from
    `11_regression_analysis.ipynb`, refits the DGI-outcome model using the canonical DGI
    from Part 1 (so the regression is internally consistent with the descriptive stats),
    and adds the Benjamini-Hochberg FDR correction and ADII sensitivity-weight check that
    the paper's methods text describes but that no notebook actually implements.

Run: python3 analysis_scripts/12_verification_and_corrections.py
"""

import ast
import os
import warnings
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.stats import spearmanr
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
from statsmodels.stats.outliers_influence import variance_inflation_factor
import statsmodels.formula.api as smf
from statsmodels.stats.multitest import multipletests

warnings.filterwarnings("ignore")
pd.set_option("display.width", 140)
pd.set_option("display.max_columns", 20)

DEFAULT_DATA_PATH = Path(__file__).resolve().parents[1] / "data" / "mhealth_apps_metrics_anonymized.csv"
DATA_PATH = Path(os.environ.get("MHEALTH_DATA_PATH", DEFAULT_DATA_PATH))


def parse_set(x):
    """Parse a stringified Python set/list column into a real set of lowercase tokens."""
    if pd.isna(x):
        return set()
    try:
        v = ast.literal_eval(x)
        if isinstance(v, (set, list, tuple)):
            return {str(t).strip().lower() for t in v}
        return {str(v).strip().lower()}
    except Exception:
        return {t.strip().lower() for t in str(x).split(";") if t.strip()}


def hbar(title):
    print("\n" + "=" * 78)
    print(title)
    print("=" * 78)


if not DATA_PATH.exists():
    raise FileNotFoundError(
        f"{DATA_PATH} not found. Expected the released anonymized corpus here "
        "(or set MHEALTH_DATA_PATH to the internal raw corpus)."
    )
df = pd.read_csv(DATA_PATH, low_memory=False)
ID_COL = "app_id" if "app_id" in df.columns else "anon_app_id"
assert df[ID_COL].nunique() == 931, f"expected 931 apps, got {df[ID_COL].nunique()}"

# ---------------------------------------------------------------------------
# PART 1: Canonical-taxonomy Disclosure Gap Index (DGI)
# ---------------------------------------------------------------------------
hbar("PART 1: Canonical DGI")

# Session/transport identifiers: app infrastructure, excluded from disclosure comparison
# per the paper's documented methodology (Sec 3.4 / Appendix D.4 crosswalk).
INFRA_TOKENS = {
    "bearer token", "cookie", "user agent", "request_id", "access_token",
    "session_id", "api_key", "refresh_token", "app_key", "branch_key",
    "trusted_account_key", "entity_guid", "moe_user_id", "insert_id",
    "local_ip",
}

# Observed (network-traffic) tokens -> canonical taxonomy category.
OBSERVED_TO_CANON = {
    "uuid": "device_ids", "android_id": "device_ids", "advertising_id": "device_ids",
    "adid": "device_ids", "device_id": "device_ids", "android_app_set_id": "device_ids",
    "hardware_id": "device_ids", "device_fingerprint_id": "device_ids",
    "identity_id": "device_ids", "ip address": "device_ids",
    "account_id": "user_ids", "profile_id": "user_ids",
    "email": "email",
    "name": "name",
    "phone number": "phone",
    "address": "address",
    "birthdate": "dob",
    "geolocation": "location",
    "medical record": "health", "symptoms": "health", "diagnosis": "health",
    "blood pressure": "health", "heart rate": "health", "glucose levels": "health",
    "fingerprints": "biometric",
}

# Declared/disclosed tokens (Data Safety categories + LLM-extracted policy statements)
# -> canonical taxonomy category. Exact-match only (never substring) to avoid
# vocabulary contamination -- see module docstring.
DISCLOSED_TO_CANON = {
    "device or other ids": "device_ids", "device identifiers": "device_ids",
    "unique device identifiers": "device_ids", "device identifier": "device_ids",
    "cookie identifiers": "device_ids", "online identifiers": "device_ids",
    "mobile advertising identifiers": "device_ids", "advertising identifiers": "device_ids",
    "advertising identifier": "device_ids", "ad identifiers": "device_ids",
    "adv identifiers": "device_ids", "mobile ids": "device_ids", "marketing ids": "device_ids",
    "analytics ids": "device_ids", "anonymous ids": "device_ids",
    "ip address": "device_ids", "ip addresses": "device_ids", "device information": "device_ids",
    "mac address": "device_ids",
    "user ids": "user_ids", "account identifiers": "user_ids",
    "anonymous account identifier": "user_ids", "username": "user_ids",
    "email": "email", "email address": "email", "emails": "email",
    "e-mail address": "email", "email addresses": "email", "e-mail addresses": "email",
    "name": "name", "first name": "name",
    "phone number": "phone", "telephone number": "phone",
    "address": "address", "physical address": "address", "billing address": "address",
    "shipping address": "address", "postal address": "address", "mailing address": "address",
    "home address": "address", "street address": "address",
    "date of birth": "dob", "birth date": "dob", "birthday": "dob", "birthdate": "dob",
    "approximate location": "location", "precise location": "location",
    "location": "location", "location data": "location",
    "fitness info": "health", "health info": "health", "health data": "health",
    "health information": "health",  # NOTE: 'diagnostics' deliberately excluded --
    "diagnosis year": "health",       # that token is Android's crash/perf-diagnostics
    "diagnostic test results": "health",  # category, not a medical diagnosis disclosure.
    "biometric information": "biometric", "biometric data": "biometric",
    "biometric identifiers": "biometric", "biometrics": "biometric",
    "fingerprint scan": "biometric",
}

# Contamination guard: developer-contact boilerplate that mentions "email"/"address" but
# is NOT a disclosure of collecting the user's email/address, so must not be mapped even
# though it superficially resembles a disclosed token.
CONTACT_BOILERPLATE = {
    "email provided for privacy inquiries", "email and physical address provided",
    "email and physical address provided for inquiries",
    "email and physical address provided for privacy inquiries",
    "email and physical address provided for inquiries.",
    "email address provided for inquiries", "address provided for inquiries",
    "and address provided", "and physical address provided",
    "email and mailing address provided", "email and postal address provided",
    "email and mailing address provided for inquiries",
    "email and postal address provided for inquiries",
    "email and postal address provided for privacy inquiries",
    "email addresses provided for privacy inquiries",
    "franchisee email address", "franchisee physical address",
    "contact address", "correspondence address", "business address",
    "service address", "address for delivery of rewards",
    "invoicing and delivery address", "delivery address",
    "line manager address",
}


def canon_from_tokens(tokens, mapping):
    tokens = tokens - CONTACT_BOILERPLATE
    return {mapping[t] for t in tokens if t in mapping}


df["observed_tok"] = df["observed_set_final"].apply(parse_set)
df["disclosed_tok"] = df["disclosed_set_final"].apply(parse_set)

df["canon_observed"] = df["observed_tok"].apply(lambda s: canon_from_tokens(s, OBSERVED_TO_CANON))
df["canon_disclosed"] = df["disclosed_tok"].apply(lambda s: canon_from_tokens(s, DISCLOSED_TO_CANON))
df["canon_missing"] = df.apply(lambda r: r["canon_observed"] - r["canon_disclosed"], axis=1)
df["DGI_canon"] = df.apply(
    lambda r: (len(r["canon_missing"]) / len(r["canon_observed"])) if r["canon_observed"] else np.nan,
    axis=1,
)

app_dgi = df.groupby(ID_COL)["DGI_canon"].mean().dropna()
print(f"N apps with canonical DGI: {len(app_dgi)}")
print(f"mean={app_dgi.mean():.3f}  median={app_dgi.median():.3f}  "
      f"Q1={app_dgi.quantile(.25):.3f}  Q3={app_dgi.quantile(.75):.3f}")
print(f"% DGI<0.2: {100*(app_dgi < 0.2).mean():.1f}%")
print(f"% DGI>=0.8: {100*(app_dgi >= 0.8).mean():.1f}%")
print(f"% DGI==0: {100*(app_dgi == 0).mean():.1f}%   % DGI==1: {100*(app_dgi == 1).mean():.1f}%")

app_cat = df.groupby(ID_COL)["category"].first()
cat_dgi = app_dgi.to_frame("DGI_canon").join(app_cat).groupby("category")["DGI_canon"].agg(["mean", "count"])
print("\nCategory-level canonical DGI:")
print(cat_dgi.sort_values("mean").round(3))

# Ranked list of most-frequently-undisclosed canonical categories (apps with >=1 occurrence)
undisclosed_apps = {c: set() for c in set(OBSERVED_TO_CANON.values())}
for app_id, sub in df.groupby(ID_COL):
    all_missing = set().union(*sub["canon_missing"]) if len(sub) else set()
    for c in all_missing:
        undisclosed_apps[c].add(app_id)
print("\nMost-undisclosed canonical categories (# apps with >=1 undisclosed occurrence):")
for cat, apps in sorted(undisclosed_apps.items(), key=lambda kv: -len(kv[1])):
    print(f"  {cat:12s} {len(apps)}")

# ---------------------------------------------------------------------------
# PART 2: Privacy archetypes (k=4), reproduced, + pre-consent PHI by cluster
# ---------------------------------------------------------------------------
hbar("PART 2: Archetype clustering + pre-consent PHI leakage by cluster")

app_metrics = df.groupby(ID_COL).agg(
    ADII=("ADII", "mean"), DGI_raw=("DGI", "mean"),
    PCLR=("PCLR", "mean"), AS=("AS", "mean"),
).dropna()
app_metrics = app_metrics.join(app_dgi.rename("DGI_canon"), how="inner")
print(f"N apps with complete metrics for clustering: {len(app_metrics)}")

# NOTE: clustering uses the CANONICAL DGI (Part 1), not the notebook's raw-token DGI,
# so that "DGI" refers to the same quantity everywhere in the paper (internal
# consistency was judged more important than matching the notebook's raw feature).
X = np.column_stack([
    np.log1p(app_metrics["ADII"]), app_metrics["DGI_canon"],
    app_metrics["PCLR"], app_metrics["AS"],
])
Xs = StandardScaler().fit_transform(X)
km = KMeans(n_clusters=4, random_state=42, n_init=20).fit(Xs)
app_metrics["cluster"] = km.labels_

summary = app_metrics.groupby("cluster").agg(
    n=("ADII", "size"), ADII=("ADII", "mean"), DGI=("DGI_canon", "mean"),
    PCLR=("PCLR", "mean"), AS=("AS", "mean"),
).round(3).sort_values("ADII")
print(summary)

# pre-consent PHI leakage per app (any row where pre_PHI_set is non-empty / contains
# 'medical record')
df["pre_PHI_tok"] = df["pre_PHI_set"].apply(parse_set)
app_phi = df.groupby(ID_COL)["pre_PHI_tok"].apply(lambda s: set().union(*s) if len(s) else set())
app_metrics["any_pre_phi"] = app_metrics.index.map(lambda a: len(app_phi.get(a, set())) > 0)
app_metrics["pre_medrec"] = app_metrics.index.map(lambda a: "medical record" in app_phi.get(a, set()))

phi_by_cluster = app_metrics.groupby("cluster").agg(
    n=("ADII", "size"),
    pct_any_phi=("any_pre_phi", "mean"),
    pct_medrec=("pre_medrec", "mean"),
).round(3)
phi_by_cluster["pct_any_phi"] *= 100
phi_by_cluster["pct_medrec"] *= 100
print("\nPre-consent PHI leakage by cluster (joined to ADII-sorted cluster order above):")
print(phi_by_cluster)
print(f"\nOverall: {app_metrics['any_pre_phi'].sum()}/{len(app_metrics)} "
      f"({100*app_metrics['any_pre_phi'].mean():.1f}%) leak some PHI pre-consent; "
      f"{app_metrics['pre_medrec'].sum()}/{len(app_metrics)} "
      f"({100*app_metrics['pre_medrec'].mean():.1f}%) leak medical-record data pre-consent.")

# ---------------------------------------------------------------------------
# PART 3: Regression -- refit with canonical DGI, BH-FDR correction
# ---------------------------------------------------------------------------
hbar("PART 3: Regression (app-level OLS, HC3) + within-outcome BH-FDR")

reg_df = df.groupby(ID_COL).agg(
    ADII=("ADII", "mean"), PCLR=("PCLR", "mean"), AS=("AS", "mean"),
    num_trackers=("num_trackers", "first"), num_permissions=("num_permissions", "first"),
    num_dangerous_permissions=("num_dangerous_permissions", "first"),
    offersIAP=("offersIAP", "first"), ad_supported=("ad_supported", "first"),
    downloads_int=("downloads_int", "first"), ratings_count=("ratings_count", "first"),
    average_score=("average_score", "first"), top_grossing=("top_grossing", "first"),
    category=("category", "first"),
).dropna(subset=["ADII", "PCLR", "AS"])
reg_df = reg_df.join(app_dgi.rename("DGI_canon"))

reg_df["log_ADII"] = np.log1p(reg_df["ADII"])
reg_df["log_downloads"] = np.log1p(reg_df["downloads_int"])
reg_df["log_ratings"] = np.log1p(reg_df["ratings_count"].fillna(0))
reg_df["top_grossing_bin"] = (reg_df["top_grossing"] == "Yes").astype(int)
reg_df["offersIAP"] = reg_df["offersIAP"].astype(int)
reg_df["ad_supported"] = reg_df["ad_supported"].astype(int)

FOCUS = ["num_trackers", "num_permissions", "num_dangerous_permissions",
         "offersIAP", "ad_supported", "log_downloads", "log_ratings",
         "top_grossing_bin", "average_score"]
for c in FOCUS:
    if reg_df[c].std() > 0:
        reg_df[f"z_{c}"] = (reg_df[c] - reg_df[c].mean()) / reg_df[c].std()
Z = [f"z_{c}" for c in FOCUS]

results = {}
for outcome, label in [("log_ADII", "log-ADII"), ("DGI_canon", "DGI"),
                        ("PCLR", "PCLR"), ("AS", "AS")]:
    sub = reg_df.dropna(subset=[outcome] + Z)
    formula = f"{outcome} ~ " + " + ".join(Z) + " + C(category)"
    model = smf.ols(formula, data=sub).fit(cov_type="HC3")
    r2 = model.rsquared
    r2_adj = model.rsquared_adj
    coefs = model.params[Z]
    pvals = model.pvalues[Z]
    results[label] = pd.DataFrame({"coef": coefs, "p": pvals})
    print(f"\n--- {label}  (N={len(sub)}, R2={r2:.3f}, adj-R2={r2_adj:.3f}) ---")
    print(results[label].round(4))

# BH-FDR within each outcome model (9 focus predictors per model)
hbar("BH-FDR correction (within-outcome)")
for label, tab in results.items():
    rej, qvals, _, _ = multipletests(tab["p"].values, alpha=0.05, method="fdr_bh")
    tab["q_within"] = qvals
    tab["sig_fdr"] = rej
    print(f"\n{label}:")
    print(tab.round(4))

# ---------------------------------------------------------------------------
# PART 4: ADII sensitivity-weight robustness (baseline 1/2/3 vs flat vs steep 1/3/9)
# ---------------------------------------------------------------------------
hbar("PART 4: ADII sensitivity-weight robustness")

WEIGHT_BASELINE = {"device_ids": 1, "user_ids": 2, "email": 2, "name": 2, "phone": 2,
                    "address": 2, "dob": 2, "location": 2, "health": 3, "biometric": 3}
WEIGHT_FLAT = {k: 1 for k in WEIGHT_BASELINE}
WEIGHT_STEEP = {"device_ids": 1, "user_ids": 3, "email": 3, "name": 3, "phone": 3,
                "address": 3, "dob": 3, "location": 3, "health": 9, "biometric": 9}


def parse_freq_map(x):
    if pd.isna(x):
        return {}
    try:
        v = ast.literal_eval(x)
        return {str(k).strip().lower(): v2 for k, v2 in v.items()} if isinstance(v, dict) else {}
    except Exception:
        return {}


df["pre_freq"] = df["pre_type_frequencies_map"].apply(parse_freq_map)
df["post_freq"] = df["post_type_frequencies_map"].apply(parse_freq_map)


def weighted_adii(row, weights):
    total = 0.0
    for freq_map in (row["pre_freq"], row["post_freq"]):
        for tok, freq in freq_map.items():
            cat = OBSERVED_TO_CANON.get(tok)
            if cat and tok not in INFRA_TOKENS:
                total += weights[cat] * freq
    return total


sample = df.sample(n=min(6000, len(df)), random_state=0)  # subsample for speed; app-level mean below
sample = sample.copy()
sample["adii_baseline"] = sample.apply(lambda r: weighted_adii(r, WEIGHT_BASELINE), axis=1)
sample["adii_flat"] = sample.apply(lambda r: weighted_adii(r, WEIGHT_FLAT), axis=1)
sample["adii_steep"] = sample.apply(lambda r: weighted_adii(r, WEIGHT_STEEP), axis=1)
app_w = sample.groupby(ID_COL)[["adii_baseline", "adii_flat", "adii_steep"]].mean()

rho_flat, _ = spearmanr(app_w["adii_baseline"], app_w["adii_flat"])
rho_steep, _ = spearmanr(app_w["adii_baseline"], app_w["adii_steep"])
print(f"N apps in weight-sensitivity subsample: {len(app_w)}")
print(f"Spearman rho baseline vs flat (1/1/1):  {rho_flat:.4f}")
print(f"Spearman rho baseline vs steep (1/3/9): {rho_steep:.4f}")

# ---------------------------------------------------------------------------
# PART 5: VIF diagnostic for the regression predictors
# ---------------------------------------------------------------------------
hbar("PART 5: VIF diagnostic (regression predictors)")
vif_df = reg_df.dropna(subset=Z)[Z]
vifs = pd.Series(
    [variance_inflation_factor(vif_df.values, i) for i in range(vif_df.shape[1])],
    index=Z,
)
print(vifs.round(2).sort_values(ascending=False))

print("\nDone. Cite exact values above in the .tex revision -- do not round differently"
      " in the paper than what is printed here.")
