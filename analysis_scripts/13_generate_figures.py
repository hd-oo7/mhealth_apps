"""Regenerate paper figures as publication-quality vector PDFs.

Produces PDF versions (matplotlib savefig format='pdf') of the figures whose
underlying values changed during the accuracy-correction pass in
12_verification_and_corrections.py (canonical DGI, corrected archetype
clusters, corrected regression coefficients): ecdf_privacy_metrics,
privacy_archetypes_pca, category_privacy_heatmap, app_level_ols_coefficients,
adaptation_relationships_subfigures. A shared style block keeps typography,
sizing, and the categorical palette consistent across all figures (the prior
version had three different hardcoded 7-color region palettes across three
figures; this module defines one).

Palette: validated colorblind-safe categorical order from the dataviz skill's
reference palette (fixed hue order, never cycled): blue, orange, aqua, yellow,
magenta, green, violet, red.

Runs against data/mhealth_apps_metrics_anonymized.csv (released with this
repo) by default; set MHEALTH_DATA_PATH to point at the authors' internal
corpus (real app_id) instead -- the figures are identical either way, since
none of the columns used here change under anonymization.

Run: python3 analysis_scripts/13_generate_figures.py
"""

import ast
import os
import sys
import warnings
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.patches import Ellipse
from sklearn.cluster import KMeans
from sklearn.decomposition import PCA
from sklearn.metrics import silhouette_score, calinski_harabasz_score
from sklearn.preprocessing import StandardScaler
import statsmodels.formula.api as smf

warnings.filterwarnings("ignore")

ROOT = Path(__file__).resolve().parents[1]
# NOTE: this standalone release writes figures to ./figures/, unlike the
# paper's own internal copy of this script, which writes directly into the
# LaTeX build tree (usenix/sections/images/) -- a path that only exists in
# the paper's monorepo, not in this repository.
OUT_DIR = ROOT / "figures"
DEFAULT_DATA_PATH = ROOT / "data" / "mhealth_apps_metrics_anonymized.csv"
DATA_PATH = Path(os.environ.get("MHEALTH_DATA_PATH", DEFAULT_DATA_PATH))

# ---------------------------------------------------------------------------
# Shared style
# ---------------------------------------------------------------------------
CATV = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#4a3aa7", "#e34948"]
TEXT_PRIMARY = "#0b0b0b"
TEXT_SECONDARY = "#52514e"
GRID_COLOR = "#d9d8d3"

plt.rcParams.update({
    "font.size": 13,
    "font.family": "serif",
    "axes.titlesize": 14,
    "axes.labelsize": 13,
    "xtick.labelsize": 12,
    "ytick.labelsize": 12,
    "legend.fontsize": 11,
    "axes.edgecolor": TEXT_SECONDARY,
    "axes.labelcolor": TEXT_PRIMARY,
    "text.color": TEXT_PRIMARY,
    "xtick.color": TEXT_SECONDARY,
    "ytick.color": TEXT_SECONDARY,
    "axes.grid": True,
    "grid.color": GRID_COLOR,
    "grid.linewidth": 0.6,
    "grid.alpha": 0.7,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "axes.linewidth": 0.9,
    "lines.linewidth": 1.8,
    "pdf.fonttype": 42,  # embed as real text, not paths
    "figure.dpi": 150,
})


def savepdf(fig, name):
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    path = OUT_DIR / f"{name}.pdf"
    fig.savefig(path, format="pdf", bbox_inches="tight")
    print(f"wrote {path}")
    plt.close(fig)


def parse_set(x):
    if pd.isna(x):
        return set()
    try:
        v = ast.literal_eval(x)
        if isinstance(v, (set, list, tuple)):
            return {str(t).strip().lower() for t in v}
        return {str(v).strip().lower()}
    except Exception:
        return {t.strip().lower() for t in str(x).split(";") if t.strip()}


# ---------------------------------------------------------------------------
# Recompute canonical DGI (same crosswalk as script 12; only the OBSERVED/
# DISCLOSED mappings are needed here -- 12's INFRA_TOKENS set is specific
# to its ADII-weighting sensitivity check, which this script doesn't do)
# ---------------------------------------------------------------------------
OBSERVED_TO_CANON = {
    "uuid": "device_ids", "android_id": "device_ids", "advertising_id": "device_ids",
    "adid": "device_ids", "device_id": "device_ids", "android_app_set_id": "device_ids",
    "hardware_id": "device_ids", "device_fingerprint_id": "device_ids",
    "identity_id": "device_ids", "ip address": "device_ids",
    "account_id": "user_ids", "profile_id": "user_ids",
    "email": "email", "name": "name", "phone number": "phone", "address": "address",
    "birthdate": "dob", "geolocation": "location",
    "medical record": "health", "symptoms": "health", "diagnosis": "health",
    "blood pressure": "health", "heart rate": "health", "glucose levels": "health",
    "fingerprints": "biometric",
}
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
    "health information": "health", "diagnosis year": "health",
    "diagnostic test results": "health",
    "biometric information": "biometric", "biometric data": "biometric",
    "biometric identifiers": "biometric", "biometrics": "biometric",
    "fingerprint scan": "biometric",
}
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
    "invoicing and delivery address", "delivery address", "line manager address",
}


def canon_from_tokens(tokens, mapping):
    tokens = tokens - CONTACT_BOILERPLATE
    return {mapping[t] for t in tokens if t in mapping}


print("Loading data and recomputing canonical DGI...")
if not DATA_PATH.exists():
    raise FileNotFoundError(
        f"{DATA_PATH} not found. Expected the released anonymized corpus here "
        "(or set MHEALTH_DATA_PATH to the internal raw corpus)."
    )
df = pd.read_csv(DATA_PATH, low_memory=False)
ID_COL = "app_id" if "app_id" in df.columns else "anon_app_id"
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
app_cat = df.groupby(ID_COL)["category"].first()

app_metrics = df.groupby(ID_COL).agg(
    ADII=("ADII", "mean"), PCLR=("PCLR", "mean"), AS=("AS", "mean"),
).dropna()
app_metrics = app_metrics.join(app_dgi.rename("DGI"), how="inner").join(app_cat)

# ===========================================================================
# Figure 1: ECDF of privacy metrics
# ===========================================================================
print("Generating ecdf_privacy_metrics...")
fig, axes = plt.subplots(2, 2, figsize=(8.0, 6.4))
metrics = [("ADII", "ADII (data invasiveness)"), ("DGI", "DGI (disclosure gap)"),
           ("PCLR", "PCLR (pre-consent leakage)"), ("AS", "AS (adaptation score)")]
for ax, (col, label) in zip(axes.flat, metrics):
    vals = np.sort(app_metrics[col].dropna().values)
    y = np.arange(1, len(vals) + 1) / len(vals)
    ax.plot(vals, y, color=CATV[0], linewidth=2.2)
    med, mean = np.median(vals), np.mean(vals)
    ax.axvline(med, color=TEXT_SECONDARY, linestyle="--", linewidth=1.4, label=f"median={med:.2f}")
    ax.axvline(mean, color=CATV[1], linestyle=":", linewidth=1.8, label=f"mean={mean:.2f}")
    ax.set_title(label)
    ax.set_ylabel("ECDF")
    ax.legend(loc="lower right", frameon=False, fontsize=11)
    if col == "ADII":
        ax.set_xscale("log")
fig.tight_layout()
savepdf(fig, "ecdf_privacy_metrics")

# ===========================================================================
# Figure 2: Privacy archetypes (k=4 on canonical DGI) with PCA projection
# ===========================================================================
print("Generating privacy_archetypes_pca...")
X = np.column_stack([np.log1p(app_metrics["ADII"]), app_metrics["DGI"],
                      app_metrics["PCLR"], app_metrics["AS"]])
Xs = StandardScaler().fit_transform(X)
km = KMeans(n_clusters=4, random_state=42, n_init=20).fit(Xs)
app_metrics["cluster"] = km.labels_

# Map numeric cluster id -> descriptive name, by ADII ranking (matches paper text)
means = app_metrics.groupby("cluster")["ADII"].mean().sort_values()
order = list(means.index)
names = {order[0]: "Opaque, low-collection", order[1]: "Transparent, moderate-collection",
         order[2]: "High-collection, consent-weak", order[3]: "Geo-adaptive, high-collection"}
# NOTE: order[1]/order[2] assigned by ADII rank; fix by PCLR since group 2 (moderate ADII)
# is "Transparent" (lowest DGI) not necessarily 2nd-lowest ADII -- re-derive from DGI/PCLR/AS
summary = app_metrics.groupby("cluster").agg(ADII=("ADII", "mean"), DGI=("DGI", "mean"),
                                              PCLR=("PCLR", "mean"), AS=("AS", "mean"),
                                              n=("ADII", "size"))
name_map = {}
for cid, row in summary.iterrows():
    if row["ADII"] < 700 and row["DGI"] > 0.5:
        name_map[cid] = "Opaque, low-collection"
    elif row["ADII"] < 700:
        name_map[cid] = "Transparent, moderate-collection"
    elif row["PCLR"] > 0.5:
        name_map[cid] = "High-collection, consent-weak"
    else:
        name_map[cid] = "Geo-adaptive, high-collection"
app_metrics["archetype"] = app_metrics["cluster"].map(name_map)
print(summary.assign(name=[name_map[c] for c in summary.index]).round(3))

pca = PCA(n_components=2)
pcs = pca.fit_transform(Xs)
app_metrics["pc1"], app_metrics["pc2"] = pcs[:, 0], pcs[:, 1]
var = pca.explained_variance_ratio_ * 100

fig, ax = plt.subplots(figsize=(6.4, 5.2))
archetype_order = ["Transparent, moderate-collection", "Opaque, low-collection",
                    "High-collection, consent-weak", "Geo-adaptive, high-collection"]
markers = ["o", "s", "^", "D"]
for i, arch in enumerate(archetype_order):
    sub = app_metrics[app_metrics["archetype"] == arch]
    ax.scatter(sub["pc1"], sub["pc2"], s=22, alpha=0.55, color=CATV[i], marker=markers[i],
               label=f"{arch} (n={len(sub)})", edgecolors="none")
    cx, cy = sub["pc1"].mean(), sub["pc2"].mean()
    ax.scatter([cx], [cy], marker="x", s=140, color=CATV[i], linewidths=2.8, zorder=5)
    cov = np.cov(sub["pc1"], sub["pc2"])
    eigval, eigvec = np.linalg.eigh(cov)
    angle = np.degrees(np.arctan2(eigvec[1, -1], eigvec[0, -1]))
    width, height = 2 * 1.5 * np.sqrt(eigval[-1]), 2 * 1.5 * np.sqrt(eigval[0])
    ell = Ellipse((cx, cy), width, height, angle=angle, facecolor=CATV[i], alpha=0.10, edgecolor="none")
    ax.add_patch(ell)
ax.set_xlabel(f"PC1 ({var[0]:.1f}% var; high AS / low PCLR $\\rightarrow$)")
ax.set_ylabel(f"PC2 ({var[1]:.1f}% var; high ADII / low DGI $\\rightarrow$)")
ax.legend(loc="upper left", frameon=False, fontsize=10.5, markerscale=1.6, bbox_to_anchor=(-0.02, 1.26), ncol=1)
fig.tight_layout()
savepdf(fig, "privacy_archetypes_pca")

# ===========================================================================
# Figure 3: Category-level heatmap (z-scored, canonical DGI)
# ===========================================================================
print("Generating category_privacy_heatmap...")
cat_means = app_metrics.groupby("category")[["ADII", "DGI", "PCLR", "AS"]].mean()
cat_order = ["Parenting", "Health & Fitness", "Medical", "Food & Drink", "Lifestyle",
             "Education", "Productivity"]
cat_means = cat_means.reindex(cat_order)
z = (cat_means - cat_means.mean()) / cat_means.std()
z = z.clip(-2, 2)

fig, ax = plt.subplots(figsize=(6.2, 4.4))
im = ax.imshow(z.values, cmap="RdBu_r", vmin=-2, vmax=2, aspect="auto")
ax.set_xticks(range(4)); ax.set_xticklabels(["ADII", "DGI", "PCLR", "AS"])
ax.set_yticks(range(len(cat_order))); ax.set_yticklabels(cat_order)
ax.grid(False)
for i in range(z.shape[0]):
    for j in range(z.shape[1]):
        raw = cat_means.values[i, j]
        txt = f"{raw:.2f}" if j != 0 else f"{raw:.0f}"
        color = "white" if abs(z.values[i, j]) > 1 else TEXT_PRIMARY
        ax.text(j, i, txt, ha="center", va="center", fontsize=11.5, color=color)
cbar = fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
cbar.set_label("Normalized score (z-score)", fontsize=11.5)
cbar.ax.tick_params(labelsize=10.5)
fig.tight_layout()
savepdf(fig, "category_privacy_heatmap")

# ===========================================================================
# Figure 4: App-level OLS regression coefficients (4 outcomes)
# ===========================================================================
print("Generating app_level_ols_coefficients...")
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
FOCUS_LABELS = ["Trackers", "Permissions", "Dangerous perms.", "In-app purchases",
                 "Ad-supported", "Log installs", "Log rating count",
                 "Top-grossing", "Average rating"]
for c in FOCUS:
    reg_df[f"z_{c}"] = (reg_df[c] - reg_df[c].mean()) / reg_df[c].std()
Z = [f"z_{c}" for c in FOCUS]

outcomes = [("log_ADII", "log(ADII)"), ("DGI_canon", "DGI"), ("PCLR", "PCLR"), ("AS", "AS")]
fig, axes = plt.subplots(1, 4, figsize=(12.4, 3.1), sharey=True)
for ax, (outcome, label) in zip(axes, outcomes):
    sub = reg_df.dropna(subset=[outcome] + Z)
    formula = f"{outcome} ~ " + " + ".join(Z) + " + C(category)"
    model = smf.ols(formula, data=sub).fit(cov_type="HC3")
    coefs = model.params[Z]
    ci = model.conf_int().loc[Z]
    ypos = np.arange(len(Z))[::-1]
    ax.errorbar(coefs.values, ypos, xerr=[coefs.values - ci[0].values, ci[1].values - coefs.values],
                fmt="o", color=CATV[0], ecolor=TEXT_SECONDARY, capsize=3, markersize=6)
    ax.axvline(0, color=TEXT_SECONDARY, linestyle="--", linewidth=1.1)
    ax.set_title(label)
    ax.set_xlabel("Standardized coef.")
    ax.tick_params(axis="x", labelsize=11)
axes[0].set_yticks(np.arange(len(Z))[::-1])
axes[0].set_yticklabels(FOCUS_LABELS, fontsize=12)
fig.tight_layout()
savepdf(fig, "app_level_ols_coefficients")

# ===========================================================================
# Figure 5: Adaptation & privacy relationships (4-panel)
# ===========================================================================
print("Generating adaptation_relationships_subfigures...")
adapt = df.groupby(ID_COL).agg(
    ADII=("ADII", "mean"), PCLR=("PCLR", "mean"), AS=("AS", "mean"),
    downloads=("downloads_int", "first"), n_countries=("country", "nunique"),
).dropna()
adapt = adapt[adapt["n_countries"] >= 3].join(app_dgi.rename("DGI"))
as_scaled = StandardScaler().fit_transform(adapt[["AS"]])
print("AS-regime clustering: silhouette / Calinski-Harabasz by k")
for k in range(2, 7):
    labels_k = KMeans(n_clusters=k, random_state=42, n_init=10).fit_predict(as_scaled)
    print(f"  k={k}: silhouette={silhouette_score(as_scaled, labels_k):.3f}, "
          f"CH={calinski_harabasz_score(as_scaled, labels_k):.1f}")
km3 = KMeans(n_clusters=3, random_state=42, n_init=10).fit(as_scaled)
adapt["grp"] = km3.labels_
grp_means = adapt.groupby("grp")["AS"].mean().sort_values()
grp_names = {grp_means.index[0]: "Stable", grp_means.index[1]: "Partially adaptive",
             grp_means.index[2]: "Highly adaptive"}
adapt["group"] = adapt["grp"].map(grp_names)
group_colors = {"Stable": CATV[0], "Partially adaptive": CATV[1], "Highly adaptive": CATV[7]}

fig, axes = plt.subplots(2, 2, figsize=(8.6, 7.2))

# (a) normalized profiles by group
ax = axes[0, 0]
prof = adapt.groupby("group")[["ADII", "DGI", "PCLR", "AS"]].mean()
prof_order = ["Stable", "Partially adaptive", "Highly adaptive"]
prof = prof.reindex(prof_order)
profz = (prof - prof.mean()) / prof.std()
x = np.arange(4)
for i, g in enumerate(prof_order):
    ax.plot(x, profz.loc[g], marker="o", color=group_colors[g], label=g, linewidth=2.2, markersize=7)
ax.set_xticks(x); ax.set_xticklabels(["ADII", "DGI", "PCLR", "AS"])
ax.axhline(0, color=TEXT_SECONDARY, linewidth=0.8)
ax.set_ylabel("Normalized (z-score)")
ax.set_title("(a) Metric profile by adaptation group")
ax.legend(frameon=False, fontsize=10.5, loc="upper right")

# (b) AS vs DGI
ax = axes[0, 1]
ax.scatter(adapt["AS"], adapt["DGI"], s=14, alpha=0.35, color=CATV[0], edgecolors="none")
r = np.corrcoef(adapt["AS"], adapt["DGI"])[0, 1]
z = np.polyfit(adapt["AS"], adapt["DGI"], 1)
xs = np.linspace(adapt["AS"].min(), adapt["AS"].max(), 50)
ax.plot(xs, np.polyval(z, xs), color=TEXT_PRIMARY, linestyle="--", linewidth=1.8)
ax.set_xlabel("Adaptation Score (AS)"); ax.set_ylabel("DGI")
ax.set_title(f"(b) AS vs. DGI ($r$={r:.2f})")

# (c) AS vs PCLR
ax = axes[1, 0]
ax.scatter(adapt["AS"], adapt["PCLR"], s=14, alpha=0.35, color=CATV[2], edgecolors="none")
r2 = np.corrcoef(adapt["AS"], adapt["PCLR"])[0, 1]
z2 = np.polyfit(adapt["AS"], adapt["PCLR"], 1)
ax.plot(xs, np.polyval(z2, xs), color=TEXT_PRIMARY, linestyle="--", linewidth=1.8)
ax.set_xlabel("Adaptation Score (AS)"); ax.set_ylabel("PCLR")
ax.set_title(f"(c) AS vs. PCLR ($r$={r2:.2f})")

# (d) AS vs downloads
ax = axes[1, 1]
for g in prof_order:
    sub = adapt[adapt["group"] == g]
    ax.scatter(sub["downloads"] + 1, sub["AS"], s=14, alpha=0.4, color=group_colors[g], label=g, edgecolors="none")
ax.set_xscale("log")
ax.set_xlabel("Downloads (log scale)"); ax.set_ylabel("Adaptation Score (AS)")
ax.set_title("(d) AS vs. app popularity")
ax.legend(frameon=False, fontsize=10.5, loc="upper right")

fig.tight_layout()
savepdf(fig, "adaptation_relationships_subfigures")

# ===========================================================================
# Figure 6: Permissions and trackers by category (boxplot)
# ===========================================================================
print("Generating permission_and_trackers...")
pt_df = df.groupby(ID_COL).agg(
    num_permissions=("num_permissions", "first"),
    num_dangerous_permissions=("num_dangerous_permissions", "first"),
    num_trackers=("num_trackers", "first"),
    category=("category", "first"),
).dropna()
pt_cats = sorted(pt_df["category"].unique())

fig, ax = plt.subplots(figsize=(9.5, 4.6))
box_width, group_gap, n_series = 0.24, 1.0, 3
series = [("num_permissions", "Permissions", CATV[2]),
          ("num_dangerous_permissions", "Dangerous & special permissions", CATV[7]),
          ("num_trackers", "Trackers", CATV[0])]
positions_by_cat = {cat: i * group_gap for i, cat in enumerate(pt_cats)}
for j, (col, label, color) in enumerate(series):
    data = [pt_df.loc[pt_df["category"] == cat, col].values for cat in pt_cats]
    offset = (j - 1) * (box_width + 0.03)
    pos = [positions_by_cat[cat] + offset for cat in pt_cats]
    bp = ax.boxplot(data, positions=pos, widths=box_width, patch_artist=True,
                     showfliers=True, whis=(5, 95),
                     flierprops=dict(marker="o", markersize=3, markerfacecolor=color,
                                      markeredgecolor="none", alpha=0.5),
                     medianprops=dict(color=TEXT_PRIMARY, linewidth=1.6),
                     boxprops=dict(facecolor=color, alpha=0.55, edgecolor=TEXT_SECONDARY),
                     whiskerprops=dict(color=TEXT_SECONDARY), capprops=dict(color=TEXT_SECONDARY))
ax.set_xticks(list(positions_by_cat.values()))
ax.set_xticklabels(pt_cats, rotation=20, ha="right")
ax.set_ylabel("Count per app")
handles = [plt.Rectangle((0, 0), 1, 1, facecolor=c, alpha=0.55, edgecolor=TEXT_SECONDARY) for _, _, c in series]
ax.legend(handles, [s[1] for s in series], loc="upper center", bbox_to_anchor=(0.5, -0.22),
          ncol=3, frameon=False, fontsize=12)
fig.tight_layout()
savepdf(fig, "permission_and_trackers")

# ===========================================================================
# Figure 7: Within-app adaptation overview (3-panel)
# ===========================================================================
print("Generating adaptation_overview_subfigures...")
sys.path.insert(0, str(ROOT / "mscan"))
from mhealth.metrics import build_country_feature, bray_curtis  # noqa: E402

REGION_COLORS = {"North America": CATV[0], "Latin America": CATV[1], "Europe": CATV[2],
                  "Middle East": CATV[3], "Africa": CATV[4], "Asia": CATV[5], "Oceania": CATV[6]}

fig, axes = plt.subplots(1, 3, figsize=(13.5, 4.2))

# (a) AS histogram + k=3 cluster centroids
ax = axes[0]
as_vals = adapt["AS"].values
ax.hist(as_vals, bins=30, color=CATV[6], alpha=0.75, edgecolor="white")
for g in prof_order:
    centroid = adapt.loc[adapt["group"] == g, "AS"].mean()
    ax.axvline(centroid, color=group_colors[g], linewidth=2.4,
               label=f"{g} ($\\approx${centroid:.2f})")
ax.set_xlabel("Adaptation Score (AS)"); ax.set_ylabel("# apps")
ax.set_title("(a) App-level AS with cluster centroids")
ax.legend(frameon=False, fontsize=10.5, loc="upper right")

# (b) AS vs number of countries observed
ax = axes[1]
ax.scatter(adapt["n_countries"], adapt["AS"], s=16, alpha=0.35, color=CATV[0], edgecolors="none")
r_cov = np.corrcoef(adapt["n_countries"], adapt["AS"])[0, 1]
ax.text(0.04, 0.94, f"$r$={r_cov:+.2f}", transform=ax.transAxes, fontsize=12, va="top")
ax.set_xlabel("# countries observed"); ax.set_ylabel("AS")
ax.set_title("(b) AS vs. measurement coverage")

# (c) mean within-app deviation per country, colored by region
ax = axes[2]
region_by_country = df.groupby("country")["region"].first().to_dict()
country_dev = {}
app_ids_3plus = adapt.index
for app_id, group in df[df[ID_COL].isin(app_ids_3plus)].groupby(ID_COL):
    countries = sorted(group["country"].unique())
    if len(countries) < 3:
        continue
    feats = {c: build_country_feature(group[group["country"] == c]) for c in countries}
    for c in countries:
        dists = [bray_curtis(feats[c], feats[c2]) for c2 in countries if c2 != c]
        if dists:
            country_dev.setdefault(c, []).append(float(np.mean(dists)))
dev_series = pd.Series({c: np.mean(v) for c, v in country_dev.items()}).sort_values(ascending=False)
colors = [REGION_COLORS.get(region_by_country.get(c), TEXT_SECONDARY) for c in dev_series.index]
ax.bar(range(len(dev_series)), dev_series.values, color=colors)
ax.set_xticks(range(len(dev_series)))
ax.set_xticklabels([c.upper() for c in dev_series.index], rotation=90, fontsize=8.5)
ax.set_ylabel("Mean within-app deviation")
ax.set_title("(c) Adaptation by country (color = region)")
ax.set_ylim(0, dev_series.max() * 1.4)
region_handles = [plt.Rectangle((0, 0), 1, 1, facecolor=v) for v in REGION_COLORS.values()]
ax.legend(region_handles, list(REGION_COLORS.keys()), loc="upper right", frameon=False,
          fontsize=8.5, ncol=2)

fig.tight_layout()
savepdf(fig, "adaptation_overview_subfigures")

# ===========================================================================
# Figure 8: App characteristics vs. privacy metrics (3-panel)
# ===========================================================================
print("Generating combined_privacy_relationships...")
crel_df = df.groupby(ID_COL).agg(
    ADII=("ADII", "mean"), PCLR=("PCLR", "mean"),
    num_dangerous_permissions=("num_dangerous_permissions", "first"),
    num_trackers=("num_trackers", "first"), num_permissions=("num_permissions", "first"),
).dropna()
crel_df = crel_df.join(app_dgi.rename("DGI"), how="inner")

fig, axes = plt.subplots(1, 3, figsize=(13.5, 4.2))
panels = [
    ("num_dangerous_permissions", "PCLR", "# dangerous permissions", "PCLR", CATV[2], False),
    ("num_trackers", "ADII", "# trackers", "ADII", CATV[0], True),
    ("num_permissions", "DGI", "# permissions", "DGI (canonical)", CATV[7], False),
]
from scipy.stats import pearsonr
for ax, (xcol, ycol, xlabel, ylabel, color, logy) in zip(axes, panels):
    x, y = crel_df[xcol].values, crel_df[ycol].values
    ax.scatter(x, y, s=16, alpha=0.35, color=color, edgecolors="none")
    r, p = pearsonr(x, y)
    z = np.polyfit(x, np.log(y) if logy else y, 1)
    xs = np.linspace(x.min(), x.max(), 50)
    fit = np.exp(np.polyval(z, xs)) if logy else np.polyval(z, xs)
    ax.plot(xs, fit, color=TEXT_PRIMARY, linestyle="--", linewidth=1.8)
    if logy:
        ax.set_yscale("log")
    ax.set_xlabel(xlabel); ax.set_ylabel(ylabel)
    ax.set_title(f"$r$={r:+.2f}, $p$={p:.1e}")
fig.tight_layout()
savepdf(fig, "combined_privacy_relationships")

print("\nDone. Update \\includegraphics{...png} -> {...pdf} in the .tex sections for these 8 figures.")
