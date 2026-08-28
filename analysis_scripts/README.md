# analysis_scripts

Code behind the paper's Results (Sec. 6) and Discussion (Sec. 7): per-topic
notebooks, the post-submission accuracy-correction pass, and the open-science
release tooling that produced `data/`.

## Setup

```bash
cd analysis_scripts
pip install -r requirements.txt
```

Pinned to the versions the numbers below were last verified against; see
`requirements.txt` for why (KMeans and the OLS/BH-FDR results can shift
slightly across major library versions).

## Two tiers of scripts, two data dependencies

**01-11 (notebooks): the original per-topic analysis pipeline.** `01_privacy_metrics.ipynb`
builds the canonical `mhealth_apps_metrics.csv` from the authors' internal,
pre-release corpus (`mhealth_apps_filled.csv`, `traffic_results_detailed.csv`,
`mhealth_apps_traffic.csv` — raw network-traffic and Play Store data, not
released); `02`-`11` each consume that file for one section's statistics or
figures. None of these internal intermediate files ship with this repository
(see the Ethics appendix's no-re-identification commitment), so 01-11 cannot
be re-run end-to-end from this repo alone. They're included so the full
methodology is auditable, not as a standalone reproduction path.

**12-16 (scripts): the post-submission accuracy-correction / open-science
pass**, added after a pre-submission audit found the notebooks' raw-token DGI
didn't match the paper's documented canonical-taxonomy methodology (see
`12_verification_and_corrections.py`'s docstring) and that no artifact
listed the studied apps (reviewer #254A). `12`, `13`, and `14` run directly
against **`data/mhealth_apps_metrics_anonymized.csv`, which is released with
this repo**, by default -- every column they read is unchanged by
anonymization, so the numbers they print reproduce the paper's published
results from the public release alone. `15` and `16` are the anonymization
step itself, so they need the internal raw corpus and just regenerate the
already-shipped `data/anonymized_app_list.csv` and
`data/mhealth_apps_metrics_anonymized.csv`; they're included to show how
those two released files were produced.

Scripts that accept either corpus read `MHEALTH_DATA_PATH` from the
environment (default: the released anonymized file) and detect the app-id
column at runtime (`app_id` on the internal corpus, `anon_app_id` on the
release).

## What each script produces, and where it lands in the paper

| Script | Produces | Paper section |
|---|---|---|
| `01_privacy_metrics.ipynb` | `data/mhealth_apps_metrics.csv` (internal), ADII/DGI/PCLR/AS | Sec. 4 (metric definitions), Sec. 6.1 |
| `02_app_statistics.ipynb` | Corpus statistics (apps, downloads, categories, monetization) | Sec. 3.1 (App Selection), Appendix C |
| `03_data_safety.ipynb` | Data Safety disclosure summary | Sec. 3.2 (Evidence Sources), Table 2 |
| `04_privacy_policy.ipynb` | Privacy policy coverage / no-policy cohorts | Sec. 3.2 (Evidence Sources) |
| `05_permissions_&_trackers.ipynb` | Permissions/trackers by region, country, category | Sec. 3.2, Sec. 6.3, Figure 2 |
| `06_overall_distribution_of_privacy_metrics.ipynb` | Metric distribution figure | Sec. 6.1, Figure 3 |
| `07_within_app_adaptation_across_contexts.ipynb` | Cross-country adaptation analysis | Sec. 6.2, Figures 4-5 |
| `08_privacy_risk_factors.ipynb` | Invasiveness-vs-disclosure-gap scatter | Sec. 6.3, Figure 9 (Appendix D.5) |
| `09_privacy_archetypes.ipynb` | k=4 clustering + PCA (original run) | Sec. 6.4, Figure 6 |
| `10_category_level_privacy_patterns.ipynb` | Category-level z-score heatmap | Sec. 6.5, Figure 7 |
| `11_regression_analysis.ipynb` | App- and context-level OLS/GEE models (original run) | Sec. 5.1 (methodology), Sec. 6.6, Figure 8 |
