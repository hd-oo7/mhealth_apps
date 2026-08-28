# analysis_scripts

Code behind the paper's Results (Sec. 6) and Discussion (Sec. 7): per-topic
notebooks.

## Setup

```bash
cd analysis_scripts
pip install -r requirements.txt
```

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