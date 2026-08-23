"""
The four privacy metrics: ADII, DGI, PCLR, AS.

"""

from __future__ import annotations

from itertools import combinations

import numpy as np
import pandas as pd

from .parsing import (merge_maps, normalize_map, parse_frequency_map,
                      parse_token_set)
from .taxonomy import (SENSITIVE_CATEGORIES, canonicalize_declared,
                       canonicalize_observed, weight_of)

STATES = ("pre", "post")


# ---------------------------------------------------------------- ADII -----
def compute_adii(row) -> float:
    """Sensitivity-weighted volume of observed transmission.

        ADII(a,g) = sum_s sum_{i in T} w_i * f_i, with w_i = 1 for any token
        i that does not map into the canonical taxonomy T (Appendix D).

    """
    total = 0.0
    for state in STATES:
        freqs = parse_frequency_map(row.get(f"{state}_type_frequencies"))
        for token, count in freqs.items():
            cats = canonicalize_observed([token], drop_infrastructure=False)
            weight = max((weight_of(c) for c in cats), default=1)
            total += weight * count
    return total


# ----------------------------------------------------------------- DGI -----
def compute_dgi(row) -> float:
    """Fraction of observed canonical categories that are undeclared.

        DGI(a,g) = |D_obs \\ D_decl| / |D_obs|

    """
    observed = set()
    for state in STATES:
        observed |= parse_token_set(row.get(f"{state}_observed_data_types"))
    obs = canonicalize_observed(observed, drop_infrastructure=True)
    if not obs:
        return np.nan

    declared = parse_token_set(row.get("data_safety_data_collected")) | \
        parse_token_set(row.get("data_safety_data_shared"))
    decl = canonicalize_declared(declared)

    return len(obs - decl) / len(obs)


# ---------------------------------------------------------------- PCLR -----
def compute_pclr(row) -> float:
    """Share of sensitive transmission occurring before user action.

        PCLR(a,g) = sigma_pre / (sigma_pre + sigma_post)

    """
    sigma = {}
    for state in STATES:
        freqs = parse_frequency_map(row.get(f"{state}_type_frequencies"))
        total = 0.0
        for token, count in freqs.items():
            for cat in canonicalize_observed([token], drop_infrastructure=True):
                if cat in SENSITIVE_CATEGORIES:
                    total += weight_of(cat) * count
        sigma[state] = total

    denominator = sigma["pre"] + sigma["post"]
    if denominator <= 0:
        return np.nan
    return sigma["pre"] / denominator


# ------------------------------------------------------------------ AS -----
def build_country_feature(country_rows, normalize=False) -> dict:
    """Behavioural feature vector for one app in one country.

    Combines per-state transmission composition (raw frequency counts) with
    binary presence flags for observed data types, matching the formula used
    to produce the paper's published AS figures (Section 7.1: median 0.374,
    mean 0.377).

    """
    feature = {}
    for state in STATES:
        maps = [parse_frequency_map(v)
                for v in country_rows.get(f"{state}_type_frequencies", [])]
        merged = merge_maps(*maps)
        if normalize:
            merged = normalize_map(merged)
        for token, value in merged.items():
            feature[f"{state}_freq::{token}"] = value

        types = set()
        for v in country_rows.get(f"{state}_observed_data_types", []):
            types |= parse_token_set(v)
        flag = (1.0 / max(len(types), 1)) if normalize else 1.0
        for t in types:
            feature[f"{state}_type::{t}"] = flag
    return feature


def bray_curtis(a: dict, b: dict) -> float:
    """Normalized L1 distance in [0, 1] over the union of keys."""
    keys = set(a) | set(b)
    if not keys:
        return 0.0
    num = sum(abs(a.get(k, 0.0) - b.get(k, 0.0)) for k in keys)
    den = sum(abs(a.get(k, 0.0)) + abs(b.get(k, 0.0)) for k in keys)
    return 0.0 if den == 0 else num / den


def compute_as(app_df, min_countries=3, normalize=False) -> float:
    """Mean pairwise behavioural divergence across countries.

        AS(a) = C(|G_a|,2)^-1 * sum_{g<g'} d(F_a^g, F_a^g')

    """
    if "country" not in app_df.columns:
        return np.nan
    app_df = app_df.dropna(subset=["country"])
    if app_df["country"].nunique() < min_countries:
        return np.nan

    features = {
        country: build_country_feature(group, normalize=normalize)
        for country, group in app_df.groupby("country", dropna=True)
    }
    countries = sorted(features)
    distances = [bray_curtis(features[a], features[b])
                 for a, b in combinations(countries, 2)]
    return float(np.mean(distances)) if distances else np.nan


# ------------------------------------------------------- health exposure ---
def pre_consent_health_types(row) -> set:
    """Health/biometric canonical categories transmitted before consent.
    """
    observed = parse_token_set(row.get("pre_observed_data_types"))
    cats = canonicalize_observed(observed, drop_infrastructure=True)
    return {c for c in cats if c in {"health", "biometric"}}
