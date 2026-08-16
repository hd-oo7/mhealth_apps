"""
The four privacy metrics: ADII, DGI, PCLR, AS.

Each function documents the definition it implements and, where the original
pipeline differed, what changed and why. All four now match the equations in
the paper (Section 4).
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

    Weights are applied to the *canonical category* of a token when it has
    one, so an app is not penalised differently for a data type simply
    because the extractor happens to have many distinct token spellings for
    it. Tokens with no canonical mapping (session/transport artefacts such
    as bearer tokens, cookies, or request IDs; see taxonomy.py's
    INFRASTRUCTURE_TOKENS) still count toward ADII at the default weight of
    1 -- unlike DGI and PCLR, ADII in this module intentionally keeps that
    behavior (rather than excluding unmapped tokens entirely) to stay close
    to the formula used to produce the paper's published ADII figures
    (Section 7.1: median 604, mean ~929).

    KNOWN GAP. Applied to the full corpus, this function currently gives
    mean ~802 / median ~524 -- closer to the published figures than the
    "exclude unmapped tokens" alternative (mean ~767) but not an exact
    match. The pre-existing `ADII` column the paper's numbers were computed
    from was produced by an earlier pipeline stage whose exact source is not
    present in this repository, so the residual gap (one plausible
    contributor: `ip address` may have been weighted as `location` (2)
    rather than `device_ids` (1) upstream, which alone would close roughly
    half the gap) could not be fully reverse-engineered. Documented here
    rather than silently claiming exact parity; see the paper's consistency
    report for the full investigation.
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

    CHANGED FROM ORIGINAL. The previous implementation differenced raw token
    strings against raw disclosure labels, so `uuid` never matched
    `device or other ids` and the metric saturated (mean 0.826, median 0.829,
    56.9% of apps >= 0.8). It measured vocabulary mismatch, not
    non-disclosure. Both sides are now projected onto the canonical taxonomy
    first, and session/transport tokens are excluded from the observed side.

    Returns NaN when nothing mappable was observed, so that apps we could not
    characterise are dropped rather than scored 0.
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

    where sigma_s is sensitivity-WEIGHTED transmission of sensitive categories.

    CHANGED FROM ORIGINAL. The previous implementation summed raw instance
    counts over a binary "sensitive" filter (weight >= 2), giving a health
    reading the same influence as an email address. The paper's equation
    specifies weighting; this now matches it. The practical effect is to
    increase the weight of health data in the ratio, which is the behaviour the
    metric is meant to capture.

    Returns NaN when no sensitive transmission was observed in either state
    (an app with no sensitive traffic has no meaningful leakage ratio).
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

    An alternative formulation (``normalize=True``: frequencies scaled to
    sum to 1 per state, presence flags scaled by 1/|types| instead of a flat
    1.0) was evaluated and would decouple the resulting distance from raw
    traffic volume, which the current, published formula does not do -- see
    the paper's Open Science appendix / consistency report for the analysis
    and why it was not adopted for this revision. ``normalize`` is kept as a
    parameter (default off) so that comparison remains available without
    re-deriving the published metric.
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

    Averaging over pairs (rather than summing) keeps AS comparable across apps
    observed in different numbers of countries.

    Returns NaN below ``min_countries``; the paper requires at least 3.
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

    Backs the paper's headline finding. Kept separate from PCLR because a
    ratio cannot distinguish pre-consent telemetry from pre-consent PHI.
    """
    observed = parse_token_set(row.get("pre_observed_data_types"))
    cats = canonicalize_observed(observed, drop_infrastructure=True)
    return {c for c in cats if c in {"health", "biometric"}}
