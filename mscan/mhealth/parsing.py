"""
Parsing helpers for the serialized columns in the metrics table.

Previously each of notebooks 01/06/07/08/09/10 carried its own copy of these
functions. The copies had already drifted -- notebook 07's feature builder
normalized frequency maps while notebook 01's did not, which silently produced
two incompatible Adaptation Scores from the same input. This module is now
the only implementation.
"""

from __future__ import annotations

import ast
import re

import numpy as np
import pandas as pd

NULL_STRINGS = frozenset({"", "nan", "none", "null", "no content", "n/a", "na"})


def _is_null(value) -> bool:
    if value is None:
        return True
    try:
        if pd.isna(value):
            return True
    except (TypeError, ValueError):
        pass
    return str(value).strip().lower() in NULL_STRINGS


def parse_token_set(value) -> set:
    """Parse a cell holding a list/set literal or a delimited string.

    Accepts ``"['a', 'b']"``, ``"a,b"``, ``"a;b"``, or a real list/set.
    Always returns lowercased, stripped tokens.
    """
    if _is_null(value):
        return set()
    if isinstance(value, (list, set, tuple)):
        raw = value
    else:
        text = str(value).strip()
        raw = None
        if text[:1] in "[{(" and text[-1:] in "]})":
            try:
                parsed = ast.literal_eval(text)
                if isinstance(parsed, (list, set, tuple)):
                    raw = parsed
                elif isinstance(parsed, dict):
                    raw = parsed.keys()
            except (ValueError, SyntaxError):
                raw = None
        if raw is None:
            raw = re.split(r"[;,\n]", text)
    return {str(t).strip().lower() for t in raw if str(t).strip()
            and str(t).strip().lower() not in NULL_STRINGS}


def parse_frequency_map(value) -> dict:
    """Parse ``"email:1;ip address:11;uuid:132"`` into ``{token: count}``.

    Negative counts are clamped to zero. Unparseable entries are skipped rather
    than silently coerced, so a malformed cell cannot masquerade as a zero.
    """
    if _is_null(value):
        return {}
    if isinstance(value, dict):
        items = value.items()
    else:
        items = []
        for part in str(value).split(";"):
            if ":" not in part:
                continue
            key, val = part.rsplit(":", 1)
            items.append((key, val))
    out = {}
    for key, val in items:
        key = str(key).strip().lower()
        if not key:
            continue
        try:
            out[key] = out.get(key, 0.0) + max(float(val), 0.0)
        except (TypeError, ValueError):
            continue
    return out


def normalize_map(mapping: dict) -> dict:
    """Scale a frequency map to sum to 1.

    Used only when ``build_country_feature``/``compute_as`` are called with
    ``normalize=True``: an opt-in variant that measures transmission
    *composition* rather than volume (an app simply transmitting more data in
    one country would otherwise score as adaptive even with an identical data
    mix). Not the default -- see ``mhealth.metrics.build_country_feature`` for
    why the paper's published AS figures use the unnormalized, volume-sensitive
    formula instead.
    """
    total = sum(mapping.values())
    if total <= 0:
        return {}
    return {k: v / total for k, v in mapping.items()}


def merge_maps(*maps) -> dict:
    """Sum several frequency maps key-wise."""
    merged = {}
    for mapping in maps:
        if not isinstance(mapping, dict):
            continue
        for k, v in mapping.items():
            try:
                merged[k] = merged.get(k, 0.0) + float(v)
            except (TypeError, ValueError):
                continue
    return merged


def coerce_numeric(series, fill=np.nan):
    out = pd.to_numeric(series, errors="coerce")
    return out.fillna(fill) if fill is not np.nan else out
