"""
Metric definitions shared with the mSCAN tool (../../../mscan/). Vendored
here as the minimal subset mSCAN's record.py actually imports --
compute_adii/compute_dgi/compute_pclr from metrics.py, which in turn needs
parsing.py and taxonomy.py.

Typical use:

    from mhealth.metrics import compute_adii, compute_dgi, compute_pclr
"""

from . import metrics, parsing, taxonomy  # noqa: F401

__all__ = ["metrics", "parsing", "taxonomy"]
__version__ = "2.0.0"
