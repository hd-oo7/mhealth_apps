"""Network-traffic capture and extraction for a single app, under the
manual-VPN assumption: the operator has already connected the VPN endpoint
for the target country and started the emulator before running mSCAN.

This module does not manage VPN connections or country selection itself; it
only verifies that the device's current egress IP actually resolves to the
country the operator claims (cheap insurance against a whole batch getting
silently mislabeled because someone forgot to switch the VPN), then reuses
the install / capture / uninstall automation already built and debugged in
mscan/collection/wireguard_vpn.py, and the offline log extractor in
mscan/collection/traffic_analyzer.py, rather than re-implementing either.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

_ROOT_DIR = Path(__file__).resolve().parents[2]
_COLLECTION_DIR = Path(__file__).resolve().parents[1] / "collection"
if str(_COLLECTION_DIR) not in sys.path:
    sys.path.insert(0, str(_COLLECTION_DIR))

import wireguard_vpn as wg  # noqa: E402
import traffic_analyzer as ta  # noqa: E402

# wireguard_vpn.py's NETWORK_TRAFFIC_DIR is a relative path ("../data/network_traffic")
# meant to be resolved from mscan/collection/ when run in place. Overriding the
# module-level constant here, rather than chdir'ing, makes captures land in
# this repo's own data/network_traffic/ regardless of where mscan.py itself
# is invoked from.
wg.NETWORK_TRAFFIC_DIR = str(_ROOT_DIR / "data" / "network_traffic")

# The standard Android emulator's alias for the host machine's loopback
# interface, paired with mitmdump's default listening port. Confirmed
# against this project's emulator: with the device's global proxy pointed
# here, an active mitmdump instance does intercept the device's HTTPS
# traffic (Play Services' own traffic fails on its pinned cert, as
# expected; unpinned third-party app traffic is captured normally).
PROXY_HOST_PORT = "10.0.2.2:8080"


def _set_proxy(device: str, value: str) -> None:
    """wireguard_vpn.py's install_app/run_country_session/uninstall never
    touch the device's proxy setting themselves, so this is the missing
    piece: Play Store installs fail outright if the global proxy points at
    a port nothing is listening on (confirmed empirically), so the proxy
    must be OFF during install/uninstall and ON only for the capture
    window. `value` is "host:port" to enable, or ":0" to disable.
    """
    subprocess.run(
        [wg.ADB, "-s", device, "shell", "settings", "put", "global", "http_proxy", value],
        check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


class VPNMismatchError(RuntimeError):
    """Raised when the device's actual egress country does not match the
    country the operator claims to have connected. Meant to stop a whole
    batch before it silently mislabels every app in it."""


def verify_vpn(expected_country_code: str) -> dict:
    """Check the device's current egress IP/country against what the
    operator claims. `expected_country_code` is a 2-letter ISO code (e.g.
    "de"); pass None/"us" to skip the WireGuard-interface check for
    no-VPN/US baseline runs, matching the batch pipeline's convention.
    """
    code = expected_country_code.upper()
    if code == "US":
        info = wg.get_ip_and_location()
        return {"ok": info is not None, "info": info}

    ok = wg.verify_connection(code)
    return {"ok": ok, "info": wg.get_ip_and_location()}


def connect_device():
    """Attach to the already-running emulator. Raises/exits (via
    wg.ensure_emulator_running) with a clear message if none is found."""
    import uiautomator2 as u2

    device = wg.ensure_emulator_running()
    d = u2.connect(device)
    return device, d


def capture(app_id: str, country: str, device: str, d) -> dict:
    """Install the app, capture pre- and post-consent traffic, uninstall,
    and return a status dict. Delegates entirely to wireguard_vpn's already
    -built automation (install_app / run_country_session); this function
    only adds the on-demand, single-app framing.
    """
    _set_proxy(device, ":0")  # ensure it's off for install; a stale on-state
                              # from a prior run would fail the install below
    installed, install_reason = wg.install_app(device, app_id, d)
    if not installed:
        return {"app_id": app_id, "country": country, "captured": False,
                "reason": install_reason}

    _set_proxy(device, PROXY_HOST_PORT)
    try:
        success, reason = wg.run_country_session(d, app_id, country)
    finally:
        _set_proxy(device, ":0")  # off again before uninstall / the next app's install

    wg.uninstall_all_third_party_apps(device)

    return {"app_id": app_id, "country": country, "captured": success,
            "reason": reason}


def extract(app_id: str, country: str) -> dict | None:
    """Run the offline extractor on this app's freshly captured logs and
    return one row in the same schema as context_level.csv (pre/post
    observed data types, type frequencies, contacted domains, ADII, PCLR),
    directly usable by mhealth.metrics.
    """
    traffic_dir = Path(wg.NETWORK_TRAFFIC_DIR)
    pre_path = traffic_dir / f"{app_id}_{country}_pre_consent.log"
    post_path = traffic_dir / f"{app_id}_{country}_post_consent.log"

    pre = ta.process_single_log(str(pre_path), app_id) if pre_path.exists() else None
    post = ta.process_single_log(str(post_path), app_id) if post_path.exists() else None

    if pre is None and post is None:
        return None
    return ta.build_country_row(app_id, country, pre=pre, post=post)


def collect(app_id: str, country: str, device: str, d) -> dict:
    """Capture + extract in one call: the network-traffic arm of the
    consolidated per-app record."""
    status = capture(app_id, country, device, d)
    row = extract(app_id, country) if status["captured"] else None
    if row is not None:
        status.update(row)
    return status
