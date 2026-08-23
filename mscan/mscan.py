#!/usr/bin/env python3
"""mSCAN: single-app, four-source mHealth privacy audit.

mSCAN -- multi-source Security & Privacy Cross-context Auditing Network tool.

Given an app_id, runs the same four evidence-source extractors used to build
the paper's corpus (Google Play Data Safety, privacy policy, static
permissions/trackers, and decrypted network traffic) and emits one
consolidated record per app.

Assumptions (see README.md for the full rationale):
  - A VPN client is already connected on this machine to the country you
    pass with --country; mSCAN only verifies the resulting egress IP
    resolves to that country, it does not manage the VPN connection itself.
  - An Android emulator is already running with the mitmproxy CA trusted,
    reachable over adb, if you're requesting the network-traffic source.
  - One run = one country. To audit the same apps in another country,
    switch the VPN yourself and run again with a different --country.

Usage:
    python3 mscan.py --app-ids com.foo.app,com.bar.app --country de
    python3 mscan.py --app-ids-file apps.txt --country us --sources data_safety,privacy_policy
    python3 mscan.py --app-ids com.foo.app --country jp --skip-vpn-check

    # No --out: nothing is written to disk, each record prints to stdout instead
    python3 mscan.py --app-ids com.foo.app --country us \\
        --sources data_safety,privacy_policy,permissions_trackers
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from record import build_record, compute_metrics  # noqa: E402
from sources import data_safety, permissions_trackers, privacy_policy  # noqa: E402

ALL_SOURCES = ("data_safety", "privacy_policy", "permissions_trackers", "network_traffic")
DEFAULT_POLICY_DIR = Path(__file__).resolve().parents[1] / "data" / "privacy_policies"


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    app_group = ap.add_mutually_exclusive_group(required=True)
    app_group.add_argument("--app-ids", help="comma-separated app_ids")
    app_group.add_argument("--app-ids-file",
                           help="path to a .txt file (one app_id per line) or a .csv "
                                "file with an app_id column (falls back to the first "
                                "column if there's no header)")

    ap.add_argument("--country", required=True,
                    help="2-letter country code for the VPN you already connected "
                         "(e.g. de, jp, us). Used to tag output files and, unless "
                         "--skip-vpn-check, to verify the device's actual egress IP.")
    ap.add_argument("--sources", default=",".join(ALL_SOURCES),
                    help=f"comma-separated subset of {ALL_SOURCES} (default: all four)")
    ap.add_argument("--skip-vpn-check", action="store_true",
                    help="skip verifying the device's egress IP against --country "
                         "(only meaningful if network_traffic is in --sources)")
    ap.add_argument("--policy-dir", default=str(DEFAULT_POLICY_DIR),
                    help="where to cache retrieved privacy-policy text")
    ap.add_argument("--out", default=None,
                    help="output path prefix; writes <out>_<country>.jsonl. If "
                         "omitted, nothing is written to disk -- each record "
                         "prints to stdout instead.")
    return ap.parse_args()


def _read_app_ids_file(path: str) -> list[str]:
    """Accepts either a plain text file (one app_id per line, '#' comments
    allowed) or a CSV with an `app_id` column -- reviewers asked for "a CSV
    with a list of app_id" specifically, so detect and handle both rather
    than requiring a particular format.
    """
    if path.lower().endswith(".csv"):
        import csv
        with open(path, newline="") as f:
            sniff = f.read(4096)
            f.seek(0)
            has_header = csv.Sniffer().has_header(sniff) if sniff.strip() else False
            reader = csv.reader(f)
            rows = list(reader)
        if not rows:
            return []
        if has_header:
            header = [h.strip().lower() for h in rows[0]]
            col = header.index("app_id") if "app_id" in header else 0
            rows = rows[1:]
        else:
            col = 0
        return [row[col].strip() for row in rows if row and row[col].strip()]

    with open(path) as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def load_app_ids(args: argparse.Namespace) -> list[str]:
    if args.app_ids:
        ids = [a.strip() for a in args.app_ids.split(",") if a.strip()]
    else:
        ids = _read_app_ids_file(args.app_ids_file)
    seen = set()
    deduped = [a for a in ids if not (a in seen or seen.add(a))]
    return deduped


def make_selenium_driver():
    import os
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service

    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument(
        "user-agent=Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

    chrome_bin = os.environ.get("CHROME_BIN")
    if chrome_bin:
        options.binary_location = chrome_bin

    chromedriver_bin = os.environ.get("CHROMEDRIVER_BIN")
    service = Service(executable_path=chromedriver_bin) if chromedriver_bin else None
    return webdriver.Chrome(options=options, service=service)


def main() -> int:
    args = parse_args()
    app_ids = load_app_ids(args)
    sources = {s.strip() for s in args.sources.split(",") if s.strip()}
    unknown = sources - set(ALL_SOURCES)
    if unknown:
        print(f"[FATAL] unknown source(s): {sorted(unknown)}; choose from {ALL_SOURCES}")
        return 1

    print(f"[mSCAN] {len(app_ids)} app(s), country={args.country}, "
          f"sources={sorted(sources)}")

    device = d = None
    if "network_traffic" in sources:
        from sources import network_traffic

        device, d = network_traffic.connect_device()

        if not args.skip_vpn_check:
            check = network_traffic.verify_vpn(args.country)
            if not check["ok"]:
                print(f"[FATAL] Egress IP does not resolve to '{args.country}': "
                      f"{check['info']}. Reconnect your VPN, or pass "
                      f"--skip-vpn-check if this is expected.")
                return 1
            print(f"[OK] VPN verified: {check['info']}")
        else:
            print("[WARN] --skip-vpn-check set; not verifying egress country. "
                  "Output will be tagged with the country you claimed, whether "
                  "or not the device actually routes through it.")

    driver = None
    needs_browser = sources & {"data_safety", "privacy_policy", "permissions_trackers"}
    if needs_browser:
        driver = make_selenium_driver()

    out_path = None
    out_f = None
    if args.out is not None:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        out_path = Path(f"{args.out}_{args.country}.jsonl")
        out_f = open(out_path, "a", encoding="utf-8")

    try:
        for app_id in app_ids:
            print(f"\n=== {app_id} ===")
            ds = pp = pt = nt = None

            if "data_safety" in sources:
                try:
                    ds = data_safety.collect(app_id, driver)
                except Exception as e:
                    print(f"[data_safety] error for {app_id}: {e}")

            if "privacy_policy" in sources:
                try:
                    pp = privacy_policy.collect(app_id, driver, args.policy_dir)
                except Exception as e:
                    print(f"[privacy_policy] error for {app_id}: {e}")

            if "permissions_trackers" in sources:
                try:
                    pt = permissions_trackers.collect(app_id, driver)
                except Exception as e:
                    print(f"[permissions_trackers] error for {app_id}: {e}")

            if "network_traffic" in sources:
                try:
                    from sources import network_traffic as nt_mod
                    nt = nt_mod.collect(app_id, args.country, device, d)
                except Exception as e:
                    print(f"[network_traffic] error for {app_id}: {e}")

            record = build_record(app_id, args.country, ds, pp, pt, nt)
            try:
                record["metrics"] = compute_metrics(record)
            except Exception as e:
                print(f"[metrics] could not compute for {app_id}: {e}")
                record["metrics"] = {}
            record["collected_at"] = datetime.now(timezone.utc).isoformat()

            if out_f is not None:
                out_f.write(json.dumps(record) + "\n")
                out_f.flush()
            else:
                print(json.dumps(record, indent=2))

            summary = (
                f"  data_safety_data_collected={'yes' if record['data_safety_data_collected'] else 'no'}  "
                f"trackers={record['num_trackers']}  "
                f"traffic_captured={record['traffic_captured']}"
            )
            if record["metrics"]:
                summary += f"  ADII={record['metrics']['ADII']:.0f}  " \
                           f"DGI={record['metrics']['DGI']:.2f}  " \
                           f"PCLR={record['metrics']['PCLR']:.2f}"
            print(summary)
    finally:
        if driver is not None:
            driver.quit()
        if out_f is not None:
            out_f.close()

    if out_path is not None:
        print(f"\n[DONE] wrote {out_path}")
    else:
        print(f"\n[DONE] {len(app_ids)} app(s) processed; no --out given, so "
              f"nothing was written to disk (records printed above).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
