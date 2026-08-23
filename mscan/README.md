# mSCAN

**mSCAN** -- **m**ulti-source **S**ecurity & Privacy **C**ross-context
**A**uditing **N**etwork tool.

A single-app, four-source privacy- and security-audit tool for Android
mHealth apps. Given an `app_id` (or a list of them) and a country, mSCAN
collects four evidence sources, Google Play *Data Safety*, the privacy
policy, static permissions/trackers, and decrypted network traffic, and
emits one consolidated record per app in a shared canonical taxonomy. If
network traffic was captured, it also computes ADII, DGI, and PCLR for that
(app, country) pair directly via `mhealth.metrics`, using the same metric
definitions verified (in the paper this tool accompanies) to reproduce that
paper's published corpus-level statistics, so a single audited app's numbers
are directly comparable to the paper's results.

This repository contains the tool only, not the paper's underlying dataset,
collection pipeline, or analysis code: mSCAN is meant for on-demand,
single-app spot-checks, not as a replacement for a large-scale batch
collection run.

## What it does *not* do

- **It does not manage your VPN.** Connect your VPN client to the target
  country yourself before running mSCAN. It only checks (via
  `sources/network_traffic.py:verify_vpn`) that the device's actual egress
  IP resolves to the country you claim, so a forgotten VPN switch fails loud
  instead of silently mislabeling a whole batch. Pass `--skip-vpn-check` to
  skip even that check.
- **It does not manage your emulator.** Start it yourself, with the
  mitmproxy CA already trusted on it, before requesting the
  `network_traffic` source. mSCAN attaches to whatever emulator
  `adb devices` reports; it does not boot one.
- **It does not sweep countries.** One run = one country, matching how you'd
  actually operate a manually-connected VPN: audit the list of app_ids,
  switch the VPN yourself, run again with a different `--country`.

## Setup

```bash
cd mscan
pip install -r requirements.txt
```

You also need, on this machine:

- **Chrome** (for Selenium; used by `data_safety`, `privacy_policy`, and
  `permissions_trackers`).
- **A rooted Android emulator or device**, reachable over `adb`, with a
  system-trusted `mitmproxy` CA installed (only for `network_traffic`; see
  `docker/README.md` for a containerized setup that automates the CA and
  Frida deployment against an emulator you already have running).
- **`GEMINI_API_KEY`** in the environment, if you want the privacy policy's
  declared-data answers LLM-parsed rather than falling back to the Data
  Safety label alone.
- **`ANDROID_SDK_ROOT`** (or `ANDROID_HOME`); defaults to
  `~/Library/Android/sdk` if unset.

mSCAN's install/capture/extract automation is implemented directly in
`sources/network_traffic.py`, and its metric definitions live in `mhealth/`,
so this folder is self-contained: copy or clone it on its own and it works
without anything else from this repository.

## Usage

```bash
# All four sources, one app, VPN already connected to Germany
python3 mscan.py --app-ids com.example.healthapp --country de

# A short list, static sources only (no device/VPN needed)
python3 mscan.py --app-ids-file my_apps.txt --country us \
    --sources data_safety,privacy_policy,permissions_trackers

# Network traffic only, VPN check skipped (e.g. testing without a real VPN)
python3 mscan.py --app-ids com.example.healthapp --country jp \
    --sources network_traffic --skip-vpn-check

# One-off spot check, no --out: prints the record to stdout instead of
# writing a file
python3 mscan.py --app-ids com.example.healthapp --country us \
    --sources data_safety,privacy_policy,permissions_trackers
```

Pass `--out <path-prefix>` to append results, one JSON object per line, to
`<path-prefix>_<country>.jsonl` instead. Each record looks like:

```json
{
  "app_id": "com.example.healthapp",
  "country": "de",
  "data_collected": "email, location, health information",
  "data_shared": "device or other IDs",
  "security_practices": "Data is encrypted in transit",
  "policy_retrieved": true,
  "permissions": "...", "num_permissions": 42,
  "dangerous_permissions": "...", "num_dangerous_permissions": 6,
  "trackers": "Google Firebase Analytics, ...", "num_trackers": 5,
  "traffic_captured": true,
  "pre_observed_data_types": "device_ids,ip address",
  "post_observed_data_types": "device_ids,ip address,email,health",
  "metrics": {"ADII": 842.0, "DGI": 0.4, "PCLR": 0.31},
  "collected_at": "2026-08-09T00:00:00+00:00"
}
```

## Layout

```
mscan.py                    CLI entrypoint: orchestrates the four sources per app_id
record.py                   merges the four sources' output into one row + computes metrics
sources/
  data_safety.py             Google Play Data Safety (shared/collected data, security practices)
  privacy_policy.py          policy link discovery, retrieval, LLM-structured extraction
  permissions_trackers.py    static permissions/trackers via exodus-privacy.eu.org
  network_traffic.py         install/capture/uninstall automation + offline log extraction, self-contained
```

## A note on scope

The three static sources (`data_safety`, `privacy_policy`,
`permissions_trackers`) return in seconds and need no special hardware.
`network_traffic` is the slow, infrastructure-bound one: each app costs
roughly install time + a ~15s pre-consent capture + a ~30s post-consent
capture + uninstall, per country, and it needs the same device/VPN setup
the main study used. Budget accordingly if you're auditing more than a
handful of apps in one run.
