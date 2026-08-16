# mSCAN

*The **m** mirrors how the paper styles* mHealth *(mobile health); the rest is
Data **S**afety, permissions/tra**c**kers, policy retriev**a**l, **n**etwork traffic.*

mSCAN is a multi-source privacy- and security-audit tool for Android mHealth
apps. Given an `app_id` (or a list of them) and a country, it collects four
evidence sources for that app, Google Play *Data Safety*, the privacy
policy, static permissions/trackers, and decrypted network traffic, and
emits one consolidated record per app in a shared canonical taxonomy. If
network traffic was captured, it also computes three per-app privacy
metrics (ADII, DGI, PCLR) directly from that record.

This repository contains the tool only: `mscan/`, the CLI, its Docker
packaging, and the small set of vendored modules it depends on
(`mscan/collection/`, `mscan/mhealth/`). It does not contain the derived
dataset, the batch collection pipeline, or the analysis code used to
produce the paper's reported results.

## Quick start

```bash
cd mscan
pip install -r requirements.txt
python3 mscan.py --app-ids com.example.healthapp --country us \
    --sources data_safety,privacy_policy,permissions_trackers
```

The `network_traffic` source additionally needs a rooted Android emulator
or device with a system-trusted `mitmproxy` CA. See `mscan/README.md` for
full setup, and `mscan/docker/README.md` for a containerized deployment
that only needs an already-running, already-logged-in emulator on your own
machine.

## Repository structure

```
mscan/                       the tool -- see mscan/README.md
  mscan.py                   CLI entrypoint
  record.py                  merges the four sources into one record + computes metrics
  sources/                   one collector per evidence source
  collection/
    wireguard_vpn.py         install/capture/uninstall automation on the emulator
    traffic_analyzer.py      offline extraction of observed data types from captured traffic
  mhealth/
    metrics.py               ADII / DGI / PCLR definitions
    taxonomy.py              canonical data-type taxonomy and sensitivity weights
    parsing.py               frequency-map parsing helpers metrics.py depends on
  docker/                    container packaging (Dockerfile, docker-compose.yml, README.md)
```

`mscan/collection/` and `mscan/mhealth/` are not standalone pipelines here;
they are exactly the modules `mscan/record.py` and
`mscan/sources/network_traffic.py` import, vendored inside `mscan/` so the
whole tool is self-contained -- clone or copy `mscan/` on its own and it
works without the rest of this repository.

## Privacy metrics

- **ADII** — App Data Invasiveness Index: sensitivity-weighted volume of data leaving the device
- **DGI** — Disclosure Gap Index: observed-but-undeclared collection over a canonical taxonomy
- **PCLR** — Pre-Consent Leakage Rate: share of sensitive transmission before user action

## Ethical considerations

mSCAN observes an app's own runtime behavior on a device you control; it
does not collect data from real users. If you point it at network traffic
capture, use a synthetic profile, not a real one, and only audit apps you
have the right to test under the terms of service you've agreed to.

## Citation

If you use this tool, please cite the paper it accompanies (details added
upon publication).
