# mSCAN

**mSCAN** -- **m**ulti-source **S**ecurity & Privacy **C**ross-context
**A**uditing **N**etwork tool.

mSCAN is a multi-source privacy- and security-audit tool for Android mHealth
apps. Given an `app_id` (or a list of them) and a country, it collects four
evidence sources for that app, Google Play *Data Safety*, the privacy
policy, static permissions/trackers, and decrypted network traffic, and
emits one consolidated record per app in a shared canonical taxonomy. If
network traffic was captured, it also computes three per-app privacy
metrics (ADII, DGI, PCLR) directly from that record.

This repository contains two things: `mscan/` (the tool itself -- see below)
and `analysis_scripts/` + `data/` (the code and anonymized dataset behind the
paper's Sec. 6 results, figures, etc.). It does not contain the batch collection
pipeline, raw network traffic, or any per-app intermediate file that could
re-identify a specific application, per the paper's Ethics Considerations
and Open Science sections.

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
  mhealth/
    metrics.py               ADII / DGI / PCLR definitions
    taxonomy.py              canonical data-type taxonomy and sensitivity weights
    parsing.py               frequency-map parsing helpers metrics.py depends on
  docker/                    container packaging (Dockerfile, docker-compose.yml, README.md)

analysis_scripts/            paper results, figures, and release tooling -- see analysis_scripts/README.md
  01-11                      per-topic notebooks (Sec. 3-6); need the internal raw corpus
  12-14                      accuracy-correction pass; run directly on the released data below
  15-16                      generate the two files in data/ below from the internal raw corpus

data/
  anonymized_app_list.csv                one row per app, keyed by anon_app_id, no direct identifiers
  mhealth_apps_metrics_anonymized.csv    full app-country-state metrics dataset behind every table/figure (Git LFS)
```

`data/mhealth_apps_metrics_anonymized.csv` is ~140MB and tracked with
[Git LFS](https://git-lfs.com); install `git-lfs` and run `git lfs pull` (or
just `git clone`, if your Git already has the LFS filter configured) to
fetch its actual contents rather than a pointer file.

## Reproducing the paper's results

```bash
cd analysis_scripts
pip install -r requirements.txt
python3 12_verification_and_corrections.py     # Sec. 6 statistics
python3 13_generate_figures.py                 # figures/*.pdf
```

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
