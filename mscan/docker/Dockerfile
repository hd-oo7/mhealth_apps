# mSCAN audit container.
#
# Holds the tooling only: adb client, mitmproxy, Frida's client side, Chrome/
# Selenium for the three static sources, and mSCAN itself. It does NOT hold
# an Android emulator -- that stays on the reviewer's own machine, already
# running and already logged into their own Google Play Store account, and
# this container reaches it over adb (see docker/README.md for the one-time
# host-side setup that can't be containerized away).
#
# mSCAN is self-contained (mhealth/ lives inside this directory, and
# sources/network_traffic.py has no external mscan-internal dependencies),
# so build from `mscan/` itself:
#     cd mscan && docker build -f docker/Dockerfile -t mscan .

FROM python:3.11-slim-bookworm

ARG DEBIAN_FRONTEND=noninteractive

# --- system packages -------------------------------------------------------
# chromium/chromium-driver: Selenium, for data_safety/privacy_policy/permissions_trackers
# adb: Debian's android-tools package, NOT Google's platform-tools zip 
# xz-utils/curl: fetching frida-server at setup time
RUN apt-get update && apt-get install -y --no-install-recommends \
        chromium chromium-driver \
        android-tools-adb \
        xz-utils curl ca-certificates procps \
    && rm -rf /var/lib/apt/lists/*
ENV PATH="/usr/lib/android-sdk/platform-tools:${PATH}"

# --- python dependencies ----------------------------------------------------
COPY requirements.txt /app/mscan/requirements.txt
RUN pip install --no-cache-dir -r /app/mscan/requirements.txt \
    && pip install --no-cache-dir mitmproxy frida-tools

# --- the tool itself. mscan/ is self-contained (mhealth/ is the only
#     subpackage it depends on), so one copy picks up everything -----------
COPY . /app/mscan/

# --- writable output/cache locations, meant to be bind-mounted so results
#     and cached policy text survive past the container's lifetime ---------
RUN mkdir -p /app/data/network_traffic /app/data/privacy_policies /app/mscan/results

ENV ANDROID_SDK_ROOT=/usr/lib/android-sdk
ENV CHROME_BIN=/usr/bin/chromium
ENV CHROMEDRIVER_BIN=/usr/bin/chromedriver
WORKDIR /app/mscan

RUN chmod +x /app/mscan/docker/entrypoint.sh

ENTRYPOINT ["/app/mscan/docker/entrypoint.sh"]
