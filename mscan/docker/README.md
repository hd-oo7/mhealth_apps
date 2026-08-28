# mSCAN Docker image

A container with mSCAN plus its interception tooling — adb client,
mitmproxy, Frida's client side, Chrome/Selenium — pre-installed and
pre-configured. It does **not** contain an Android emulator. You run an
emulator on your own machine, log into your own Google Play Store account on
it yourself, and this container reaches it over `adb`. This is deliberate:
Play Store login can't be automated or shipped in an image, and running the
emulator itself inside Docker on macOS isn't practical (no GPU passthrough,
no `--network host`). So the split is: **emulator stays on your host,
everything else is containerized.**

Everything below was verified end to end on a machine that started with
*nothing* installed — no Docker, no Android SDK, no emulator, no root tooling
— up through installing a real app from Play, capturing real decrypted HTTPS
traffic through the container, and computing real ADII/DGI/PCLR. Every
command here is one that was actually run, not just written down.

## Prerequisites

If you already have Docker and an Android emulator you use regularly, skip
to [One-time host setup](#one-time-host-setup) — you likely only need step 1
there (rooting). Starting from nothing:

- **Docker Desktop**: [docker.com/products/docker-desktop](https://www.docker.com/products/docker-desktop/).
  After installing, launch it once (`open -a Docker` on macOS) and wait for
  the whale icon to settle — `docker info` should succeed with no
  "Cannot connect to the Docker daemon" error.
- **Android SDK command-line tools** (`adb`, `emulator`, `avdmanager`,
  `sdkmanager`): the easiest path is installing Android Studio
  ([developer.android.com/studio](https://developer.android.com/studio)),
  which bundles all four plus a JDK for the Java-based ones. After
  installing, the tools live under `~/Library/Android/sdk` (macOS) /
  `~/Android/Sdk` (Linux) / `%LOCALAPPDATA%\Android\Sdk` (Windows):
  `platform-tools/adb`, `emulator/emulator`,
  `cmdline-tools/latest/bin/{avdmanager,sdkmanager}`. Put
  `platform-tools` and `emulator` on your `PATH`; the `cmdline-tools` ones
  are only needed for the one-time AVD setup below and can be run by full
  path. `avdmanager`/`sdkmanager` need a JDK — Android Studio ships its own
  at `Android Studio.app/Contents/jbr` (macOS) if you don't already have
  one; point `JAVA_HOME` at it for the commands below if `java -version`
  otherwise fails.
- **An AVD to root.** If you don't have one yet, create a Play Store x86_64
  image (matches your machine's own CPU on Intel/AMD; use `arm64-v8a`
  instead on Apple Silicon):
  ```bash
  sdkmanager "system-images;android-29;google_apis_playstore;x86_64"
  avdmanager create avd -n Pixel_4 -k "system-images;android-29;google_apis_playstore;x86_64" -d pixel_4
  ```

## One-time host setup

Four things need to be true on your host *before* you use this container.
None of these are things the container can do for you — they're exactly the
prerequisites mSCAN already has outside Docker, plus one Docker-specific
networking step.

### 1. A rooted Play Store AVD

The default Play Store AVD image is a production build — `adb root` is
always refused on it, and without root, mitmproxy's CA can't be installed
into the system trust store, so HTTPS interception can't work. **Don't**
switch to the `google_apis` (non-Play-Store) image to get around this — it's
rootable, but ships no Play Store app at all, and mSCAN's install flow needs
one (it launches apps via a `market://` deep link, which only the Play
Store app handles). Instead, root your *existing* Play Store image directly
with [rootAVD](https://github.com/newbit1/rootAVD) — it patches in Magisk
while leaving the Play Store partition intact:

```bash
git clone https://github.com/newbit1/rootAVD.git
emulator -avd Pixel_4 &          # rootAVD needs the AVD running
cd rootAVD
export ANDROID_HOME=~/Library/Android/sdk   # wherever your SDK lives
./rootAVD.sh system-images/android-29/google_apis_playstore/x86_64/ramdisk.img
```

Use the path matching your own AVD's API level/arch (see
`avdmanager list avd` → `Based on:` line). The script pushes Magisk, patches
`ramdisk.img`, and shuts the emulator down; relaunch it once (see step 2
below) for the patch to take effect — this is expected, not a failure.

Then, **on the emulator's screen**, open the Magisk app once (it's
installed automatically) and set **Settings → Superuser → Automatic
response** to **Grant**. This is not optional: without it, every `su` call
blocks waiting for an interactive prompt nothing can answer, and fails
closed with `Permission denied` — confirmed as the actual failure mode when
this step is skipped. Root via `su` is a different mechanism from
`adb root` (Magisk doesn't unlock the ADB daemon itself, only grants root to
`su -c ...` invocations) — `docker/setup_device.py` detects and uses
whichever one actually works.

### 2. The emulator, logged into Google Play, launched with a transparent proxy

Boot your AVD with the `-http-proxy` flag pointed at wherever this
container's mitmproxy port will be published (default `8080`):

```bash
emulator -avd Pixel_4 -http-proxy 127.0.0.1:8080
```

This is the flag that matters for `network_traffic`. We tried the
alternative — setting Android's `global http_proxy` system setting instead
of using this launch flag — and confirmed empirically that it is **not**
sufficient: it's honored by some apps/WebViews but plain browser/app traffic
routed through it never reached mitmproxy in testing, while the same traffic
was intercepted immediately once the emulator was relaunched with
`-http-proxy`. If you only need the three static sources
(`data_safety`, `privacy_policy`, `permissions_trackers`), this step doesn't
matter — skip it.

Log into your own Google Play Store account on this emulator now, the normal
way, by hand. The container never sees your credentials.

### 3. A second adb server bound to all interfaces

Docker containers can't easily share your host's USB/emulator transport, so
the container instead talks to a copy of `adb` on the host, over TCP. The
default adb server only listens on `localhost`, which a container can't
reach.

If you normally use Android Studio, **don't** kill and rebind its adb server
directly — Studio owns `localhost:5037` and will silently respawn a
localhost-only server the moment that one dies, fighting any rebind attempt.
Instead, run a second, independent adb server on a different port, bound to
all interfaces. It can see the same emulator without disturbing Studio's own
connection:

```bash
adb -a -P 5038 nodaemon server start &
```

Verify it: `adb -P 5038 devices -l` should list your emulator.

(If you don't use Android Studio at all, plain
`adb -a nodaemon server start` on the default port 5037 works fine too —
just point `ADB_SERVER_SOCKET` at 5037 instead of 5038 in the commands
below.)

### 4. Docker Desktop running

macOS/Windows: just have it open: `host.docker.internal` resolves
automatically. Linux: `docker run`/`compose` commands below already include
`--add-host=host.docker.internal:host-gateway` to make it resolve there too.

## Build

mSCAN is self-contained, so build from the `mscan/` directory itself:

```bash
cd mscan
docker build -f docker/Dockerfile -t mscan .
```

Builds natively for whatever architecture you run it on (Apple Silicon,
Intel, Linux x86_64/arm64) — no `--platform` flag needed. We initially tried
Google's official `platform-tools-latest-linux.zip` for `adb`, which only
ships an x86_64 binary; that forced `--platform linux/amd64` builds on
Apple Silicon and made Chromium crash under QEMU emulation (missing SSE3).
Switched to Debian's `android-tools-adb` package instead, which is
multi-arch, so the whole image — Chromium included — now builds and runs
natively.

## Check your setup

Before running a real audit, confirm the container can actually reach your
emulator and that the CA/Frida setup is in place:

```bash
docker run --rm \
  -e ADB_SERVER_SOCKET=tcp:host.docker.internal:5038 \
  -e ANDROID_ADB_SERVER_HOST=host.docker.internal \
  -e ANDROID_ADB_SERVER_PORT=5038 \
  --add-host=host.docker.internal:host-gateway \
  -v "$(pwd)/data/mitmproxy_ca:/root/.mitmproxy" \
  mscan setup --check
```

`--check` only reports status, it doesn't change anything. Drop `--check` to
actually push the mitmproxy CA into the device's system trust store and
deploy `frida-server` — both are idempotent, safe to run every time.

The `-v .../data/mitmproxy_ca:/root/.mitmproxy` volume matters even for a
plain `docker run --rm`: without it, every container generates a brand-new
CA key pair, and mitmproxy always uses the same CA *subject name*
(`CN=mitmproxy`) — which is what Android's system-cacerts filename is a
hash of, not the key. So the install-check will match by filename and
report `installed` even when the key underneath no longer matches what's
actually on the device from a previous run, and interception fails
silently with cert errors. Mount this volume so the same CA persists
across runs. (`data/mitmproxy_ca/` holds a private key once generated —
it's gitignored, never commit it.)

Two environment variables carry the adb server location, not one: the `adb`
CLI itself honors `ADB_SERVER_SOCKET`, but `uiautomator2` (used by the
`network_traffic` source) goes through a separate Python library
(`adbutils`) that instead reads `ANDROID_ADB_SERVER_HOST` /
`ANDROID_ADB_SERVER_PORT`. Set both, as above, or `network_traffic` will
fail to connect even though plain `adb` works.

Expect one of these for the CA step:

- `installed` — done, everything works from here. On a Magisk-rooted image
  (see step 1 above), this installs the CA as a Magisk module and reboots
  the device once (~15-30s) to apply it — expected, not an error.
- `needs_root` — neither `adb root` nor `su` grants root on this device.
  You skipped (or need to redo) [One-time host setup step 1](#1-a-rooted-play-store-avd)
  above — most commonly because Magisk's Superuser "Automatic response" is
  still set to "Prompt" rather than "Grant", so headless `su` calls have no
  one to answer their permission dialog and fail closed.

## Run

```bash
docker run --rm \
  -p 8080:8080 \
  -e ADB_SERVER_SOCKET=tcp:host.docker.internal:5038 \
  -e ANDROID_ADB_SERVER_HOST=host.docker.internal \
  -e ANDROID_ADB_SERVER_PORT=5038 \
  --add-host=host.docker.internal:host-gateway \
  -v "$(pwd)/results:/app/mscan/results" \
  -v "$(pwd)/data/mitmproxy_ca:/root/.mitmproxy" \
  -v "$(pwd)/app_ids.csv:/app/mscan/app_ids.csv:ro" \
  mscan --app-ids-file app_ids.csv --country us \
  --out /app/mscan/results/results
```

- `-p 8080:8080` publishes the container's mitmproxy port to your host, so
  the emulator's `-http-proxy 127.0.0.1:8080` traffic actually reaches it.
  Only needed for the `network_traffic` source.
- `--app-ids-file` accepts either a plain `.txt` (one `app_id` per line,
  `#` comments allowed) or a `.csv` with an `app_id` column (falls back to
  the first column if there's no header) — pass whichever you have. A
  single app also works directly: `--app-ids com.example.app`.
- `--out` is a filename *prefix*, not a directory — mSCAN writes
  `<out>_<country>.jsonl`. Point it *inside* a mounted volume (as above), or
  your results will only exist inside the now-deleted container. Omit
  `--out` entirely for a one-off check — mSCAN prints each record to stdout
  instead of writing a file.
- Add `--sources data_safety,privacy_policy,permissions_trackers` to skip
  `network_traffic` entirely and avoid needing any of the emulator
  prerequisites above — no AVD, no root, no adb bridge, no proxy. mSCAN
  only touches `adb` at all when `network_traffic` is among the requested
  sources; the three static sources just need Chrome/Selenium, which the
  image already has.

Confirmed working end to end: this exact invocation pattern, against a real
Magisk-rooted Play Store AVD, installed a real app from Play, ran the
pre/post-consent capture automation, uninstalled it afterward, and returned
`"traffic_captured": true` with real extracted ADII/DGI/PCLR — decrypted
HTTPS traffic, not a stub.

## docker-compose

`docker/docker-compose.yml` bundles the flags above, including the
`mitmproxy_ca` persistence volume. From `mscan/docker/`:

```bash
docker compose build
docker compose run --rm -v $(pwd)/my_apps.csv:/app/mscan/app_ids.csv:ro \
    mscan --app-ids-file app_ids.csv --country us \
    --out /app/mscan/results/results
```

Edit the `ADB_SERVER_SOCKET` port in `docker-compose.yml` if you're using
the default 5037 instead of a dedicated 5038.

## Known limitations

- **One country per run**, same as mSCAN outside Docker: switch your VPN
  yourself and re-run with a different `--country`.
- **No GEMINI_API_KEY set** by default: the privacy-policy source's LLM
  disclosure-rating step is skipped (Data Safety is still collected). Pass
  `-e GEMINI_API_KEY=...` to enable it.
- **The emulator's Google Play login and `-http-proxy` launch flag are your
  responsibility**, every time you start a fresh emulator session — the
  container has no way to automate either, by design.
- **Rooting is per system-image, not per-AVD.** `rootAVD.sh` patches the
  shared `ramdisk.img` under the SDK's `system-images/` tree, so every AVD
  built from that same image/arch becomes rootable, not just the one you
  booted while running it. This is normally a convenience, not a problem.
