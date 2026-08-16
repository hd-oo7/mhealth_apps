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

Everything below was verified end to end against a real emulator (installing
a real app from Play, capturing real decrypted HTTPS traffic through the
container, computing real ADII/DGI/PCLR) — not just built, actually run.

## One-time host setup

You need three things running on your host *before* you use this container.
None of these are things the container can do for you — they're exactly the
prerequisites mSCAN already has outside Docker, plus one Docker-specific
networking step.

### 1. An Android emulator, logged into Google Play, launched with a transparent proxy

Boot your AVD with the `-http-proxy` flag pointed at wherever this
container's mitmproxy port will be published (default `8080`):

```bash
emulator -avd <your_avd_name> -http-proxy 127.0.0.1:8080
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

### 2. A second adb server bound to all interfaces

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

### 3. Docker Desktop running

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
  mscan setup --check
```

`--check` only reports status, it doesn't change anything. Drop `--check` to
actually push the mitmproxy CA into the device's system trust store and
deploy `frida-server` — both are idempotent, safe to run every time.

Two environment variables carry the adb server location, not one: the `adb`
CLI itself honors `ADB_SERVER_SOCKET`, but `uiautomator2` (used by the
`network_traffic` source) goes through a separate Python library
(`adbutils`) that instead reads `ANDROID_ADB_SERVER_HOST` /
`ANDROID_ADB_SERVER_PORT`. Set both, as above, or `network_traffic` will
fail to connect even though plain `adb` works.

Expect one of these for the CA step:

- `installed` — done, everything works from here.
- `needs_root` — your AVD image is a production/`user` build, not
  `userdebug`/`eng`; `adb root` is refused. You'll need to create or switch
  to a rootable AVD image (Android Studio's AVD Manager lets you pick a
  `Google APIs`/non-Play-Store system image, which is rootable, instead of
  the default `Google Play` image, which isn't). Without this, HTTPS traffic
  interception won't work regardless of Docker.

## Run

```bash
docker run --rm \
  -p 8080:8080 \
  -e ADB_SERVER_SOCKET=tcp:host.docker.internal:5038 \
  -e ANDROID_ADB_SERVER_HOST=host.docker.internal \
  -e ANDROID_ADB_SERVER_PORT=5038 \
  --add-host=host.docker.internal:host-gateway \
  -v "$(pwd)/results:/app/mscan/results" \
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
  your results will only exist inside the now-deleted container.
- Add `--sources data_safety,privacy_policy,permissions_trackers` to skip
  `network_traffic` entirely and avoid needing the proxy/CA/Frida setup at
  all — useful for a quick check that doesn't need the emulator prerequisites
  above.

## docker-compose

`docker/docker-compose.yml` bundles the flags above. From `mscan/docker/`:

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
