#!/bin/bash
set -e

cd /app/mscan

if [ "$1" = "setup" ]; then
    shift
    exec python3 docker/setup_device.py "$@"
fi

if [ "${SKIP_DEVICE_SETUP:-}" != "1" ]; then
    echo "[entrypoint] running device setup (CA + frida-server); set SKIP_DEVICE_SETUP=1 to skip"
    python3 docker/setup_device.py || echo "[entrypoint] device setup reported issues (see above) -- continuing; static sources (data_safety/privacy_policy/permissions_trackers) are unaffected."
    echo ""
fi

exec python3 mscan.py "$@"
