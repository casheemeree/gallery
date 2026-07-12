#!/usr/bin/env sh
set -eu

APP_DIR="${APP_DIR:-/srv/capi-gallery}"
BRANCH="${BRANCH:-main}"

cd "$APP_DIR"
git fetch origin "$BRANCH"
git checkout "$BRANCH"
git pull --ff-only origin "$BRANCH"
python3 -m unittest discover -s tests -v
sudo systemctl restart capi-gallery
sudo systemctl is-active --quiet capi-gallery
