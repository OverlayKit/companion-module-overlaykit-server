#!/usr/bin/env bash
set -euo pipefail

if [[ "$(id -u)" == "0" && "${H034_IDENTITY_MAPPED:-0}" != "1" ]]; then
  groupmod --non-unique --gid "${H034_HOST_GID}" overlaykit
  usermod --non-unique --uid "${H034_HOST_UID}" --gid "${H034_HOST_GID}" overlaykit
  chown -R overlaykit:overlaykit /data /evidence
  export H034_IDENTITY_MAPPED=1
  exec runuser --user overlaykit --preserve-environment -- "$0" "$@"
fi

{
  printf 'node='
  node --version
  printf 'commit=%s\n' "$H034_OVERLAYKIT_COMMIT"
  . /etc/os-release
  printf 'os=%s\nversion=%s\n' "$ID" "$VERSION_ID"
} > /evidence/overlaykit-runtime.txt

node /opt/h034/device-proxy.cjs &
proxy_pid=$!
trap 'kill "$proxy_pid" 2>/dev/null || true' EXIT INT TERM

cd /opt/overlaykit
exec node server/dist/index.js
