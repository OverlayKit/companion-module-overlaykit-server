#!/usr/bin/env bash
set -euo pipefail

if [[ "$(id -u)" == "0" && "${H034_IDENTITY_MAPPED:-0}" != "1" ]]; then
  groupmod --non-unique --gid "${H034_HOST_GID}" companion
  usermod --non-unique --uid "${H034_HOST_UID}" --gid "${H034_HOST_GID}" companion
  chown -R companion:companion /companion /evidence
  export H034_IDENTITY_MAPPED=1
  exec runuser --user companion --preserve-environment -- "$0" "$@"
fi

{
  printf 'node='
  /app/node-runtimes/main/bin/node --version
  printf 'module_sha256='
  cut -d' ' -f1 /opt/h034/module.sha256
  . /etc/os-release
  printf 'os=%s\nversion=%s\n' "$ID" "$VERSION_ID"
} > /evidence/companion-runtime.txt

exec /app/node-runtimes/main/bin/node /app/main.js \
  --admin-address :: \
  --admin-port "${COMPANION_ADMIN_PORT}" \
  --config-dir "${COMPANION_CONFIG_BASEDIR}" \
  --extra-module-path /app/module-local-dev
